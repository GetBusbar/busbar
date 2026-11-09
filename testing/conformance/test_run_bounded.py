"""Focused process-group cleanup checks; no conformance subjects are launched."""

import ast
import errno
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import types
import unittest
from unittest import mock

SOURCE = (
    (Path(__file__).parent / "run.sh")
    .read_text()
    .split("<<'PYTIMEOUT'\n", 1)[1]
    .split("\nPYTIMEOUT", 1)[0]
)
TREE = ast.parse(SOURCE)
HELPER = compile(
    ast.Module(
        body=[
            n
            for n in TREE.body
            if isinstance(n, ast.FunctionDef) and n.name == "signal_owned_group"
        ],
        type_ignores=[],
    ),
    "<run_bounded cleanup>",
    "exec",
)


def cleanup(pid=123, result=0, platform="darwin"):
    scope = {
        "os": os,
        "sys": types.SimpleNamespace(platform=platform),
        "errno": errno,
        "subprocess": subprocess,
        "process": types.SimpleNamespace(pid=pid, poll=lambda: result),
    }
    exec(HELPER, scope)
    return scope["signal_owned_group"]


def states(pgid):
    table = subprocess.check_output(
        ["/bin/ps", "-axo", "pgid=,stat="], text=True, timeout=2
    )
    return [
        row.split()[1]
        for row in table.splitlines()
        if row.split() and int(row.split()[0]) == pgid
    ]


class DeniedSignal(unittest.TestCase):
    def test_only_confirmed_completed_darwin_group_is_ignored(self):
        for table in ("123 Z\n1 Ss\n", "1 Ss\n"):
            with (
                self.subTest(table=table),
                mock.patch.object(
                    os, "killpg", side_effect=PermissionError(errno.EPERM, "denied")
                ),
            ):
                with mock.patch.object(
                    subprocess, "check_output", return_value=table
                ) as ps:
                    cleanup()(signal.SIGTERM)
                    ps.assert_called_once_with(
                        ["/bin/ps", "-axo", "pgid=,stat="], text=True, timeout=1
                    )

    def test_live_or_unreaped_group_cannot_hide_permission_denial(self):
        with mock.patch.object(
            os, "killpg", side_effect=PermissionError(errno.EPERM, "denied")
        ):
            for table in ("123 S\n", "123 Z\n123 R+\n", "123 T\n"):
                with (
                    self.subTest(table=table),
                    mock.patch.object(subprocess, "check_output", return_value=table),
                ):
                    with self.assertRaises(PermissionError):
                        cleanup()(signal.SIGTERM)
            with mock.patch.object(subprocess, "check_output") as ps:
                with self.assertRaises(PermissionError):
                    cleanup(result=None)(signal.SIGTERM)
                ps.assert_not_called()

    def test_unknown_enumeration_is_failure(self):
        with mock.patch.object(
            os, "killpg", side_effect=PermissionError(errno.EPERM, "denied")
        ):
            for table in ("", "not-a-pgid Z\n", "123\n", "123 Z extra\n"):
                with (
                    self.subTest(table=table),
                    mock.patch.object(subprocess, "check_output", return_value=table),
                ):
                    with self.assertRaises(RuntimeError):
                        cleanup()(signal.SIGTERM)
            for error in (
                subprocess.CalledProcessError(1, "ps"),
                subprocess.TimeoutExpired("ps", 1),
            ):
                with (
                    self.subTest(error=error),
                    mock.patch.object(subprocess, "check_output", side_effect=error),
                ):
                    with self.assertRaises(type(error)):
                        cleanup()(signal.SIGTERM)

    def test_other_platforms_and_permission_errors_remain_failures(self):
        for platform, error in [("linux", errno.EPERM), ("darwin", errno.EACCES)]:
            with self.subTest(platform=platform, error=error):
                with mock.patch.object(
                    os, "killpg", side_effect=PermissionError(error, "denied")
                ):
                    with mock.patch.object(subprocess, "check_output") as ps:
                        with self.assertRaises(PermissionError):
                            cleanup(platform=platform)(signal.SIGKILL)
                        ps.assert_not_called()

    @unittest.skipUnless(
        sys.platform == "darwin", "actual XNU zombie process-group behavior"
    )
    def test_actual_darwin_zombie_group_can_be_cleaned(self):
        # Own this zombie directly so the test can deterministically retain and reap
        # it; it models a zombie descendant whose group leader was already reaped.
        pid = os.fork()
        if pid == 0:
            os.setpgid(0, 0)
            os._exit(0)
        try:
            deadline = time.monotonic() + 2
            while states(pid) != ["Z"]:
                if time.monotonic() >= deadline:
                    self.fail("owned child did not become a zombie")
                time.sleep(0.01)
            with self.assertRaises(PermissionError) as error:
                os.killpg(pid, signal.SIGTERM)
            self.assertEqual(error.exception.errno, errno.EPERM)
            cleanup(pid=pid)(signal.SIGTERM)
            cleanup(pid=pid)(signal.SIGKILL)
        finally:
            os.waitpid(pid, 0)

    def test_actual_live_group_is_not_ignored(self):
        child = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            start_new_session=True,
        )
        try:
            with mock.patch.object(
                os, "killpg", side_effect=PermissionError(errno.EPERM, "denied")
            ):
                with self.assertRaises(PermissionError):
                    cleanup(pid=child.pid)(signal.SIGTERM)
        finally:
            child.kill()
            child.wait(timeout=2)


class BoundedCommands(unittest.TestCase):
    def start(self, command, budget="5"):
        return subprocess.Popen(
            [sys.executable, "-I", "-c", SOURCE, budget, "focused fixture", *command],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def test_original_command_exit_status_is_preserved(self):
        for result in (0, 7):
            with self.subTest(result=result):
                process = self.start(
                    [sys.executable, "-c", f"raise SystemExit({result})"]
                )
                _, error = process.communicate(timeout=5)
                self.assertEqual(process.returncode, result, error)

    def held_group(self, cancel):
        child_code = (
            "import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); "
            "print('ready',flush=True); time.sleep(60)"
        )
        command = (
            "import os,signal,subprocess,sys,time; "
            "signal.signal(signal.SIGTERM,signal.SIG_IGN); "
            f'child=subprocess.Popen([sys.executable,"-u","-c",{child_code!r}],'
            "stdout=subprocess.PIPE,text=True); "
            'assert child.stdout.readline().strip()=="ready"; '
            "print(os.getpid(),child.pid,flush=True); time.sleep(60)"
        )
        process = self.start(
            [sys.executable, "-u", "-c", command], budget="10" if cancel else "1"
        )
        group = None
        try:
            parent, _descendant = map(int, process.stdout.readline().split())
            group = parent
            if cancel:
                process.send_signal(signal.SIGTERM)
            _, error = process.communicate(timeout=8)
            self.assertEqual(
                process.returncode, 128 + signal.SIGTERM if cancel else 124, error
            )
            self.assertFalse(any(not state.startswith("Z") for state in states(group)))
            if not cancel:
                self.assertIn("exceeded its time budget", error)
        finally:
            if group is not None:
                cleanup(pid=group, platform=sys.platform)(signal.SIGKILL)
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=3)

    def test_timeout_still_terminates_term_ignoring_descendants(self):
        self.held_group(cancel=False)

    def test_cancellation_still_terminates_term_ignoring_descendants(self):
        self.held_group(cancel=True)


if __name__ == "__main__":
    unittest.main()
