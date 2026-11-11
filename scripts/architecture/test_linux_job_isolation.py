"""Focused regressions for bounded candidate storage and remapped host identity."""

import json
import os
from pathlib import Path
import tempfile
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import confinement_entry
import linux_job_isolation as isolation


class Isolation(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR"))
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.writable = self.root / "candidate"
        self.writable.mkdir()
        self.config = {"storage_kind": "tmpfs", "storage_reserve_bytes": 0,
                       "storage_root": str(self.root), "storage_bytes": 16 * 1024**2,
                       "storage_inodes": 1024, "uid_map": [0, 524288, 65536],
                       "gid_map": [0, 524288, 65536]}
        self.rows = [{"path": self.root, "root": "/", "type": "tmpfs",
                      "options": {"rw", "nosuid", "nodev"}}]
        self.capacity = SimpleNamespace(f_blocks=4096, f_frsize=4096, f_files=1024)

    def validate(self):
        with patch.object(isolation.os, "geteuid", return_value=0), \
                patch.object(isolation, "mount_rows", return_value=self.rows), \
                patch.object(isolation.os, "statvfs", return_value=self.capacity):
            return isolation.validate_storage(self.config, [self.writable])

    def test_aggregate_byte_and_inode_limits_are_both_required(self):
        self.assertEqual(self.validate()["bytes"], 16 * 1024**2)
        for field, value in (("f_files", 1025), ("f_files", 0),
                             ("f_blocks", 4097), ("f_blocks", 0)):
            previous = getattr(self.capacity, field)
            setattr(self.capacity, field, value)
            with self.subTest(field=field, value=value), self.assertRaisesRegex(ValueError, "quota"):
                self.validate()
            setattr(self.capacity, field, previous)

    def test_bind_alias_or_nested_mount_cannot_bypass_cap(self):
        self.rows[0]["root"] = "/alias"
        with self.assertRaisesRegex(ValueError, "dedicated"):
            self.validate()
        self.rows[0]["root"] = "/"
        self.rows.append(dict(self.rows[0], path=self.writable / "escape"))
        with self.assertRaisesRegex(ValueError, "nested mount"):
            self.validate()

    def test_writable_roots_must_be_within_quota(self):
        self.writable = self.root.parent
        with self.assertRaisesRegex(ValueError, "escapes"):
            self.validate()

    def test_user_namespace_cannot_be_disabled_per_container(self):
        info = {"SecurityOptions": ["name=userns", "name=seccomp,profile=builtin"]}
        isolation.validate_userns(self.config, info, {"HostConfig": {"UsernsMode": ""}})
        with self.assertRaisesRegex(ValueError, "userns-remap"):
            isolation.validate_userns(self.config, {"SecurityOptions": []})
        with self.assertRaisesRegex(ValueError, "inherit"):
            isolation.validate_userns(self.config, info, {"HostConfig": {"UsernsMode": "host"}})

    def test_privileged_or_unbounded_mapping_rejected(self):
        for row in ([0, 0, 65536], [0, 65536, 0], [0, 2**32 - 1, 65536],
                    [1, 524288, 65536], [0, True, 65536]):
            with self.subTest(row=row), self.assertRaisesRegex(ValueError, "identity map"):
                isolation.validate_configuration(dict(self.config, uid_map=row))

    def test_entry_checks_real_map_before_candidate_command(self):
        env = {"BUSBAR_EXPECTED_UID_MAP": json.dumps(self.config["uid_map"]),
               "BUSBAR_EXPECTED_GID_MAP": json.dumps(self.config["gid_map"])}
        with patch.dict(os.environ, env), patch.object(Path, "read_text", return_value="0 0 4294967295\n"):
            with self.assertRaisesRegex(RuntimeError, "user namespace"):
                confinement_entry.verify_boundary()

    def test_ownership_preparation_does_not_follow_candidate_symlinks(self):
        target = self.root / "controller-secret"
        target.write_text("controller")
        (self.writable / "redirect").symlink_to(target)
        with patch.object(isolation, "validate_storage", return_value={}), \
                patch.object(isolation.os, "chown") as change:
            isolation.prepare_writable(self.config, [self.writable], 1001, 1002)
        change.assert_called_once_with(self.writable, 525289, 525290, follow_symlinks=False)
        self.assertEqual(target.read_text(), "controller")

    def test_ownership_preparation_rejects_external_hardlink(self):
        target = self.root / "controller-secret"
        target.write_text("controller")
        os.link(target, self.writable / "alias")
        with patch.object(isolation, "validate_storage", return_value={}), \
                patch.object(isolation.os, "chown") as change:
            with self.assertRaisesRegex(ValueError, "hard-linked"):
                isolation.prepare_writable(self.config, [self.writable], 1001, 1002)
        change.assert_called_once_with(self.writable, 525289, 525290, follow_symlinks=False)

    def disk_config(self):
        return dict(self.config, storage_kind="loop-ext4", storage_root=str(self.root / "store"),
                    storage_image=str(self.root / "job.ext4"), storage_bytes=64 * 1024**2,
                    storage_reserve_bytes=16 * 1024**2)

    def test_disk_budget_preflight_does_not_create_an_underfunded_job(self):
        config = self.disk_config()
        with patch.object(isolation.os, "geteuid", return_value=0), \
                patch.object(isolation, "protected_image_parent", return_value=self.root), \
                patch.object(isolation, "available_bytes", return_value=79 * 1024**2), \
                patch.object(isolation.subprocess, "run") as run:
            with self.assertRaisesRegex(ValueError, "insufficient host disk"):
                isolation.prepare(config)
        run.assert_not_called()
        self.assertFalse(Path(config["storage_root"]).exists())
        self.assertFalse(Path(config["storage_image"]).exists())

    def test_disk_image_cannot_be_inside_the_candidate_filesystem(self):
        config = self.disk_config()
        config["storage_image"] = str(Path(config["storage_root"]) / "job.ext4")
        with self.assertRaisesRegex(ValueError, "protected sibling"):
            isolation.validate_configuration(config)

    def test_failed_image_allocation_cleans_only_its_fresh_files(self):
        config = self.disk_config()
        with patch.object(isolation.os, "geteuid", return_value=0), \
                patch.object(isolation, "protected_image_parent", return_value=self.root), \
                patch.object(isolation, "available_bytes", return_value=128 * 1024**2), \
                patch.object(isolation.subprocess, "run", side_effect=OSError("allocation failed")):
            with self.assertRaisesRegex(OSError, "allocation failed"):
                isolation.prepare(config)
        self.assertFalse(Path(config["storage_root"]).exists())
        self.assertFalse(Path(config["storage_image"]).exists())

    def test_loop_detach_must_confirm_no_remaining_kernel_reference(self):
        with patch.object(isolation.subprocess, "run"), \
                patch.object(isolation.time, "sleep"), \
                patch.object(isolation, "loop_rows", return_value=[{"name": "/dev/loop7"}]):
            with self.assertRaisesRegex(ValueError, "still in use"):
                isolation.detach_loop("/dev/loop7", self.root / "job.ext4")

    def test_loop_backing_inode_and_device_limit_are_pinned(self):
        config = self.disk_config()
        metadata = SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_nlink=1, st_uid=0,
            st_size=config["storage_bytes"], st_blocks=config["storage_bytes"] // 512,
            st_dev=os.makedev(8, 1), st_ino=123)
        row = {"name": "/dev/loop7", "back-file": config["storage_image"], "back-ino": 123,
               "back-maj:min": "8:1", "offset": 0, "ro": False, "sizelimit": config["storage_bytes"]}
        with patch.object(isolation, "protected_image_parent"), \
                patch.object(Path, "lstat", return_value=metadata), \
                patch.object(isolation, "loop_rows", return_value=[row]):
            self.assertEqual(isolation.validate_loop(config, "/dev/loop7"), "/dev/loop7")
            for key, replacement in (("back-ino", 124), ("back-maj:min", "8:2"),
                                     ("sizelimit", 0), ("offset", 4096)):
                previous = row[key]
                row[key] = replacement
                with self.subTest(key=key), self.assertRaisesRegex(ValueError, "identity or limit"):
                    isolation.validate_loop(config, "/dev/loop7")
                row[key] = previous

    def test_existing_disk_image_is_never_truncated_or_removed(self):
        config = self.disk_config()
        image = Path(config["storage_image"])
        image.write_bytes(b"existing owner data")
        with patch.object(isolation.os, "geteuid", return_value=0), \
                patch.object(isolation, "protected_image_parent", return_value=self.root), \
                patch.object(isolation, "available_bytes", return_value=128 * 1024**2), \
                patch.object(isolation.subprocess, "run") as run:
            with self.assertRaisesRegex(ValueError, "image must be fresh"):
                isolation.prepare(config)
        run.assert_not_called()
        self.assertEqual(image.read_bytes(), b"existing owner data")


if __name__ == "__main__":
    unittest.main()
