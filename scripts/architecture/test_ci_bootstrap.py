"""Exercise the actual trusted YAML parser against GitLab's observed wire value."""
import ast
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import textwrap
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]


class ConfigReference(unittest.TestCase):
    def match(self, uri, project='GetBusbar/busbar-auth-admin-tokens'):
        yaml = (Path(__file__).parents[2] / 'ci/architecture-pipeline.yml').read_text()
        source = textwrap.dedent(yaml.split("      python3 -I -B - <<'PY'\n", 1)[1].split('\n      PY', 1)[0])
        assignment = next(node for node in ast.parse(source).body
                          if isinstance(node, ast.Assign)
                          and any(isinstance(target, ast.Name) and target.id == 'match' for target in node.targets))
        expression = compile(ast.Expression(assignment.value), '<actual-ci-parser>', 'eval')
        with patch.dict(os.environ, CI_SERVER_HOST='git.example.test', CI_PROJECT_PATH=project):
            return eval(expression, {'os': os, 're': re, 'uri': uri})

    def uri(self, project='GetBusbar/busbar-auth-admin-tokens', revision='a' * 40):
        return ('git.example.test/' + project + '//ci/architecture-pipeline.yml'
                '@GetBusbar/busbar:' + revision + '@refs/heads/corefix-boundary-hardening')

    def test_installed_gitlab_core_and_consumer_references(self):
        for project in ('GetBusbar/busbar', 'GetBusbar/busbar-release', 'BusbarInc/busbar-auth-scim'):
            with self.subTest(project=project):
                match = self.match(self.uri(project), project)
                self.assertIsNotNone(match)
                self.assertEqual(match[1], 'a' * 40)

    def test_current_dev_reference(self):
        uri = self.uri().replace('@refs/heads/corefix-boundary-hardening', '@refs/heads/dev')
        self.assertEqual(self.match(uri)[1], 'a' * 40)

    def test_untrusted_or_movable_configuration_is_rejected(self):
        uri = self.uri()
        for bad in (self.uri(revision='dev'), self.uri(revision='a' * 39),
                    uri.replace('@GetBusbar/busbar:', '@BusbarInc/other:'),
                    uri.replace('git.example.test/', 'other.example/'),
                    uri.replace('/busbar-auth-admin-tokens//', '/other//'),
                    uri.replace('/ci/architecture-pipeline.yml', '/candidate.yml'),
                    uri.replace('@refs/heads/', '@refs/tags/'), uri + '\n'):
            with self.subTest(uri=bad):
                self.assertIsNone(self.match(bad))


def job_block(name):
    text = (ROOT / 'ci/architecture-pipeline.yml').read_text()
    return text.split('\n' + name + ':\n', 1)[1].split('\n\n', 1)[0]


def security_script():
    block = job_block('security-scans')
    script = block.split('  script:\n    - |\n', 1)[1].split('\n  artifacts:', 1)[0]
    return '\n'.join(line[6:] for line in script.splitlines()) + '\n'


class SecurityBootstrap(unittest.TestCase):
    """security-scans runs no Python: POSIX sh selects and fetches the policy."""

    SHELLS = [shell for shell in ('/bin/sh', '/bin/dash', '/bin/bash') if Path(shell).exists()]

    def select(self, shell, uri, project):
        selection = security_script().split('test -n "${BUSBAR_NATIVE_SCRATCH+set}"', 1)[0]
        env = dict(PATH='/usr/bin:/bin', CI_CONFIG_REF_URI=uri, CI_SERVER_HOST='git.example.test',
                   CI_PROJECT_PATH=project, LANG='en_US.UTF-8')
        result = subprocess.run([shell, '-c', selection + 'printf "%s" "$revision"\n'], env=env,
                                capture_output=True, timeout=10)
        self.assertIn(result.returncode, (0, 1))
        if result.returncode:
            self.assertIn(b'must select the approved immutable core revision', result.stderr)
            return None
        return result.stdout.decode()

    def test_shell_selection_equals_the_python_bootstrap_parser(self):
        reference = ConfigReference()
        project = 'GetBusbar/busbar-auth-admin-tokens'
        base = reference.uri(project)
        uris = [base, 'https://' + base, 'https://https://' + base, 'http://' + base,
                base.replace('corefix-boundary-hardening', 'dev'), base.replace('corefix-boundary-hardening', ''),
                base.replace('a' * 40, 'A' * 40), base.replace('a' * 40, 'a' * 41), base.replace('a' * 40, 'dev'),
                base.replace('/' + project + '//', '/other//'), base.replace('git.example.test', 'git.exampleXtest'),
                base.replace('//ci/', '/ci/'), base.replace('@refs/heads/', '@refs/tags/'), 'x' + base,
                base + '@refs/heads/x', base + '/café', base + '*', base + '[x]', base + '$(id)'] + [
                base + space for space in (' x', '\t', '\n', '\r', '\x0b', '\x0c', '\x1c', '\x1f', '\x85',
                                           '\xa0', ' ', ' ', ' ', ' ', ' ', ' ',
                                           ' ', '　')]
        for shell in self.SHELLS:
            for uri in uris:
                with self.subTest(shell=shell, uri=uri):
                    match = reference.match(uri, project)
                    self.assertEqual(self.select(shell, uri, project), match and match[1])

    def test_job_has_its_own_python_free_script_and_one_controller_entry(self):
        block = job_block('security-scans')
        script = security_script()
        self.assertIn('  extends: native-qualification\n', block)
        self.assertNotRegex(block.lower(), r'python|\.py\b|<<')
        self.assertEqual(script.count('sh "$trusted/tools/ci/security-scans.sh" "$trusted" "$work" || exit 1'), 1)
        self.assertEqual(re.findall(r'.*CI_JOB_TOKEN.*', script),
                         ["auth=$(printf 'gitlab-ci-token:%s' \"$CI_JOB_TOKEN\" | base64 | tr -d '\\n')"])
        # The credential exists only in the one fetch command's environment.
        self.assertEqual(len(re.findall(r'\$auth\b', script)), 1)
        self.assertLess(script.index('git -C "$trusted" fetch --depth 1'), script.index('unset auth'))
        self.assertLess(script.index("trap 'rm -rf -- \"$work\"' EXIT"), script.index('git -C "$trusted" init -q'))
        self.assertLess(script.index('!= "$revision"'), script.index('tools/ci/security-scans.sh'))
        native = job_block('native-qualification')
        self.assertNotIn('security', native)
        self.assertNotIn('scripts/security', (ROOT / 'ci/architecture-pipeline.yml').read_text())

    def test_controller_is_a_separate_dependency_free_workspace(self):
        import tomllib
        root = tomllib.loads((ROOT / 'Cargo.toml').read_text())['workspace']
        self.assertFalse(any(member.startswith('tools') for member in root['members']))
        manifest = tomllib.loads((ROOT / 'tools/ci/Cargo.toml').read_text())
        self.assertEqual((manifest['package']['name'], manifest['workspace'], manifest['dependencies']),
                         ('busbar-ci', {}, {}))
        lock = tomllib.loads((ROOT / 'tools/ci/Cargo.lock').read_text())
        self.assertEqual(lock['package'], [{'name': 'busbar-ci', 'version': manifest['package']['version']}])
        # Executable entry points never start Python (Rust comments may cite scan.py history).
        for path in (ROOT / 'tools/ci').rglob('*'):
            if path.is_file() and path.suffix in ('.sh', '.toml', '.lock', '.pin'):
                self.assertNotIn(b'python', path.read_bytes().lower(), path)
            if path.suffix == '.rs':
                self.assertNotRegex(path.read_text(), r'Command::new\("(?!git"|docker"|sleep"|sh")', path)
        pin = dict(line.split('=', 1) for line in (ROOT / 'tools/ci/controller.pin').read_text().splitlines())
        self.assertEqual(set(pin), {'image', 'sha256', 'bytes', 'package'})
        self.assertRegex(pin['image'], r'^mirror\.gcr\.io/library/rust:[0-9.]+-alpine@sha256:[0-9a-f]{64}$')
        self.assertRegex(pin['sha256'], r'^[0-9a-f]{64}$')
        self.assertEqual(pin['package'], 'https://git.getbusbar.dev/api/v4/projects/3/packages/generic/'
                         'busbar-ci-controller/' + manifest['package']['version'] + '-' + pin['sha256'][:16]
                         + '/busbar-ci')


@unittest.skipUnless(shutil.which('sh'), 'POSIX sh required')
class ControllerAcquisition(unittest.TestCase):
    """tools/ci/security-scans.sh: pinned fetch, offline rebuild fallback, no token leak."""

    TOKEN = 'glcbt-CANARY-job-token'

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.trusted = self.root / 'trusted'
        shutil.copytree(ROOT / 'tools/ci', self.trusted / 'tools/ci',
                        ignore=shutil.ignore_patterns('target'))
        self.log = self.root / 'log'
        self.log.mkdir()
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        self.controller = ('#!/bin/sh\nprintf "%s\\n" "$@" > ' + str(self.log / 'controller.args') + '\n'
                           'env > ' + str(self.log / 'controller.env') + '\nexit "${FAKE_CONTROLLER_EXIT:-0}"\n')
        payload = self.controller.encode()
        self.pin(hashlib.sha256(payload).hexdigest(), len(payload))
        self.tool('curl', 'cat > "$LOG/curl.stdin"; printf "%s\\n" "$@" > "$LOG/curl.args"\n'
                  '[ -n "${FAKE_CURL_FAIL:-}" ] && exit 22\n'
                  'while [ $# -gt 1 ]; do [ "$1" = --output ] && out=$2; shift; done\n'
                  'printf "%s" "$FAKE_PAYLOAD" > "$out"\n')
        real = shutil.which('sha256sum')
        self.tool('sha256sum', ('exec ' + real if real else 'exec shasum -a 256') + ' "$@"\n')
        (self.trusted / 'tools/ci/build-controller.sh').write_text(
            '#!/bin/sh\nset -eu\nprintf "%s\\n" "$@" > "$LOG/build.args"\nmkdir "$2"\n'
            'printf "%s" "$FAKE_BUILT" > "$2/busbar-ci"\n')
        self.work = self.root / 'work'
        self.work.mkdir()

    def pin(self, digest, size):
        package = ('https://git.getbusbar.dev/api/v4/projects/3/packages/generic/busbar-ci-controller/'
                   '0.1.0-' + digest[:16] + '/busbar-ci')
        lines = [line for line in (self.trusted / 'tools/ci/controller.pin').read_text().splitlines()
                 if line.startswith('image=')]
        (self.trusted / 'tools/ci/controller.pin').write_text('\n'.join(
            lines + ['sha256=' + digest, 'bytes=' + str(size), 'package=' + package]) + '\n')

    def tool(self, name, body):
        (self.bin / name).write_text('#!/bin/sh\nLOG=' + str(self.log) + '\n' + body)
        (self.bin / name).chmod(0o755)

    def run_script(self, **env):
        environ = dict(PATH=str(self.bin) + ':/usr/bin:/bin', CI_JOB_TOKEN=self.TOKEN, LOG=str(self.log),
                       CI_PROJECT_DIR=str(self.root / 'project'), FAKE_PAYLOAD=self.controller,
                       FAKE_BUILT=self.controller)
        environ.update(env)
        return subprocess.run(['sh', str(self.trusted / 'tools/ci/security-scans.sh'), str(self.trusted),
                               str(self.work)], env=environ, capture_output=True, text=True, timeout=30)

    def leaked(self):
        return [path.name for path in self.log.iterdir() if path.name != 'curl.stdin'
                and path.name != 'controller.env' and self.TOKEN in path.read_text()]

    def test_pinned_download_runs_the_controller_with_fixed_arguments(self):
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('fetched by pinned digest', result.stdout)
        self.assertEqual((self.log / 'controller.args').read_text().splitlines(), [
            'security-scans', '--trusted', str(self.trusted), '--checkout', str(self.root / 'project'),
            '--work', str(self.work), '--output', str(self.root / 'project/boundary-evidence/security.json')])
        self.assertEqual((self.log / 'curl.stdin').read_text(), 'header = "JOB-TOKEN: ' + self.TOKEN + '"\n')
        self.assertIn('--proto', (self.log / 'curl.args').read_text())
        self.assertFalse((self.log / 'build.args').exists())
        self.assertEqual(self.leaked(), [])
        self.assertNotIn(self.TOKEN, result.stdout + result.stderr)

    def test_unavailable_or_mismatched_download_rebuilds_offline_from_trusted_source(self):
        for env in ({'FAKE_CURL_FAIL': '1'}, {'FAKE_PAYLOAD': 'tampered'}):
            with self.subTest(env=env):
                shutil.rmtree(self.work)
                self.work.mkdir()
                for path in self.log.iterdir():
                    path.unlink()
                result = self.run_script(**env)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('building it from trusted source', result.stdout)
                self.assertEqual((self.log / 'build.args').read_text().splitlines(), [
                    str(self.trusted / 'tools/ci'), str(self.work / 'controller/build'), 'unix:///var/run/docker.sock'])
                self.assertTrue((self.log / 'controller.args').exists())
                self.assertFalse((self.work / 'controller/busbar-ci').exists())
                self.assertEqual(self.leaked(), [])

    def test_controller_failure_and_malformed_pin_fail_the_job(self):
        self.assertEqual(self.run_script(FAKE_CONTROLLER_EXIT='1').returncode, 1)
        shutil.rmtree(self.work)
        self.work.mkdir()
        for path in self.log.iterdir():
            path.unlink()
        self.pin('not-a-digest', 1)
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.log / 'curl.args').exists())


if __name__ == '__main__':
    unittest.main()
