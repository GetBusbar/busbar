"""Exercise the actual trusted YAML bootstrap and controller delivery.

Every trusted job (native/conformance/diagnostic and security-scans) shares one
POSIX sh script that selects the immutable policy, fetches it, and runs the one
pinned busbar-ci controller through tools/ci/controller.sh.
"""
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[2]
YAML = (ROOT / 'ci/architecture-pipeline.yml').read_text()
JOBS = ('native-qualification', 'core-conformance', 'external-conformance', 'native-isolation-diagnostic',
        'security-scans')


def script():
    block = YAML.split('\nnative-qualification:\n', 1)[1].split('\n  script:\n    - |\n', 1)[1]
    return textwrap.dedent(block.split('\n  artifacts:\n', 1)[0])


def job_block(name):
    return YAML.split('\n' + name + ':\n', 1)[1].split('\n\n', 1)[0]


def former_python_parser(uri, server_host, project):
    """The exact expression of the former in-YAML Python bootstrap (reference)."""
    return re.fullmatch(r'(?:https://)?' + re.escape(server_host) + '/' + re.escape(project)
                        + r'//ci/architecture-pipeline\.yml@GetBusbar/busbar:([0-9a-f]{40})@refs/heads/[^\s]+', uri)


def source_digest(directory, image):
    """controller.sh's build-input digest: sha256sum lines in byte order, then the image."""
    directory = Path(directory)
    files = [directory / name for name in ('Cargo.toml', 'Cargo.lock', 'build-controller.sh')]
    files += [path for path in (directory / 'src').rglob('*') if path.is_file()]
    names = sorted((path.relative_to(directory).as_posix() for path in files), key=str.encode)
    listing = ''.join(hashlib.sha256((directory / name).read_bytes()).hexdigest() + '  ' + name + '\n'
                      for name in names) + 'image=' + image + '\n'
    return hashlib.sha256(listing.encode()).hexdigest()


def read_pin(path=ROOT / 'tools/ci/controller.pin'):
    return dict(line.split('=', 1) for line in Path(path).read_text().splitlines())


SHELLS = [shell for shell in ('/bin/sh', '/bin/dash', '/bin/bash') if Path(shell).exists()]


def select(shell, uri, project, server_host='git.example.test'):
    selection = script().split('case $CI_JOB_NAME in', 1)[0]
    env = dict(PATH='/usr/bin:/bin', CI_CONFIG_REF_URI=uri, CI_SERVER_HOST=server_host,
               CI_PROJECT_PATH=project, LANG='en_US.UTF-8')
    result = subprocess.run([shell, '-c', selection + 'printf "%s" "$revision"\n'], env=env,
                            capture_output=True, timeout=10)
    assert result.returncode in (0, 1), result
    if result.returncode:
        assert b'must select the approved immutable core revision' in result.stderr, result.stderr
        return None
    return result.stdout.decode()


class ConfigReference(unittest.TestCase):
    def match(self, uri, project='GetBusbar/busbar-auth-admin-tokens'):
        return select('/bin/sh', uri, project)

    def uri(self, project='GetBusbar/busbar-auth-admin-tokens', revision='a' * 40):
        return ('git.example.test/' + project + '//ci/architecture-pipeline.yml'
                '@GetBusbar/busbar:' + revision + '@refs/heads/corefix-boundary-hardening')

    def test_installed_gitlab_core_and_consumer_references(self):
        for project in ('GetBusbar/busbar', 'GetBusbar/busbar-release', 'BusbarInc/busbar-auth-scim'):
            with self.subTest(project=project):
                self.assertEqual(self.match(self.uri(project), project), 'a' * 40)
                self.assertEqual(self.match('https://' + self.uri(project), project), 'a' * 40)

    def test_current_dev_reference(self):
        uri = self.uri().replace('@refs/heads/corefix-boundary-hardening', '@refs/heads/dev')
        self.assertEqual(self.match(uri), 'a' * 40)

    def test_untrusted_or_movable_configuration_is_rejected(self):
        uri = self.uri()
        for bad in (self.uri(revision='dev'), self.uri(revision='a' * 39), self.uri(revision='A' * 40),
                    uri.replace('@GetBusbar/busbar:', '@BusbarInc/other:'),
                    uri.replace('git.example.test/', 'other.example/'),
                    uri.replace('/busbar-auth-admin-tokens//', '/other//'),
                    uri.replace('/ci/architecture-pipeline.yml', '/candidate.yml'),
                    uri.replace('@refs/heads/', '@refs/tags/'),
                    uri.replace('@refs/heads/corefix-boundary-hardening', '@refs/heads/'),
                    uri + '\n', uri + ' x', uri + '\tx', 'http://' + uri, 'prefix' + uri):
            with self.subTest(uri=bad):
                self.assertIsNone(self.match(bad))

    def test_shell_selection_equals_the_former_python_parser(self):
        project = 'GetBusbar/busbar-auth-admin-tokens'
        base = self.uri(project)
        uris = [base, 'https://' + base, 'https://https://' + base, 'http://' + base,
                base.replace('corefix-boundary-hardening', 'dev'), base.replace('corefix-boundary-hardening', ''),
                base.replace('a' * 40, 'A' * 40), base.replace('a' * 40, 'a' * 41), base.replace('a' * 40, 'dev'),
                base.replace('/' + project + '//', '/other//'), base.replace('git.example.test', 'git.exampleXtest'),
                base.replace('//ci/', '/ci/'), base.replace('@refs/heads/', '@refs/tags/'), 'x' + base,
                base + '@refs/heads/x', base + '/café', base + '*', base + '[x]', base + '$(id)'] + [
                base + space for space in (' x', '\t', '\n', '\r', '\x0b', '\x0c', '\x1c', '\x1f', '\x85',
                                           '\xa0', ' ', ' ', ' ', ' ', ' ', ' ',
                                           ' ', ' ', '　')]
        for shell in SHELLS:
            for uri in uris:
                with self.subTest(shell=shell, uri=uri):
                    match = former_python_parser(uri, 'git.example.test', project)
                    self.assertEqual(select(shell, uri, project), match and match[1])


class Bootstrap(unittest.TestCase):
    """Every trusted job runs no operational Python of its own in the YAML."""

    def test_yaml_runs_no_python_and_every_job_shares_the_one_script(self):
        source = script()
        self.assertNotRegex(source.lower(), r'python|\.py\b|<<')
        # The only Python-named text left in the pipeline is an environment setting.
        self.assertEqual(re.findall(r'(?i).*python.*', YAML), ['    PYTHONDONTWRITEBYTECODE: "1"'])
        self.assertNotRegex(YAML, r'\.py\b')
        self.assertNotIn('native_ci_bootstrap', YAML)
        self.assertNotIn('scripts/security', YAML)
        self.assertEqual(YAML.count('  script:\n'), 1)
        for job in ('core-conformance', 'native-isolation-diagnostic', 'security-scans'):
            with self.subTest(job=job):
                self.assertIn('  extends: native-qualification\n', job_block(job))
        self.assertEqual(source.count('sh "$trusted/tools/ci/controller.sh" "$trusted" "$work" "$@"'), 1)
        self.assertEqual(len(re.findall(r'(?m)^ *controller [a-z-]+ ', source)), 2)

    def test_ordering_credential_and_cleanup(self):
        source = script()
        # Cleanup on every exit path, including cancellation signals.
        self.assertLess(source.index("trap 'rm -rf -- \"$work\"' EXIT"), source.index('mkdir -- "$trusted"'))
        self.assertLess(source.index("trap 'rm -rf -- \"$work\"' EXIT"), source.index('git -C "$trusted" init -q'))
        self.assertIn("trap 'exit 143' TERM", source)
        self.assertIn("trap 'exit 130' INT", source)
        # The credential is a Git header in the one fetch command's environment only.
        self.assertEqual(re.findall(r'.*CI_JOB_TOKEN.*', source),
                         ["auth=$(printf 'gitlab-ci-token:%s' \"$CI_JOB_TOKEN\" | base64 | tr -d '\\n')"])
        self.assertEqual(len(re.findall(r'\$auth\b', source)), 1)
        self.assertLess(source.index('git -C "$trusted" fetch --depth 1'), source.index('unset auth'))
        self.assertIn('if test "$(git -C "$trusted" rev-parse HEAD)" != "$revision"; then', source)
        verified = source.index('!= "$revision"; then')
        self.assertLess(source.index('git -C "$trusted" checkout --detach FETCH_HEAD'), verified)
        self.assertLess(verified, source.index('controller security-scans'))
        self.assertLess(verified, source.index('controller native-bootstrap'))
        self.assertLess(source.index("(*) echo 'unrecognized trusted native job'"), source.index('mkdir -- "$work"'))


@unittest.skipUnless(shutil.which('sh'), 'POSIX sh required')
class Dispatch(unittest.TestCase):
    """Run the actual YAML script with a stub Git and controller for each job."""

    REVISION = 'b' * 40

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        self.log = self.root / 'log'
        self.log.mkdir()
        (self.bin / 'git').write_text(textwrap.dedent('''\
            #!/bin/sh
            printf '%s\\n' "$*" >> "$LOG/git"
            case "$3" in
              rev-parse) printf '%s\\n' "$FAKE_HEAD" ;;
              checkout) mkdir -p "$2/tools/ci" && printf '%s\\n' \\
                'printf "%s\\n" "$@" > "$LOG/controller"; exit "${FAKE_EXIT:-0}"' > "$2/tools/ci/controller.sh" ;;
            esac
            '''))
        (self.bin / 'git').chmod(0o755)

    def run_job(self, job, head=REVISION, **env):
        uri = ('git.example.test/GetBusbar/busbar//ci/architecture-pipeline.yml@GetBusbar/busbar:'
               + self.REVISION + '@refs/heads/dev')
        environ = dict(PATH=str(self.bin) + ':/usr/bin:/bin', LOG=str(self.log), FAKE_HEAD=head,
                       CI_CONFIG_REF_URI=uri, CI_SERVER_HOST='git.example.test', CI_PROJECT_PATH='GetBusbar/busbar',
                       CI_SERVER_URL='https://git.example.test/', CI_JOB_TOKEN='glcbt-CANARY', CI_JOB_NAME=job,
                       CI_PROJECT_ID='3', CI_JOB_ID='77', CI_PROJECT_DIR=str(self.root / 'project'),
                       BUSBAR_NATIVE_SCRATCH=str(self.root / 'scratch'))
        environ.update(env)
        for path in self.log.iterdir():
            path.unlink()
        return subprocess.run(['sh', '-c', script()], env=environ, capture_output=True, text=True, timeout=30)

    def test_each_job_runs_exactly_its_controller_command(self):
        work = str(self.root / 'scratch/boundary-3-77')
        trusted = work + '/trusted'
        for job in JOBS:
            with self.subTest(job=job):
                result = self.run_job(job)
                self.assertEqual(result.returncode, 0, result.stderr)
                arguments = (self.log / 'controller').read_text().splitlines()
                self.assertEqual(arguments[:2], [trusted, work])
                if job == 'security-scans':
                    self.assertEqual(arguments[2:], [
                        'security-scans', '--trusted', trusted, '--checkout', str(self.root / 'project'),
                        '--work', work, '--output', str(self.root / 'project/boundary-evidence/security.json')])
                else:
                    self.assertEqual(arguments[2:], ['native-bootstrap', '--trusted', trusted, '--checkout',
                                                     str(self.root / 'project'), '--work', work])
                self.assertFalse(Path(work).exists(), 'staging root removed on exit')
                git = (self.log / 'git').read_text()
                self.assertIn('fetch --depth 1 https://git.example.test/GetBusbar/busbar.git ' + self.REVISION, git)
                self.assertNotIn('glcbt-CANARY', git + result.stdout + result.stderr)

    def test_unknown_job_mismatched_checkout_and_controller_failure_fail(self):
        result = self.run_job('candidate-job')
        self.assertEqual(result.returncode, 1)
        self.assertIn('unrecognized trusted native job', result.stderr)
        self.assertFalse((self.log / 'git').exists())
        result = self.run_job('native-qualification', head='c' * 40)
        self.assertEqual(result.returncode, 1)
        self.assertIn('trusted policy checkout mismatch', result.stderr)
        self.assertFalse((self.log / 'controller').exists())
        self.assertEqual(self.run_job('security-scans', FAKE_EXIT='1').returncode, 1)
        self.assertFalse((self.root / 'scratch/boundary-3-77').exists())


class ControllerCrate(unittest.TestCase):
    """One std-only crate, one pin, one delivery path for every job."""

    def test_controller_is_a_separate_dependency_free_workspace(self):
        import tomllib
        root = tomllib.loads((ROOT / 'Cargo.toml').read_text())['workspace']
        self.assertFalse(any(member.startswith('tools') for member in root['members']))
        manifest = tomllib.loads((ROOT / 'tools/ci/Cargo.toml').read_text())
        self.assertEqual((manifest['package']['name'], manifest['workspace'], manifest['dependencies']),
                         ('busbar-ci', {}, {}))
        self.assertEqual(set(manifest), {'package', 'workspace', 'dependencies', 'profile'})
        self.assertEqual(set(manifest['profile']), {'release'})
        self.assertNotIn('panic', manifest['profile']['release'])
        text = (ROOT / 'tools/ci/Cargo.toml').read_text()
        self.assertRegex(text, r'(?m)^\[dependencies\]\n(?:#.*\n|\s*\n)*(?:\[|\Z)')
        lock = tomllib.loads((ROOT / 'tools/ci/Cargo.lock').read_text())
        self.assertEqual(lock['package'], [{'name': 'busbar-ci', 'version': manifest['package']['version']}])
        self.assertEqual(sorted(path.name for path in (ROOT / 'tools/ci').iterdir()
                                if path.name != 'target'),
                         ['Cargo.lock', 'Cargo.toml', 'build-controller.sh', 'controller.pin', 'controller.sh', 'src'])

    def test_only_the_native_step_runner_paths_start_python(self):
        for path in (ROOT / 'tools/ci').rglob('*'):
            if 'target' in path.relative_to(ROOT / 'tools/ci').parts or not path.is_file():
                continue
            if path.suffix in ('.sh', '.toml', '.lock', '.pin'):
                self.assertNotIn(b'python', path.read_bytes().lower(), path)
            if path.suffix == '.rs' and path.name != 'bootstrap.rs':
                code = path.read_text().split('#[cfg(test)]', 1)[0]
                self.assertNotIn('/usr/bin/python3', code, path)
                self.assertNotRegex(code, r'"python3?"', path)
        security = (ROOT / 'tools/ci/src/security.rs').read_text()
        self.assertNotRegex(security, r'Command::new\("(?!git"|docker"|sleep"|sh")')
        bootstrap = (ROOT / 'tools/ci/src/bootstrap.rs').read_text().split('\n#[cfg(test)]\nmod tests', 1)[0]
        # Fixed trusted Python modules invoked by the controller: the native step
        # runner and the API-only diagnostic witnesses. The retention decision is
        # the controller's own `retention` command (no interpreter).
        self.assertEqual(sorted(set(re.findall(r'[a-z_]+\.py\b', bootstrap))),
                         ['native.py', 'native_isolation_diagnostic.py'])

    def test_pin_names_one_reproducible_binary_by_digest(self):
        manifest = (ROOT / 'tools/ci/Cargo.toml').read_text()
        version = re.search(r'(?m)^version = "([^"]+)"$', manifest)[1]
        pin = read_pin()
        self.assertEqual(list(pin), ['image', 'source', 'sha256', 'bytes', 'package'])
        self.assertRegex(pin['image'], r'^mirror\.gcr\.io/library/rust:1\.98\.0-alpine@sha256:[0-9a-f]{64}$')
        self.assertRegex(pin['source'], r'^[0-9a-f]{64}$')
        self.assertRegex(pin['sha256'], r'^[0-9a-f]{64}$')
        self.assertRegex(pin['bytes'], r'^[1-9][0-9]*$')
        self.assertEqual(pin['package'], 'https://github.com/api/v4/projects/3/packages/generic/'
                         'busbar-ci-controller/' + version + '-' + pin['sha256'][:16] + '/busbar-ci')

    def test_pin_is_not_stale(self):
        """Any change to the controller's build inputs must repin (sha256, bytes, source).

        Rebuild with build-controller.sh, upload the binary to the new package path,
        then record the digests. A stale pin is also refused at run time.
        """
        pin = read_pin()
        self.assertEqual(source_digest(ROOT / 'tools/ci', pin['image']), pin['source'],
                         'tools/ci changed since controller.pin was recorded: rebuild and repin')

    def test_source_digest_changes_with_every_build_input(self):
        with tempfile.TemporaryDirectory() as temporary:
            copy = Path(temporary) / 'ci'
            shutil.copytree(ROOT / 'tools/ci', copy, ignore=shutil.ignore_patterns('target'))
            image = read_pin()['image']
            original = source_digest(copy, image)
            self.assertNotEqual(source_digest(copy, image.replace('a', 'b', 1)), original)
            for name in ('Cargo.toml', 'Cargo.lock', 'build-controller.sh', 'src/main.rs'):
                with self.subTest(name=name):
                    path = copy / name
                    raw = path.read_bytes()
                    path.write_bytes(raw + b'\n')
                    self.assertNotEqual(source_digest(copy, image), original)
                    path.write_bytes(raw)
            (copy / 'src/added.rs').write_text('')
            self.assertNotEqual(source_digest(copy, image), original)
            (copy / 'src/added.rs').unlink()
            (copy / 'controller.sh').write_text('changed')
            self.assertEqual(source_digest(copy, image), original)

    def test_reproducible_offline_build(self):
        build = (ROOT / 'tools/ci/build-controller.sh').read_text()
        for needle in ('--network=none', '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges',
                       '--pull=never', 'build --release --locked --offline --target x86_64-unknown-linux-musl',
                       '-e SOURCE_DATE_EPOCH=0', 'env -i ', 'type=bind,src=$src,dst=/src,readonly',
                       'test -z "$(find "$src" -type l -print)"'):
            self.assertIn(needle, build)


@unittest.skipUnless(shutil.which('sh'), 'POSIX sh required')
class ControllerAcquisition(unittest.TestCase):
    """tools/ci/controller.sh: pinned fetch, offline rebuild fallback, stale-pin refusal, no token leak."""

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
        self.tool('curl', 'cat > "$LOG/curl.stdin"; printf "%s\\n" "$@" > "$LOG/curl.args"\n'
                  '[ -n "${FAKE_CURL_FAIL:-}" ] && exit 22\n'
                  'while [ $# -gt 1 ]; do [ "$1" = --output ] && out=$2; shift; done\n'
                  'printf "%s" "$FAKE_PAYLOAD" > "$out"\n')
        real = shutil.which('sha256sum')
        self.tool('sha256sum', ('exec ' + real if real else 'exec shasum -a 256') + ' "$@"\n')
        (self.trusted / 'tools/ci/build-controller.sh').write_text(
            '#!/bin/sh\nset -eu\nprintf "%s\\n" "$@" > "$LOG/build.args"\nmkdir "$2"\n'
            'printf "%s" "$FAKE_BUILT" > "$2/busbar-ci"\n')
        payload = self.controller.encode()
        self.pin(hashlib.sha256(payload).hexdigest(), len(payload))
        self.work = self.root / 'work'
        self.work.mkdir()

    def pin(self, digest, size, source=None):
        package = ('https://github.com/api/v4/projects/3/packages/generic/busbar-ci-controller/'
                   '0.1.0-' + digest[:16] + '/busbar-ci')
        image = read_pin()['image']
        source = source or source_digest(self.trusted / 'tools/ci', image)
        (self.trusted / 'tools/ci/controller.pin').write_text('\n'.join(
            ['image=' + image, 'source=' + source, 'sha256=' + digest, 'bytes=' + str(size),
             'package=' + package]) + '\n')

    def tool(self, name, body):
        (self.bin / name).write_text('#!/bin/sh\nLOG=' + str(self.log) + '\n' + body)
        (self.bin / name).chmod(0o755)

    def reset(self):
        shutil.rmtree(self.work)
        self.work.mkdir()
        for path in self.log.iterdir():
            path.unlink()

    def run_script(self, *arguments, **env):
        environ = dict(PATH=str(self.bin) + ':/usr/bin:/bin', CI_JOB_TOKEN=self.TOKEN, LOG=str(self.log),
                       FAKE_PAYLOAD=self.controller, FAKE_BUILT=self.controller)
        environ.update(env)
        arguments = arguments or ('native-bootstrap', '--trusted', str(self.trusted))
        return subprocess.run(['sh', str(self.trusted / 'tools/ci/controller.sh'), str(self.trusted),
                               str(self.work), *arguments], env=environ, capture_output=True, text=True, timeout=30)

    def leaked(self):
        return [path.name for path in self.log.iterdir() if path.name != 'curl.stdin'
                and path.name != 'controller.env' and self.TOKEN in path.read_text()]

    def test_pinned_download_runs_the_controller_with_exact_arguments(self):
        for arguments in (('security-scans', '--trusted', 'T', '--output', 'a b'),
                          ('native-bootstrap', '--trusted', 'T', '--work', 'W')):
            with self.subTest(arguments=arguments):
                self.reset()
                result = self.run_script(*arguments)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('fetched by pinned digest', result.stdout)
                self.assertEqual((self.log / 'controller.args').read_text().splitlines(), list(arguments))
                self.assertEqual((self.log / 'curl.stdin').read_text(), 'header = "JOB-TOKEN: ' + self.TOKEN + '"\n')
                curl = (self.log / 'curl.args').read_text().splitlines()
                self.assertIn('=https', curl)
                self.assertEqual(curl[-1], read_pin(self.trusted / 'tools/ci/controller.pin')['package'])
                self.assertFalse((self.log / 'build.args').exists())
                self.assertTrue((self.work / 'controller/busbar-ci').is_file())
                self.assertEqual(self.leaked(), [])
                self.assertNotIn(self.TOKEN, result.stdout + result.stderr)

    def test_unavailable_or_mismatched_download_rebuilds_offline_from_trusted_source(self):
        for env in ({'FAKE_CURL_FAIL': '1'}, {'FAKE_PAYLOAD': 'tampered'},
                    {'FAKE_PAYLOAD': self.controller + ' '}):
            with self.subTest(env=env):
                self.reset()
                result = self.run_script(**env)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('building it from trusted source', result.stdout)
                self.assertEqual((self.log / 'build.args').read_text().splitlines(), [
                    str(self.trusted / 'tools/ci'), str(self.work / 'controller/build'), 'unix:///var/run/docker.sock'])
                self.assertTrue((self.log / 'controller.args').exists())
                self.assertFalse((self.work / 'controller/busbar-ci').exists())
                self.assertEqual(self.leaked(), [])

    def test_stale_pin_is_never_fetched_and_rebuilds_from_source(self):
        payload = self.controller.encode()
        self.pin(hashlib.sha256(payload).hexdigest(), len(payload), source='0' * 64)
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('controller pin is stale', result.stdout)
        self.assertFalse((self.log / 'curl.args').exists())
        self.assertTrue((self.log / 'build.args').exists())
        self.assertTrue((self.log / 'controller.args').exists())

    def test_controller_failure_and_malformed_pin_fail_the_job(self):
        self.assertEqual(self.run_script(FAKE_CONTROLLER_EXIT='1').returncode, 1)
        for digest, source in (('not-a-digest', None), ('a' * 64, 'short')):
            with self.subTest(digest=digest, source=source):
                self.reset()
                self.pin(digest, 1, source)
                result = self.run_script()
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((self.log / 'curl.args').exists())
                self.assertFalse((self.log / 'controller.args').exists())

    def test_linked_source_is_refused(self):
        (self.trusted / 'tools/ci/src/link.rs').symlink_to('/etc/hosts')
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.log / 'curl.args').exists())
        self.assertFalse((self.log / 'controller.args').exists())



class RetentionPipeline(unittest.TestCase):
    """The strict job graph: retention runs before bootstrap; schedules run security only.

    Moved from the former test_ci_retention.py when the retention decision moved
    from scripts/architecture/ci_retention.py into the controller (tools/ci/src/
    retention.rs, unit-tested there with the former Python cases).
    """

    def setUp(self):
        self.blocks = dict(re.findall(r'^([a-z][a-z-]*):\n((?:(?: .*)?\n)*)', YAML, re.M))

    def test_schedule_runs_security_only(self):
        self.assertIn("- if: '$CI_PIPELINE_SOURCE == \"schedule\" && $CI_COMMIT_BRANCH == \"dev\"'",
                      self.blocks['workflow'])
        never = "    - if: '$CI_PIPELINE_SOURCE == \"schedule\"'\n      when: never\n"
        for job in ('native-qualification', 'core-conformance'):
            self.assertIn(never, self.blocks[job], job)
        self.assertNotIn('"schedule"', self.blocks['security-scans'])
        self.assertIn('  rules:\n', self.blocks['security-scans'])
        website = self.blocks['website-dev']
        self.assertNotIn('"schedule"', website)
        self.assertEqual(re.findall(r'CI_PIPELINE_SOURCE == "(\w+)"', website), ['push', 'push'])

    def test_retention_decides_before_bootstrap_for_expensive_kinds_only(self):
        # The YAML is POSIX sh; the trusted controller's native-bootstrap entry
        # makes the decision before any bootstrap download, by running its own
        # verified binary's `retention` command (never an interpreter).
        self.assertNotIn('ci_retention', YAML)
        self.assertFalse((ROOT / 'scripts/architecture/ci_retention.py').exists())
        self.assertIn('controller native-bootstrap --trusted', self.blocks['native-qualification'])
        source = (ROOT / 'tools/ci/src/bootstrap.rs').read_text().split('\n#[cfg(test)]\nmod tests', 1)[0]
        self.assertNotIn('ci_retention', source)
        self.assertIn('pub const RETAINABLE: [&str; 2] = ["native-qualification", "core-conformance"];', source)
        command = source.split('\npub fn retention_command(', 1)[1].split('\n}\n', 1)[0]
        self.assertIn('vec![\n        path_text(binary),\n        "retention".into(),', command)
        self.assertNotIn('python', command.lower())
        outer = source.split('\nfn outer(', 1)[1].split('\n}\n', 1)[0]
        decision = outer.index('if retained(&binary, &checkout, &revision, &env["CI_JOB_NAME"])? {\n'
                               '        return Ok(());\n    }')
        # Only identity checks precede it; every download and image load follows.
        self.assertLess(outer.index('verify_trusted(&trusted, &revision)?'), decision)
        self.assertLess(outer.index('let binary = fs::canonicalize('), decision)
        for later in ('fetch::fetch(', 'load_tool_image(', 'entry_command('):
            self.assertLess(decision, outer.index(later), later)
        self.assertEqual(outer.count('fetch::'), 1)
        retained = source.split('\nfn decide_retention(', 1)[1].split('\n}\n', 1)[0]
        self.assertIn('if decided && regular {\n        return Ok(true);', retained)
        self.assertIn('"retention decision left evidence without retaining"', retained)
        self.assertIn('is_ok_and(|m| m.file_type().is_file())', retained)
        main = (ROOT / 'tools/ci/src/main.rs').read_text()
        self.assertIn('"retention" => retention_main(args),', main)
        self.assertNotRegex(YAML, r'(?m)^\s*(needs|dependencies|include|default):')
        self.assertNotRegex(YAML, r'\$(BUSBAR_)?(SKIP|RETAIN)')

    def test_retention_contract_and_credential_confinement(self):
        code = (ROOT / 'tools/ci/src/retention.rs').read_text().split('\n#[cfg(test)]', 1)[0]
        for literal in ('"busbar.ci-retained-check/1"', '"busbar.ci-input-identity/1"',
                        '"busbar.protected-native-admission/1"', '"busbar.protected-conformance/1"',
                        'pub const RETAINED: i32 = 0;', 'pub const FRESH: i32 = 3;',
                        '"busbar-retention: {kind}: retained(original job {}, pipeline {}, identity {})"',
                        '"busbar-retention: {kind}: fresh({})"'):
            self.assertIn(literal, code)
        self.assertNotRegex(code.lower(), r'python3|"python')
        # The job token is read from the environment and reaches curl only as a
        # stdin-configured header (fetch::get), never an argument or a log line.
        self.assertEqual(len(re.findall(r'.*"CI_JOB_TOKEN".*', code)), 4)
        self.assertNotRegex(code, r'\.arg\([^)]*token')
        self.assertNotRegex(code, r'(print_line|eprintln!|println!)\([^;]*token')
        fetch = (ROOT / 'tools/ci/src/fetch.rs').read_text().split('\n#[cfg(test)]', 1)[0]
        get = fetch.split('\npub fn get(', 1)[1].split('\n}\n', 1)[0]
        self.assertIn('&proc::strings(&[CURL, "--disable", "--config", "-"])', get)
        self.assertIn('header = {}', get)

    def test_owner_workstation_grammar_still_accepts_the_graph(self):
        import sys
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from reuse_evidence import independent_qualification_job
        for job in ('native-qualification', 'security-scans', 'core-conformance'):
            self.assertTrue(independent_qualification_job(YAML.encode(), job))

if __name__ == '__main__':
    unittest.main()
