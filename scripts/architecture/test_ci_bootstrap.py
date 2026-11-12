"""Exercise the actual trusted YAML parser against GitLab's observed wire value."""
import os
from pathlib import Path
import re
import subprocess
import textwrap
import unittest


YAML = (Path(__file__).parents[2] / 'ci/architecture-pipeline.yml').read_text()


def script():
    block = YAML.split('\nnative-qualification:\n', 1)[1].split('\n  script:\n    - |\n', 1)[1]
    return textwrap.dedent(block.split('\n  artifacts:\n', 1)[0])


class ConfigReference(unittest.TestCase):
    def match(self, uri, project='GetBusbar/busbar-auth-admin-tokens'):
        source = script()
        function = re.search(r'(?ms)^approved_revision\(\) \{\n.*?^\}\n', source)
        self.assertIsNotNone(function, 'the pipeline parser function is missing')
        env = {'PATH': '/usr/bin:/bin', 'CI_SERVER_HOST': 'git.example.test',
               'CI_PROJECT_PATH': project, 'CI_CONFIG_REF_URI': uri}
        result = subprocess.run(['/bin/sh', '-c', 'set -eu\n' + function[0] + 'approved_revision\n'],
                                env=env, capture_output=True, text=True)
        return result.stdout.strip() if result.returncode == 0 else None

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


class Bootstrap(unittest.TestCase):
    """The native/conformance bootstrap runs no operational Python of its own."""

    def test_native_jobs_run_only_the_trusted_compiled_controller(self):
        source = script()
        self.assertNotIn('<<', source)
        self.assertNotIn('native_ci_bootstrap', source)
        build = source.index('sh "$trusted/tools/ci/build-controller.sh" "$trusted" "$work/controller" &\n')
        self.assertLess(source.index('git -C "$trusted" checkout --detach FETCH_HEAD'), build)
        self.assertLess(source.index('!= "$revision"; then'), build)
        self.assertLess(build, source.index('wait "$build"\n'))
        self.assertLess(source.index('wait "$build"\n'), source.index('native-bootstrap --trusted'))
        self.assertIn('"$work/controller/target/debug/busbar-ci" native-bootstrap --trusted "$trusted"'
                      ' --checkout "$CI_PROJECT_DIR" --work "$work" ;;\n', source)
        # Cleanup on every exit path, including cancellation signals.
        self.assertLess(source.index("trap 'wait; rm -rf \"$work\"' EXIT"), source.index('mkdir "$trusted"'))
        self.assertIn("trap 'exit 143' TERM", source)
        # The credential is a Git header in the fetch environment only.
        self.assertNotRegex(source, r'(?m)^[^#]*(echo|printf)[^\n]*CI_JOB_TOKEN[^\n]*>[^&]')
        self.assertEqual(source.count('$CI_JOB_TOKEN'), 1)
        self.assertIn('if test "$(git -C "$trusted" rev-parse HEAD)" != "$revision"; then', source)

    def test_controller_build_uses_no_candidate_or_registry_input(self):
        build = (Path(__file__).parents[2] / 'tools/ci/build-controller.sh').read_text()
        self.assertIn('env -i ', build)
        self.assertIn('--locked', build)
        manifest = (Path(__file__).parents[2] / 'tools/ci/Cargo.toml').read_text()
        self.assertRegex(manifest, r'(?m)^\[dependencies\]\n(?:#.*\n|\s*\n)*(?:\[|\Z)')
        lock = (Path(__file__).parents[2] / 'tools/ci/Cargo.lock').read_text()
        self.assertEqual(lock.count('[[package]]'), 1)


if __name__ == '__main__':
    unittest.main()
