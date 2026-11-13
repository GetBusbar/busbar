"""Exercise the actual trusted YAML parser against GitLab's observed wire value."""
import ast
import os
from pathlib import Path
import re
import textwrap
import unittest
from unittest.mock import patch


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



class ControllerArtifacts(unittest.TestCase):
    """A later-stage job must start from a clean candidate checkout.

    GitLab extracts every earlier-stage job's artifacts into CI_PROJECT_DIR unless the job
    sets `dependencies`. core-conformance (stage qualify) then found core-build's
    boundary-evidence/ in its checkout and refused it as dirty (pipeline 3016). Every
    controller job reads earlier evidence through the API by job id, never from disk.
    """

    def test_controller_jobs_download_no_earlier_artifacts(self):
        yaml = (Path(__file__).parents[2] / 'ci/architecture-pipeline.yml').read_text()
        controller = yaml.split('\n.controller:\n', 1)[1].split('\n\n', 1)[0]
        controller = controller.split('\n  script:', 1)[0]
        self.assertIn('\n  dependencies: []', controller)
        self.assertEqual(yaml.count('dependencies:'), 1, 'no job may re-enable artifact downloads')


if __name__ == '__main__':
    unittest.main()
