"""Pinned C owner data cannot replace controller commands or required stages."""
import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest

from check import Violation, load_c_recipe, validate_c_recipe, vector_revisions, PUBLIC_C_HEADER


class CRecipe(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR'))
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.recipe = {'sources': ['owner/plugin.c'], 'test-root': 'owner',
                       'unit': {'sources': ['owner/tests/unit.c'], 'defines': ['BUSBAR_FIXTURE_UNIT']},
                       'schema': {'source': 'owner/tests/schema.c', 'driver': 'owner/tests/schema.py'}}
        self.repository = 'GetBusbar/busbar-fixture-c'
        self.entry = {'language': 'c', 'private': False, 'kind': 'secret', 'sources': ['owner/plugin.c']}
        self.policy = SimpleNamespace(data={'repositories': {self.repository: self.entry}})
        for path in ['owner/plugin.c', 'owner/tests/unit.c', 'owner/tests/schema.c', 'owner/tests/schema.py']:
            file = self.root / path
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_text('/* fixture */\n' if path.endswith('.c') else '# fixture\n')
        (self.root / 'testing').mkdir()
        self.metadata = self.root / 'testing/c-witness.json'
        self.metadata.write_text(json.dumps(self.recipe))
        self.git('init', '-q')
        self.commit()

    def git(self, *args):
        return subprocess.check_output(['git', '-c', 'core.hooksPath=/dev/null', '-c', 'commit.gpgsign=false',
            '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', '-C', str(self.root), *args],
            stderr=subprocess.PIPE).decode().strip()

    def commit(self):
        self.git('add', '.')
        self.git('commit', '-qm', 'C owner fixture')
        self.revision = self.git('rev-parse', 'HEAD')

    def load(self):
        return load_c_recipe(self.policy, self.repository, self.root, self.revision)

    def test_exact_owner_recipe_preserves_required_data(self):
        self.assertEqual(self.load(), self.recipe)

    def test_missing_unknown_or_command_fields_and_invalid_paths_refuse(self):
        bad = []
        for key in self.recipe:
            value = copy.deepcopy(self.recipe)
            del value[key]
            bad.append(value)
        bad += [dict(self.recipe, command=['sh', '-c', 'true']), dict(self.recipe, **{'test-root': '../outside'})]
        for field in ('source', 'driver'):
            value = copy.deepcopy(self.recipe)
            value['schema'][field] = '/outside'
            bad.append(value)
        for define in ['-include/private', 'BUSBAR_X=1', 'BUSBAR_X -o elsewhere']:
            value = copy.deepcopy(self.recipe)
            value['unit']['defines'] = [define]
            bad.append(value)
        value = copy.deepcopy(self.recipe)
        value['sources'] = ['owner/other.c']
        bad.append(value)
        for value in bad:
            with self.subTest(value=value), self.assertRaises(Violation):
                validate_c_recipe(value, self.entry)

    def test_modified_recipe_source_and_wrong_pin_refuse(self):
        self.metadata.write_text(json.dumps(dict(self.recipe, command='true')))
        with self.assertRaisesRegex(Violation, 'committed bytes'):
            self.load()
        self.metadata.write_text(json.dumps(self.recipe))
        (self.root / 'owner/plugin.c').write_text('changed')
        with self.assertRaisesRegex(Violation, 'committed bytes'):
            self.load()
        with self.assertRaisesRegex(Violation, 'admitted commit'):
            load_c_recipe(self.policy, self.repository, self.root, '0' * 40)

    def test_source_and_directory_symlinks_refuse(self):
        source = self.root / 'owner/plugin.c'
        source.unlink()
        source.symlink_to('tests/unit.c')
        self.commit()
        with self.assertRaisesRegex(Violation, 'regular Git blob'):
            self.load()

    def test_source_root_directory_symlink_refuses(self):
        (self.root / 'owner').rename(self.root / 'elsewhere')
        (self.root / 'owner').symlink_to('elsewhere', target_is_directory=True)
        with self.assertRaisesRegex(Violation, 'indirect product input'):
            self.load()

    def test_vector_cannot_override_header_or_add_commands(self):
        vector = {'sdk': 'a' * 40, 'products': [], 'c_witness': {
            'repo': 'busbar-fixture-c', 'url': 'https://github.com/' + self.repository,
            'commit': self.revision, 'sdk': 'a' * 40, 'kind': 'secret', 'language': 'c', 'header': PUBLIC_C_HEADER}}
        vector_revisions(self.policy, vector)
        for key, value in [('header', '../private.h'), ('command', 'true'), ('kind', 'store'), ('language', 'rust')]:
            changed = copy.deepcopy(vector)
            changed['c_witness'][key] = value
            with self.subTest(key=key), self.assertRaises(Violation):
                vector_revisions(self.policy, changed)


if __name__ == '__main__':
    unittest.main()
