"""Candidate sources qualify before their public stage branches can advance."""
import re
import tempfile
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from native_sources import inputs, product_inputs, prepare, standalone_products


class Sources(unittest.TestCase):
    def test_standalone_inputs_are_selected_by_controller_mode_only(self):
        oidc = {'repo': 'busbar-auth-oidc'}
        vector = {'products': [{'repo': 'busbar-store-mysql'}, oidc]}
        self.assertEqual(standalone_products('GetBusbar/busbar', False, vector), vector['products'])
        for repository, evaluation in [('GetBusbar/busbar', True),
                ('GetBusbar/busbar-release', False)]:
            self.assertEqual(standalone_products(repository, evaluation, vector), [oidc])
            for products in ([], [oidc, oidc]):
                with self.assertRaisesRegex(ValueError, 'absent or ambiguous'):
                    standalone_products(repository, evaluation, {'products': products})
        self.assertEqual(standalone_products('GetBusbar/busbar-plane-mcp', False, vector), [])
        for evaluation in (None, 'false', 0):
            with self.assertRaisesRegex(ValueError, 'controller job mode'):
                standalone_products('GetBusbar/busbar', evaluation, vector)

    def test_required_transitive_pins_survive_without_standalone_only_history(self):
        repository = 'GetBusbar/busbar-store-mysql'
        needed, extra, current, sdk = ('a' * 40, 'b' * 40, 'c' * 40, 'd' * 40)
        def data(revision):
            return ('[[package]]\nname="mysql_common"\nversion="1.0.0"\n'
                'source="git+https://github.com/' + repository + '?rev=' + revision + '#' + revision + '"\n').encode()
        product_data = data(extra)
        vector = {'sdk': sdk, 'products': [{'repo': 'busbar-auth-oidc', 'commit': current,
                                           'lock_sha256': hashlib.sha256(product_data).hexdigest()}]}
        for owner, evaluation, standalone in [('GetBusbar/busbar', False, True),
                ('GetBusbar/busbar', True, True), ('GetBusbar/busbar-release', False, True),
                ('GetBusbar/busbar-plane-mcp', False, False)]:
            with self.subTest(owner=owner, evaluation=evaluation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / 'scripts').mkdir()
                (root / 'scripts/ci-product-pins.json').write_text(json.dumps(vector))
                (root / 'Cargo.lock').write_bytes(data(needed))
                work = root / 'work'
                work.mkdir()
                q = SimpleNamespace(repository=owner, evaluation_only=evaluation, root=root,
                    work=work, sdk=lambda: root, policy=SimpleNamespace(data={'repositories': {
                        repository: {'private': False}, 'GetBusbar/busbar-auth-oidc': {'private': False}}}),
                    env={}, receipt={}, save=lambda: None)
                with patch('native.fetch_environment', return_value={'CI_SERVER_URL': 'https://github.com'}), \
                     patch('native.git', side_effect=lambda path, *args: args[-1].removeprefix('refs/heads/input-') if args[-1].startswith('refs/') else current), \
                     patch('native_sources.subprocess.run'), \
                     patch('native_sources.subprocess.check_output', return_value=product_data) as read:
                    prepare(q, root)
                self.assertEqual(q.receipt['canonical_inputs'][repository], sorted({needed} | ({extra} if standalone else set())))
                self.assertEqual(q.receipt['canonical_inputs']['GetBusbar/busbar-auth-oidc'], [current])
                self.assertEqual(read.call_count, int(standalone))
                # Core jobs no longer read their own HEAD from canonical-inputs.
                self.assertEqual(q.receipt['canonical_inputs']['GetBusbar/busbar'],
                                 sorted({sdk} | (set() if owner == 'GetBusbar/busbar' else {current})))

    def test_collects_exact_public_commits_and_rejects_mutable_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy = {'repositories': {'GetBusbar/busbar-store-memory': {'private': False},
                                       'BusbarInc/busbar-store-mssql': {'private': True}}}
            template = '[[package]]\nname="example"\nversion="1.0.0"\nsource="{}"\n'
            source = 'git+https://github.com/GetBusbar/busbar-store-memory?rev=' + 'a' * 40 + '#' + 'a' * 40
            (root / 'Cargo.lock').write_text(template.format(source))
            self.assertEqual(inputs(root, root, policy), {'GetBusbar/busbar-store-memory': {'a' * 40}})
            for wrong in (source.replace('rev=' + 'a' * 40, 'rev=dev'), source[:-1] + 'b'):
                (root / 'Cargo.lock').write_text(template.format(wrong))
                with self.assertRaisesRegex(ValueError, 'immutable'):
                    inputs(root, root, policy)

    def test_private_sources_never_enter_public_rewrite_map(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'Cargo.lock').write_text('[[package]]\nname="private"\nversion="1.0.0"\n'
                'source="git+https://git.example/BusbarInc/private?rev=' + 'a' * 40 + '#' + 'a' * 40 + '"\n')
            self.assertEqual(inputs(root, root, {'repositories': {}}), {})

    def test_unused_sdk_patches_are_prefetched_with_the_same_identity_checks(self):
        # Cargo loads patched sources even when they do not enter the package
        # graph. The immutable SDK lock records these as [[patch.unused]].
        from native_sources import lock_inputs
        repository = 'GetBusbar/busbar-store-mysql'
        codec = '8407ab816c5606483549b13fc958054df837abd1'
        policy = {'repositories': {repository: {'private': False}}}
        source = 'git+https://github.com/' + repository + '?rev=' + codec + '#' + codec
        template = '[[patch.unused]]\nname="mysql_common"\nversion="0.35.5"\nsource="{}"\n'
        self.assertEqual(lock_inputs(template.format(source), policy), {repository: {codec}})
        self.assertEqual(lock_inputs(template.format(source),
                                     {'repositories': {repository: {'private': True}}}), {})
        for wrong in (source.replace('rev=' + codec, 'rev=dev'), source[:-1] + '0'):
            with self.assertRaisesRegex(ValueError, 'immutable'):
                lock_inputs(template.format(wrong), policy)

    def test_standalone_product_lock_adds_its_historical_codec_pin(self):
        from unittest.mock import patch
        head, codec = 'a' * 40, 'b' * 40
        repo = 'busbar-store-mysql'
        data = ('[[package]]\nname="mysql_common"\nversion="0.35.5"\n'
                'source="git+https://github.com/GetBusbar/' + repo + '?rev=' + codec + '#' + codec + '"\n').encode()
        product = {'repo':repo, 'commit':head, 'lock_sha256':hashlib.sha256(data).hexdigest()}
        policy = {'repositories':{'GetBusbar/'+repo:{'private':False}}}
        with tempfile.TemporaryDirectory() as directory, patch('native_sources.subprocess.check_output', return_value=data) as show:
            parent = Path(directory)
            self.assertEqual(product_inputs(parent, {'products':[product]}, policy), {'GetBusbar/'+repo:{codec}})
            show.assert_called_once_with(['git','-C',str(parent/repo),'show',head+':Cargo.lock'])
            product['lock_sha256'] = '0' * 64
            with self.assertRaisesRegex(ValueError, 'lock differs'):
                product_inputs(parent, {'products':[product]}, policy)


    def plugin_fixture(self, root, policy_private=False):
        """A plugin job whose SDK distribution and vector pin extra revisions."""
        sdk_rev, host_rev, own, sdk_dist, vector_only = 'd' * 40, 'e' * 40, 'a' * 40, 'b' * 40, 'c' * 40
        def lock(repository, revision):
            return ('[[package]]\nname="x"\nversion="1.0.0"\nsource="git+https://github.com/'
                    + repository + '?rev=' + revision + '#' + revision + '"\n')
        host, sdk, candidate = root / 'work/host', root / 'work/sdk', root / 'candidate'
        for path in (host / 'scripts', host / 'dist/default', sdk / 'dist/default', candidate):
            path.mkdir(parents=True)
        (host / 'scripts/ci-product-pins.json').write_text(json.dumps({'sdk': sdk_rev, 'products': [
            {'repo': 'busbar-store-memory', 'commit': own}, {'repo': 'busbar-auth-ldap', 'commit': vector_only}]}))
        (host / 'Cargo.lock').write_text('')
        (host / 'dist/default/Cargo.lock').write_text(lock('GetBusbar/busbar-store-memory', own))
        (sdk / 'Cargo.lock').write_text(lock('GetBusbar/busbar', sdk_rev))
        (sdk / 'dist/default/Cargo.lock').write_text(lock('GetBusbar/busbar-store-memory', sdk_dist))
        (candidate / 'Cargo.lock').write_text(lock('GetBusbar/busbar-store-memory', own))
        policy = {'repositories': {'GetBusbar/busbar-plane-mcp': {'private': False},
                                   'GetBusbar/busbar-store-memory': {'private': False},
                                   'GetBusbar/busbar-auth-ldap': {'private': policy_private}}}
        q = SimpleNamespace(repository='GetBusbar/busbar-plane-mcp', evaluation_only=False, root=candidate,
            work=root / 'work', sdk=lambda: sdk, policy=SimpleNamespace(data=policy),
            env={}, receipt={}, save=lambda: None)
        heads = {host.resolve(): host_rev, sdk.resolve(): sdk_rev}
        return q, host, sdk, heads, (sdk_rev, host_rev, own, sdk_dist, vector_only)

    def run_prepare(self, q, host, heads, run=None):
        calls = []
        def fake_run(argv, **kwargs):
            calls.append(argv)
            if run:
                run(argv)
        def fake_git(path, *args):
            if args[-1].startswith('refs/heads/input-'):
                return args[-1].removeprefix('refs/heads/input-')
            return heads[Path(path).resolve()]
        with patch('native.fetch_environment', return_value={'CI_SERVER_URL': 'https://github.com'}), \
             patch('native.git', side_effect=fake_git), \
             patch('native_sources.subprocess.run', side_effect=fake_run):
            prepare(q, host)
        return [argv for argv in calls if 'fetch' in argv]

    def test_plugin_fetches_only_seeded_subject_closures_from_exact_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            q, host, sdk, heads, (sdk_rev, host_rev, own, sdk_dist, vector_only) = self.plugin_fixture(Path(directory))
            fetches = self.run_prepare(q, host, heads)
            self.assertEqual(q.receipt['canonical_inputs'], {
                'GetBusbar/busbar': [sdk_rev], 'GetBusbar/busbar-store-memory': [own]})
            remotes = sorted(argv[argv.index('1') + 1] for argv in fetches)
            # The SDK revision comes from the verified controller checkout, not the forge.
            self.assertEqual(remotes, sorted([str(sdk.resolve()),
                'https://github.com/GetBusbar/busbar-store-memory.git']))
            for argv in fetches:
                self.assertEqual(argv[3:8], ['fetch', '--quiet', '--no-tags', '--depth', '1'])
            joined = ' '.join(' '.join(argv) for argv in fetches)
            for unused in (sdk_dist, vector_only, host_rev):
                self.assertNotIn(unused, joined)

    def test_core_fetches_subject_closures_and_vector_products_only(self):
        with tempfile.TemporaryDirectory() as directory:
            q, host, sdk, heads, (sdk_rev, host_rev, own, sdk_dist, vector_only) = self.plugin_fixture(Path(directory))
            # A core job: the candidate checkout is the host.
            q.repository, q.root = 'GetBusbar/busbar', host
            q.policy.data['repositories']['GetBusbar/busbar'] = {'private': False}
            (host / 'Cargo.lock').write_text((q.work.parent / 'candidate/Cargo.lock').read_text())
            calls = []
            with patch('native_sources.product_inputs', side_effect=lambda *a: calls.append(a) or {}):
                fetches = self.run_prepare(q, host, heads)
            self.assertEqual(q.receipt['canonical_inputs'], {
                'GetBusbar/busbar': [sdk_rev], 'GetBusbar/busbar-store-memory': [own],
                'GetBusbar/busbar-auth-ldap': [vector_only]})
            joined = ' '.join(' '.join(argv) for argv in fetches)
            for unused in (sdk_dist, host_rev):
                self.assertNotIn(unused, joined)
            # Every vector product still reaches the standalone product closure.
            self.assertEqual([row['repo'] for row in calls[0][1]['products']],
                             ['busbar-store-memory', 'busbar-auth-ldap'])

    def test_plugin_still_rejects_private_vector_products(self):
        with tempfile.TemporaryDirectory() as directory:
            q, host, _, heads, _ = self.plugin_fixture(Path(directory), policy_private=True)
            with self.assertRaisesRegex(ValueError, 'private repository'):
                self.run_prepare(q, host, heads)

    def test_one_shallow_fetch_per_repository_and_identity_is_verified(self):
        with tempfile.TemporaryDirectory() as directory:
            q, host, _, heads, (_, _, own, _, _) = self.plugin_fixture(Path(directory))
            second = 'f' * 40
            (q.root / 'Cargo.lock').write_text(''.join(
                '[[package]]\nname="x' + r[0] + '"\nversion="1.0.0"\nsource="git+https://github.com/'
                'GetBusbar/busbar-store-memory?rev=' + r + '#' + r + '"\n' for r in (own, second)))
            fetches = self.run_prepare(q, host, heads)
            memory = [argv for argv in fetches if argv[-1].startswith(('refs', own, second))
                      and 'busbar-store-memory.git' in ' '.join(argv)]
            self.assertEqual(len(memory), 1)
            self.assertEqual(memory[0][-2:], [own + ':refs/heads/input-' + own, second + ':refs/heads/input-' + second])
        with tempfile.TemporaryDirectory() as directory:
            q, host, _, heads, _ = self.plugin_fixture(Path(directory))
            with patch('native.fetch_environment', return_value={'CI_SERVER_URL': 'https://github.com'}), \
                 patch('native.git', side_effect=lambda path, *args: '0' * 40 if args[-1].startswith('refs/')
                       else heads[Path(path).resolve()]), \
                 patch('native_sources.subprocess.run'):
                with self.assertRaisesRegex(ValueError, 'revision mismatch'):
                    prepare(q, host)

    def test_independent_repositories_fetch_concurrently(self):
        import threading
        with tempfile.TemporaryDirectory() as directory:
            q, host, _, heads, (sdk_rev, _, own, _, _) = self.plugin_fixture(Path(directory))
            # Two network repositories must be in flight together; a serial loop
            # would break this barrier. The SDK comes from its local checkout.
            (q.root / 'Cargo.lock').write_text(
                '[[package]]\nname="x"\nversion="1.0.0"\nsource="git+https://github.com/GetBusbar/'
                'busbar-store-memory?rev=' + own + '#' + own + '"\n'
                '[[package]]\nname="y"\nversion="1.0.0"\nsource="git+https://github.com/GetBusbar/'
                'busbar-plane-mcp?rev=' + own + '#' + own + '"\n')
            barrier = threading.Barrier(2, timeout=10)
            def network(argv):
                if 'fetch' in argv and argv[argv.index('1') + 1].startswith('https://'):
                    barrier.wait()
            heads[(q.work / 'sdk').resolve()] = sdk_rev
            with patch('native_sources.FETCH_WORKERS', 2):
                fetches = self.run_prepare(q, host, heads, run=network)
            self.assertEqual(sum(argv[argv.index('1') + 1].startswith('https://') for argv in fetches), 2)


H2, DUNCE = 'd6146a5c425e55653cdfebc5660e52d87430c588', 'bb4757b8dffd9bdc619ce1fda1a147bd53e7b29d'


def fork_lock():
    """Core's shape: one fork resolved as a package, one only as an unused patch."""
    return ('[[package]]\nname="h2"\nversion="0.4.0"\nsource="git+https://github.com/MattJackson/h2?rev='
            + H2 + '#' + H2 + '"\n[[patch.unused]]\nname="dunce"\nversion="1.0.5"\n'
            'source="git+https://github.com/MattJackson/dunce.git?rev=' + DUNCE + '#' + DUNCE + '"\n')


class PublicReplica(unittest.TestCase):
    """Every build source comes from the private forge; github.com is never fetched."""
    plugin_fixture, run_prepare = Sources.plugin_fixture, Sources.run_prepare

    def test_reviewed_forks_in_packages_and_unused_patches_come_from_the_forge(self):
        from native_sources import lock_inputs
        self.assertEqual(lock_inputs(fork_lock(), {'repositories': {}}), {
            'GetBusbar/upstream-forks/h2': {H2}, 'GetBusbar/upstream-forks/dunce': {DUNCE}})
        for wrong in ('rev=' + H2 + '#' + 'a' * 40, 'rev=master#' + H2):
            with self.assertRaisesRegex(ValueError, 'immutable'):
                lock_inputs(fork_lock().replace('rev=' + H2 + '#' + H2, wrong), {'repositories': {}})

    def test_unreviewed_public_git_source_refuses_and_names_the_source(self):
        from native_sources import lock_inputs
        for source in ('git+https://github.com/someone/h2?rev=' + H2 + '#' + H2,
                       'git+https://github.com/MattJackson/h2-other?rev=' + H2 + '#' + H2,
                       'git+https://GitHub.com/MattJackson/h2?rev=' + H2 + '#' + H2,
                       'git+ssh://git@github.com/MattJackson/h2?rev=' + H2 + '#' + H2):
            for table in ('[[package]]', '[[patch.unused]]'):
                with self.subTest(source=source, table=table), \
                     self.assertRaisesRegex(ValueError, 'public replica.*' + re.escape(source)):
                    lock_inputs(table + '\nname="x"\nversion="1.0.0"\nsource="' + source + '"\n',
                                {'repositories': {}})

    def test_dot_segment_and_unclassified_first_party_sources_refuse(self):
        from native_sources import cache_name, forge_repository, lock_inputs
        policy = {'repositories': {'GetBusbar/busbar-store-memory': {'private': False},
                                   'GetBusbar/busbar-store-mssql': {'private': True}}}
        def lock(path):
            return ('[[patch.unused]]\nname="x"\nversion="1.0.0"\nsource="git+https://github.com/'
                    + path + '?rev=' + H2 + '#' + H2 + '"\n')
        for path in ('GetBusbar/..', 'GetBusbar/.', 'GetBusbar/.hidden', 'GetBusbar/...git'):
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, 'immutable'):
                lock_inputs(lock(path), policy)
        with self.assertRaisesRegex(ValueError, 'unclassified first-party.*GetBusbar/busbar-unknown'):
            lock_inputs(lock('GetBusbar/busbar-unknown'), policy)
        # A classified private repository stays out of the public map (and the seed refuses it).
        self.assertEqual(lock_inputs(lock('GetBusbar/busbar-store-mssql'), policy), {})
        for name in ('..', '.', '.hidden'):
            with self.subTest(name=name):
                self.assertIsNone(forge_repository('https://github.com/GetBusbar/' + name))
                with self.assertRaisesRegex(ValueError, 'not a canonical input'):
                    cache_name('GetBusbar/' + name)

    def prepare_forks(self, root):
        q, host, sdk, heads, revisions = self.plugin_fixture(root)
        (q.root / 'Cargo.lock').write_text((q.root / 'Cargo.lock').read_text() + fork_lock())
        fetches = self.run_prepare(q, host, heads)
        settings = [(q.env['GIT_CONFIG_KEY_' + str(i)], q.env['GIT_CONFIG_VALUE_' + str(i)])
                    for i in range(int(q.env['GIT_CONFIG_COUNT']))]
        return q, fetches, settings, revisions

    def test_forks_are_fetched_from_the_forge_path_into_noncolliding_caches_and_mapped(self):
        with tempfile.TemporaryDirectory() as directory:
            q, fetches, settings, (sdk_rev, _, own, _, _) = self.prepare_forks(Path(directory))
            parent = q.work / 'canonical-inputs'
            by_remote = {argv[argv.index('1') + 1]: argv for argv in fetches}
            for name, revision in (('h2', H2), ('dunce', DUNCE)):
                argv = by_remote['https://github.com/GetBusbar/upstream-forks/' + name + '.git']
                self.assertEqual(argv[2], str(parent / ('upstream-forks--' + name)))
                self.assertEqual(argv[-1], revision + ':refs/heads/input-' + revision)
                for suffix in ('', '.git'):
                    self.assertIn(('url.' + (parent / ('upstream-forks--' + name)).as_uri() + '.insteadOf',
                                   'https://github.com/MattJackson/' + name + suffix), settings)
            self.assertFalse(any('github.com' in remote for remote in by_remote))
            self.assertEqual(settings[-1], ('url.https://public-replica-refused.invalid/.insteadOf',
                                            'https://github.com/'))
            # First-party evidence is unchanged; fetched forks are recorded beside it.
            self.assertEqual(q.receipt['canonical_inputs'], {
                'GetBusbar/busbar': [sdk_rev], 'GetBusbar/busbar-store-memory': [own]})
            self.assertEqual(q.receipt['upstream_forks'], {
                'GetBusbar/upstream-forks/dunce': [DUNCE], 'GetBusbar/upstream-forks/h2': [H2]})

    def test_real_git_resolves_mapped_sources_locally_and_refuses_every_other_public_url(self):
        import os
        import subprocess
        with tempfile.TemporaryDirectory() as directory:
            q, _, settings, _ = self.prepare_forks(Path(directory))
            parent = q.work / 'canonical-inputs'
            seed = Path(directory) / 'seed'
            git = ['git', '-c', 'user.name=t', '-c', 'user.email=t@t', '-c', 'init.defaultBranch=main']
            plain = {'PATH': os.environ['PATH'], 'HOME': directory, 'GIT_TERMINAL_PROMPT': '0',
                     'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_CONFIG_NOSYSTEM': '1'}
            subprocess.run([*git, 'init', '--quiet', str(seed)], env=plain, check=True)
            subprocess.run([*git, '-C', str(seed), 'commit', '--quiet', '--allow-empty', '-m', 'x'],
                           env=plain, check=True)
            for cache in ('upstream-forks--h2', 'upstream-forks--dunce', 'busbar-store-memory'):
                subprocess.run([*git, 'clone', '--quiet', '--bare', str(seed), str(parent / cache)],
                               env=plain, check=True)
            env = {**plain, **q.env}
            def ls(url, *flags):
                return subprocess.run(['git', 'ls-remote', *flags, url], env=env, capture_output=True,
                                      text=True, timeout=60)
            for url, cache in (('https://github.com/MattJackson/h2', 'upstream-forks--h2'),
                               ('https://github.com/MattJackson/dunce.git', 'upstream-forks--dunce'),
                               ('https://github.com/GetBusbar/busbar-store-memory', 'busbar-store-memory')):
                with self.subTest(url=url):
                    self.assertEqual(ls(url, '--get-url').stdout.strip(), (parent / cache).as_uri())
                    listed = ls(url)
                    self.assertEqual(listed.returncode, 0, listed.stderr)
                    self.assertIn('refs/heads/main', listed.stdout)
            for url in ('https://github.com/someone/crate', 'https://github.com/MattJackson/other'):
                with self.subTest(url=url):
                    self.assertEqual(ls(url, '--get-url').stdout.strip(),
                                     'https://public-replica-refused.invalid/' + url.removeprefix('https://github.com/'))
                    self.assertNotEqual(ls(url).returncode, 0)
            # insteadOf is a plain prefix: a name extending a mapped one lands on an
            # absent local path, still never the public replica.
            url = 'https://github.com/MattJackson/h2-other'
            self.assertEqual(ls(url, '--get-url').stdout.strip(), (parent / 'upstream-forks--h2-other').as_uri())
            self.assertNotEqual(ls(url).returncode, 0)


if __name__ == '__main__':
    unittest.main()
