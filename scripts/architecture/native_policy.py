"""Required native capabilities selected only by the immutable controller policy."""
import json
from pathlib import Path

from check import Violation, read


def native_settings(repository, policy=None):
    if policy is None:
        policy = read(Path(__file__).resolve().parents[2] / 'ci/architecture.toml')
    data = policy.data if hasattr(policy, 'data') else policy
    assembly = data.get('assembly', {})
    entry = assembly if repository == assembly.get('repository') else data['repositories'].get(repository, {})
    settings = entry.get('native', {})
    allowed = {'services', 'migration_fixture', 'server_binary', 'native_oracle', 'prepare_runtime', 'required_conformance'}
    if not isinstance(settings, dict) or set(settings) - allowed:
        raise Violation('unknown native capability policy fields')
    services = settings.get('services', [])
    known = {'postgres', 'mysql', 'valkey', 'vault', 'wiremock', 'openldap'}
    if (not isinstance(services, list) or len(services) > len(known)
            or any(not isinstance(value, str) or value not in known for value in services)
            or len(set(services)) != len(services)):
        raise Violation('unknown or duplicate native fixture service')
    if settings.get('migration_fixture', 'sqlite-1.5.5') != 'sqlite-1.5.5':
        raise Violation('unknown native migration fixture')
    if 'server_binary' in settings and (settings['server_binary'] != 'valkey' or 'valkey' not in services):
        raise Violation('native server witness requires its declared service')
    if type(settings.get('native_oracle', False)) is not bool:
        raise Violation('native oracle requirement must be boolean')
    if type(settings.get('required_conformance', False)) is not bool:
        raise Violation('native conformance requirement must be boolean')
    if 'prepare_runtime' in settings:
        from product_artifacts import relative_path
        path = relative_path(settings['prepare_runtime'])
        if not path.startswith('testing/native/') or not path.endswith('.sh'):
            raise Violation('runtime preparation must name an owner native script')
    return dict(settings)


def conformance_rows(repository, policy=None, trusted=None):
    """Reuse the approved coverage inventory; candidate rosters cannot waive it."""
    if not native_settings(repository, policy).get('required_conformance'):
        return {}
    trusted = Path(trusted) if trusted is not None else Path(__file__).resolve().parents[2]
    coverage = json.loads((trusted / 'conformance/ci-coverage.json').read_text())
    if coverage.get('schema') != 'busbar.conformance.ci-coverage/1':
        raise Violation('required conformance coverage schema differs')
    rows = {name: row for name, row in coverage['suites'].items() if row.get('repo') == repository}
    if not rows or any(not isinstance(row.get('command'), str) or not row['command'] for row in rows.values()):
        raise Violation('required owner has no complete protected conformance inventory')
    return rows


def validate_conformance_roster(root, rows):
    if not rows:
        return
    from product_artifacts import regular_under
    roster = regular_under(Path(root) / 'testing/conformance/suites.tsv', Path(root))
    actual = {}
    for line in roster.read_text().splitlines():
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        fields = line.split('\t', 1)
        if len(fields) != 2 or fields[0] in actual:
            raise Violation('invalid or duplicate required conformance roster entry')
        actual[fields[0]] = fields[1]
    if any(actual.get(name) != row['command'] for name, row in rows.items()):
        raise Violation('required conformance suite is missing or its command differs from protected coverage')
