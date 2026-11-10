"""Required native capabilities selected only by the immutable controller policy."""
from pathlib import Path

from check import Violation, read


def native_settings(repository, policy=None):
    if policy is None:
        policy = read(Path(__file__).resolve().parents[2] / 'ci/architecture.toml')
    data = policy.data if hasattr(policy, 'data') else policy
    assembly = data.get('assembly', {})
    entry = assembly if repository == assembly.get('repository') else data['repositories'].get(repository, {})
    settings = entry.get('native', {})
    allowed = {'services', 'migration_fixture', 'server_binary', 'external_conformance', 'native_oracle'}
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
    if 'external_conformance' in settings:
        from product_artifacts import relative_path
        path = relative_path(settings['external_conformance'])
        if not path.startswith('testing/conformance/') or not path.endswith('.sh'):
            raise Violation('external evaluation must name an owner conformance script')
    return dict(settings)
