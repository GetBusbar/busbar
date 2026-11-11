"""Protected provisioning decisions for known offline conformance adapters.

An available row authorizes an attempt with verified inputs. It is never a suite
verdict. Native execution still enforces no network, read-only instruments,
private writable storage, and independently collected command exit statuses.
"""
import hashlib
import json

CORE = {
    'tls': {'testssl'}, 'sbom': {'sbom'}, 'oidf-oauth2': {'oidf', 'oidc-source'},
    'fapi2': {'oidf', 'oidc-source'}, 'h2': {'h2'}, 'evidence-audit-trail': set(),
    'evidence-rbac': {'zap', 'oidc-source'}, 'evidence-tls': {'tlsfuzzer'},
}
OWNERS = {
    'GetBusbar/busbar': CORE,
    'GetBusbar/busbar-plane-decisions': {'jev': set()},
    'GetBusbar/busbar-plane-streaming': {name: set() for name in ('voice-openai-realtime', 'voice-gemini-live', 'voice-twilio')},
    'GetBusbar/busbar-plane-llm': {name: {'llm-specs'} for name in ('llm-anthropic', 'llm-openai', 'llm-responses', 'llm-gemini', 'llm-bedrock', 'llm-cohere', 'voice-transcribe', 'voice-tts')},
    'GetBusbar/busbar-plane-mcp': {'mcp': {'mcp-tools'}},
    'GetBusbar/busbar-plane-a2a': {'a2a': {'a2a-tools'}},
    'GetBusbar/busbar-export-otlp': {'otlp': {'otlp'}, 'otel-semconv-weaver': {'weaver'}},
    'GetBusbar/busbar-transport-ws': {'ws': {'ws'}},
    'GetBusbar/busbar-transport-webrtc': {'webrtc-browser': {'webrtc'}},
}


def manifest(repository, source, bundles, ready):
    rows = {}
    for name, required in OWNERS.get(repository, {}).items():
        missing = sorted(required - set(bundles))
        rows[name] = ({'available': True} if ready and not missing else
                      {'available': False, 'reason': 'missing verified offline inputs: ' + ', '.join(missing)
                       if missing else 'pinned offline runtime and dependency seed are not ready'})
    if repository == 'GetBusbar/busbar':
        rows['slsa-verifier'] = ({'available': True} if ready and 'release-engineering' in bundles else
            {'available': False, 'reason': 'verified offline release-engineering controls are not staged'})
    return {'schema': 'busbar.conformance.capabilities/1', 'repo': repository, 'source': source,
            'toolchain_ready': ready, 'suites': rows}


def prepare(q):
    if q.repository not in OWNERS:
        return
    execution = q.execution
    if not execution.dependency_seed_sha256:
        raise ValueError('conformance provisioning requires the verified per-job dependency seed')
    # Real fixed-source runtime check inside this exact candidate boundary. No
    # capabilities row becomes available just because an archive was downloaded.
    command = """import subprocess,sys,yaml
assert sys.version_info[:2] == (3,11)
assert yaml.__version__ == '6.0.3'
assert subprocess.check_output(['cargo','--version'],text=True).startswith('cargo 1.98.0 ')
assert subprocess.check_output(['node','--version'],text=True).strip() == 'v22.23.3'
print('pinned offline conformance runtime available')
"""
    q.run('conformance-runtime-preflight', [execution.config['python'], '-I', '-B', '-c', command], timeout=120)
    bundles = q.receipt.get('conformance_inputs', {}).get('bundles', {})
    record = manifest(q.repository, q.receipt['source'], bundles, True)
    path = q.control / 'conformance-provisioning.json'
    path.write_text(json.dumps(record, sort_keys=True) + '\n')
    path.chmod(0o444)
    expected = hashlib.sha256(path.read_bytes()).hexdigest()
    q.receipt['conformance_capabilities_sha256'] = execution.set_conformance_capabilities(
        path, q.repository, q.receipt['source'], expected)
    q.receipt['conformance_provisioning'] = {
        'dependency_seed_sha256': execution.dependency_seed_sha256,
        'inputs_sha256': q.receipt.get('conformance_inputs', {}).get('plan_sha256'),
        'available_is_verdict': False,
        'suites': record['suites']}
