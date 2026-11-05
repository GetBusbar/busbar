#!/usr/bin/env python3
"""Explicit ephemeral fixture startup through the product's cold CLI.
Never infers freshness from an empty scan: caller must create a dedicated fixture
instance, provide its creation record, and attest exclusive/quiesced ownership.
"""
import argparse, hashlib, json, os, pathlib, subprocess, sys

def sha(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()

def prepare(binary, config, providers, evidence, creation_record):
    evidence = pathlib.Path(evidence)
    evidence.mkdir(parents=True, exist_ok=False)
    record = json.loads(pathlib.Path(creation_record).read_text())
    for key in ('newly_created_namespace', 'sender_quiesced', 'backend_quiesced', 'ephemeral_instance', 'exclusive_instance'):
        if record.get(key) is not True:
            raise ValueError('Explicit fixture creation attestation missing: ' + key)
    for key in ('actor', 'reason'):
        if not isinstance(record.get(key), str) or not record[key].strip():
            raise ValueError('Explicit fixture creation attestation missing: ' + key)
    base = [str(pathlib.Path(binary).resolve()), '--config', str(pathlib.Path(config).resolve()), '--providers', str(pathlib.Path(providers).resolve())]
    inspect = base + ['--principal-transition', '-', '--transition-action', 'inspect']
    result = subprocess.run(inspect, capture_output=True, timeout=60)
    (evidence/'inspect.stdout').write_bytes(result.stdout)
    (evidence/'inspect.stderr').write_bytes(result.stderr)
    (evidence/'inspect.command.json').write_text(json.dumps({'argv': inspect, 'returncode': result.returncode}, indent=2)+'\n')
    result.check_returncode()
    state = json.loads(result.stdout)
    if state.get('store_ephemeral') is not True:
        raise ValueError('Same-open fresh startup requires actual admitted ephemeral Store')
    if state.get('principal_receipt_head_sha256') is not None:
        raise ValueError('Inspect found an existing baseline or pending transition')
    receipt = {'version': 1, 'store_config_sha256': state['store_config_sha256'], 'requirements': state['requirements'], 'witness': None, 'creation_evidence_sha256': sha(creation_record)}
    receipt.update({key: record[key] for key in ('newly_created_namespace','sender_quiesced','backend_quiesced','ephemeral_instance','exclusive_instance','actor','reason')})
    receipt_path = evidence/'fresh.json'
    receipt_path.write_text(json.dumps(receipt, indent=2)+'\n')
    argv = base + ['--principal-transition', str(receipt_path.resolve()), '--transition-action', 'initialize-fresh-and-serve']
    (evidence/'bindings.json').write_text(json.dumps({'binary_sha256': sha(binary), 'config_sha256': sha(config), 'providers_sha256': sha(providers), 'creation_evidence_sha256': sha(creation_record), 'receipt_sha256': sha(receipt_path), 'argv': argv, 'scope': 'Inspect uses an independent ephemeral instance; initialize-and-serve creates and serves on one fresh same-open instance. No cross-process Memory continuity claimed.'}, indent=2)+'\n')
    return argv

if __name__ == '__main__':
    p=argparse.ArgumentParser()
    for key in ('binary','config','providers','evidence','creation-record'):
        p.add_argument('--'+key, required=True)
    p.add_argument('--prepare-only', action='store_true')
    a=p.parse_args()
    argv=prepare(a.binary,a.config,a.providers,a.evidence,a.creation_record)
    if a.prepare_only:
        print(json.dumps(argv))
    else:
        os.execv(argv[0], argv)
