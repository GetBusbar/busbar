"""Bind an approved offline Python environment to its exact base image ABI."""

import hashlib
import json
import re

from native_staged_fixtures import regular, require


TARGET = '/opt/busbar-conformance/python-runtime'


def bind(q):
    bundle = q.receipt['conformance_inputs']['bundles'].get('python-runtime')
    if bundle is None:
        return
    root = q.control / 'conformance-tools-python-runtime'
    identity = json.loads(regular(root / 'identity.json', 65536))
    require(set(identity) == {'schema', 'platform', 'python_version', 'base_python',
            'image_manifest_sha256', 'image_config_sha256', 'executable_sha256'}
            and identity['schema'] == 'busbar.native-python-runtime/1'
            and identity['platform'] == 'linux/amd64'
            and re.fullmatch(r'3\.[0-9]+\.[0-9]+', identity['python_version'])
            and identity['base_python'] == '/usr/bin/python3'
            and all(re.fullmatch('[0-9a-f]{64}', identity[key]) for key in
                    ('image_manifest_sha256', 'image_config_sha256', 'executable_sha256')),
            'invalid declared Python runtime ABI')
    require(bundle['files'].get('bin/python3', {}).get('executable') is True
            and hashlib.sha256(regular(root / 'bin/python3', 32 * 1024**2)).hexdigest()
                == identity['executable_sha256'], 'Python runtime executable identity differs')
    expected = ('home = /usr/bin\ninclude-system-site-packages = false\nversion = '
                + identity['python_version'] + '\n')
    require(regular(root / 'pyvenv.cfg', 4096).decode() == expected,
            'Python runtime must be a closed standard virtual environment')
    # Packing validates the artifact but has no selected execution image yet.
    if not hasattr(q.execution, 'config'):
        return
    config = q.execution.config
    require(config['image'].split('sha256:')[-1] in
                (identity['image_manifest_sha256'], identity['image_config_sha256'])
            and config['python'] == identity['base_python'],
            'Python runtime does not match the selected image ABI')
    prefix = TARGET + '/bin'
    original = config['environment']['PATH']
    require(prefix not in original.split(':'), 'Python runtime was already registered')
    config['environment']['PATH'] = prefix + ':' + original
    q.receipt['conformance_inputs']['python_runtime'] = {
        'identity': identity, 'path': TARGET, 'executable': prefix + '/python3',
        'configuration_sha256': hashlib.sha256(json.dumps(config, sort_keys=True,
            separators=(',', ':')).encode() + b'\n').hexdigest()}
