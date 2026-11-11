"""Pinned service peers with no host or external network route.

Peer root is a remapped identity. Image root is read-only; writable image
folders are copied into the existing bounded job filesystem. The controller
alone owns Docker and fixed administrative commands. Candidates only receive
opaque streams to a pinned network namespace and fixed loopback port.
"""
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path, PurePosixPath
import re
import socket
import shutil
import tarfile
import stat
import subprocess
import time
import threading
from types import SimpleNamespace
import uuid

import linux_job_isolation

PORTS = {'postgres': 5432, 'mysql': 3306, 'valkey': 6379,
         'vault': 8200, 'wiremock': 8080, 'openldap': 389}
# These are image bootstrap/data paths, not host paths. Image-declared volumes
# must appear here too; an undeclared writable volume is refused on inspection.
WRITABLE = {
    'postgres': ('/var/lib/postgresql/data', '/var/run/postgresql'),
    'mysql': ('/var/lib/mysql', '/var/run/mysqld'),
    'valkey': ('/data',),
    'vault': ('/vault/file', '/vault/logs', '/home/vault'),
    'wiremock': ('/home/wiremock',),
    'openldap': ('/root', '/etc', '/usr/sbin', '/var/lib/ldap', '/container', '/var/run', '/var/cache', '/var/log', '/var/backups', '/var/lib/dpkg'),
}
ENV = {
    'postgres': {'POSTGRES_USER': 'busbar', 'POSTGRES_PASSWORD': 'busbar', 'POSTGRES_DB': 'busbar_store_qa'},
    'mysql': {'MYSQL_ROOT_PASSWORD': 'busbar', 'MYSQL_USER': 'busbar', 'MYSQL_PASSWORD': 'busbar', 'MYSQL_DATABASE': 'busbar_store_qa'},
    'vault': {'VAULT_DEV_ROOT_TOKEN_ID': 'busbar-fixture', 'VAULT_DEV_LISTEN_ADDRESS': '0.0.0.0:8200', 'SKIP_SETCAP': 'true', 'SKIP_CHOWN': 'true'},
    'openldap': {'LDAP_ORGANISATION': 'Example Org', 'LDAP_DOMAIN': 'example.org', 'LDAP_ADMIN_PASSWORD': 'adminpassword', 'LDAP_TLS': 'false'},
}
COMMAND = {'mysql': ['--log-bin-trust-function-creators=1'], 'vault': ['server', '-dev']}
CAPS = ['CHOWN', 'DAC_OVERRIDE', 'FOWNER', 'SETGID', 'SETUID', 'NET_BIND_SERVICE']
TMPFS = {'/tmp': 'rw,nosuid,nodev,size=64m,nr_inodes=4096,mode=1777'}



class Peers:
    def __init__(self, services):
        self.owner = services
        self.q = services.q
        self.execution = services.execution
        if not re.fullmatch(r'[0-9]{1,20}', self.q.receipt['job_id']):
            raise ValueError('invalid protected fixture job identity')
        self.peers = {}
        self.names = []
        self.namespaces = []
        self.root = self.q.control / 'service-peers'
        self.root.mkdir()
        self.daemon = json.loads(self.client(['info', '--format', '{{json .}}']).stdout)
        linux_job_isolation.validate_userns(self.execution.config['isolation'], self.daemon)

    def client(self, args, **kwargs):
        kwargs.setdefault('capture_output', True)
        kwargs.setdefault('text', True)
        kwargs.setdefault('check', True)
        return self.execution._client(args, **kwargs)

    def image(self, reference):
        # No candidate daemon network. Only the controller's public image cache
        # stages the immutable service digest, with one bounded mirror attempt.
        result = self.client(['image', 'inspect', reference], check=False)
        if result.returncode == 0:
            return json.loads(result.stdout)[0]
        export_reference = reference
        found = self.execution.collector_client(['image', 'inspect', reference],
                                                capture_output=True, text=True)
        if found.returncode:
            # Same pinned public cache route as trusted scanner provisioning.
            # One bounded mirror attempt, never an anonymous Hub fallback loop.
            repository, pin = reference.rsplit('@', 1)
            if ':' in repository.rsplit('/', 1)[-1]:
                repository = repository.rsplit(':', 1)[0]
            if '/' not in repository:
                repository = 'library/' + repository
            export_reference = 'mirror.gcr.io/' + repository + '@' + pin
            self.execution.collector_client(['pull', export_reference], capture_output=True,
                                            text=True, check=True, timeout=300)
            found = self.execution.collector_client(['image', 'inspect', export_reference],
                                                    capture_output=True, text=True, check=True)
        value = json.loads(found.stdout)[0]
        if not any(value.endswith('@' + reference.rsplit('@', 1)[1]) for value in value.get('RepoDigests', [])):
            raise ValueError('fixture image digest is not present in trusted cache')
        command = [self.execution.config['docker'], '--host', self.execution.config['collector']['docker_host']]
        producer = subprocess.Popen([*command, 'save', export_reference], env=self.execution.client_env,
                                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        try:
            loaded = self.client(['load'], stdin=producer.stdout, timeout=300)
            producer.stdout.close()
            if producer.wait(timeout=300):
                raise RuntimeError('cached fixture image export failed')
        finally:
            if producer.poll() is None:
                producer.kill()
                producer.wait()
        identities = re.findall(r'^Loaded image(?: ID)?: (.+)$', loaded.stdout, re.MULTILINE)
        if len(identities) != 1:
            raise ValueError('fixture export did not produce exactly one image')
        imported = json.loads(self.client(['image', 'inspect', identities[0]]).stdout)[0]
        # Docker's containerd store identifies images by manifest while the
        # remapped legacy graph driver uses config IDs. Verify execution bytes,
        # including every uncompressed layer digest, across that representation.
        if any(imported.get(key) != value.get(key) for key in ('RootFS', 'Config', 'Os', 'Architecture')):
            raise ValueError('imported fixture image execution content differs')
        return imported

    def mapped_copy(self, source, destination, name):
        destination.mkdir()
        command = [self.execution.config['docker'], '--host', self.execution.config['docker_host'],
                   'cp', name + ':' + source + '/.', '-']
        uid_start = self.execution.config['isolation']['uid_map'][1]
        gid_start = self.execution.config['isolation']['gid_map'][1]
        uid_count = self.execution.config['isolation']['uid_map'][2]
        gid_count = self.execution.config['isolation']['gid_map'][2]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   env=self.execution.client_env)
        count, total = 0, 0
        deadline = threading.Timer(120, process.kill)
        deadline.start()
        try:
            with tarfile.open(fileobj=process.stdout, mode='r|*') as archive:
                for member in archive:
                    count += 1
                    relative = PurePosixPath(member.name)
                    if relative.is_absolute() or '..' in relative.parts or count > 100000:
                        raise ValueError('invalid fixture image directory entry')
                    path = destination.joinpath(*relative.parts)
                    if any(parent.is_symlink() for parent in path.parents if parent.is_relative_to(destination)):
                        raise ValueError('indirect fixture image directory entry')
                    uid, gid = member.uid, member.gid
                    # Remapped Docker archive exports can already carry host
                    # subordinate IDs. Avoid applying the namespace offset twice.
                    if uid_start <= uid < uid_start + uid_count:
                        uid -= uid_start
                    if gid_start <= gid < gid_start + gid_count:
                        gid -= gid_start
                    if not (0 <= uid < uid_count and 0 <= gid < gid_count):
                        raise ValueError('fixture image identity is outside subordinate range')
                    path.parent.mkdir(parents=True, exist_ok=True)
                    if member.isdir():
                        path.mkdir(exist_ok=True)
                    elif member.isfile():
                        if not 0 <= member.size <= 256 * 1024**2:
                            raise ValueError('fixture image file exceeds bound')
                        total += member.size
                        if total > 2 * 1024**3:
                            raise ValueError('fixture image directory exceeds bound')
                        with path.open('xb') as output:
                            shutil.copyfileobj(archive.extractfile(member), output, length=65536)
                    elif member.issym():
                        # Preserve image-internal symlinks without ever following
                        # them on the host (e.g. /etc/os-release -> ../usr/lib/...).
                        path.symlink_to(member.linkname)
                    elif member.islnk():
                        target = PurePosixPath(member.linkname)
                        if target.is_absolute() or '..' in target.parts:
                            raise ValueError('indirect fixture image hard link')
                        original = destination.joinpath(*target.parts)
                        if (not original.is_file() or original.is_symlink()
                                or any(p.is_symlink() for p in original.parents if p.is_relative_to(destination))):
                            raise ValueError('missing fixture image hard link target')
                        total += original.stat().st_size
                        if total > 2 * 1024**3:
                            raise ValueError('fixture image directory exceeds bound')
                        with original.open('rb') as input_file, path.open('xb') as output:
                            shutil.copyfileobj(input_file, output, length=65536)
                    else:
                        raise ValueError('special file in fixture image directory')
                    if not member.issym():
                        path.chmod(member.mode & 0o1777)
                    os.chown(path, uid_start + uid, gid_start + gid, follow_symlinks=False)
            process.stdout.close()
            if process.wait(timeout=60):
                raise RuntimeError('fixture image directory export failed')
        except BaseException as error:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            detail = process.stderr.read(8192).decode('utf-8', errors='replace')
            if isinstance(error, tarfile.ReadError) and 'Could not find the file' in detail:
                os.chown(destination, uid_start, gid_start)
            else:
                raise RuntimeError('fixture image export failed for ' + source + ': ' + str(error) + '; ' + detail) from error
        finally:
            deadline.cancel()
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
        return destination

    def start(self, service):
        if service not in PORTS or service in self.peers:
            raise ValueError('unknown or duplicate declared fixture')
        name = 'busbar-peer-' + self.q.receipt['job_id'] + '-' + service
        image = self.image(self.owner.images[service])
        declared = set((image['Config'].get('Volumes') or {}).keys())
        if any(not any(path == root or path.startswith(root + '/') for root in WRITABLE[service]) for path in declared):
            raise ValueError('unbounded image-declared fixture volume')
        source = name + '-source'
        self.names.append(source)
        self.client(['create', '--name', source, '--network=none', '--entrypoint=/bin/true', image['Id']])
        writable = []
        try:
            for index, path in enumerate(WRITABLE[service]):
                folder = self.mapped_copy(path, self.root / (service + '-' + str(index)), source)
                writable.append((folder, path))
        finally:
            self.client(['rm', '--force', '--volumes', source])
            self.names.remove(source)
        storage = linux_job_isolation.validate_storage(self.execution.config['isolation'],
                                                      [self.root, *(src for src, _ in writable)])
        if service == 'openldap':
            # The pinned upstream bootstrap rewrites /etc/hosts. Keep that file
            # inside the job quota instead of Docker's daemon-managed host file.
            hosts = self.root / 'openldap-hosts'
            hosts.write_text('127.0.0.1 localhost busbar-ldap.example.org\n::1 localhost\n')
            os.chown(hosts, self.execution.config['isolation']['uid_map'][1],
                     self.execution.config['isolation']['gid_map'][1])
            hosts.chmod(0o644)
            writable.append((hosts, '/etc/hosts'))
        args, capabilities = self.create_arguments(service, name, image, writable)
        self.names.append(name)
        self.client(args)
        inspected = json.loads(self.client(['inspect', name]).stdout)[0]
        swap_bound = self.verify(inspected, image, writable, capabilities)
        self.client(['start', name])
        inspected = json.loads(self.client(['inspect', name]).stdout)[0]
        if not inspected['State']['Running']:
            raise RuntimeError('fixture failed before namespace capture')
        pid = inspected['State']['Pid']
        for key in ('uid_map', 'gid_map'):
            rows = [list(map(int, row.split())) for row in Path(f'/proc/{pid}/{key}').read_text().splitlines()]
            if rows != [self.execution.config['isolation'][key]]:
                raise ValueError('fixture kernel identity map differs')
        if os.stat(f'/proc/{pid}/ns/pid').st_ino == os.stat('/proc/self/ns/pid').st_ino:
            raise ValueError('fixture shares controller PID namespace')
        namespace = os.open('/proc/' + str(pid) + '/ns/net', os.O_RDONLY | os.O_CLOEXEC)
        self.namespaces.append(namespace)
        if os.fstat(namespace).st_ino == os.stat('/proc/self/ns/net').st_ino:
            raise ValueError('fixture shares controller network namespace')
        again = json.loads(self.client(['inspect', name]).stdout)[0]
        if not again['State']['Running'] or again['State']['Pid'] != pid:
            raise RuntimeError('fixture process changed during namespace capture')
        port = 27000 + list(PORTS).index(service)
        self.owner.proxy.add(port, namespace=namespace, peer_port=PORTS[service])
        peer = {'name': name, 'port': port, 'namespace': namespace}
        self.peers[service] = peer
        self.q.receipt.setdefault('service_peers', {})[service] = {
            'image': inspected['Image'], 'requested_image': self.owner.images[service], 'network': 'none', 'namespace_inode': os.fstat(namespace).st_ino,
            'capabilities': capabilities, 'storage': storage, 'swap_bound': swap_bound, 'readonly_root': True, 'memory_bytes': 1073741824, 'pids': 256,
            'uid_map': self.execution.config['isolation']['uid_map'], 'port': PORTS[service]}
        return peer

    def create_arguments(self, service, name, image, writable):
        args = ['create', '--name', name, '--pull=never', '--network=none', '--read-only',
                '--runtime', self.execution.config.get('runtime', 'runc'),
                '--ipc=private', '--cgroupns=private', '--cap-drop=ALL', '--security-opt=no-new-privileges',
                '--memory=1073741824', '--memory-swap=1073741824', '--cpus=1', '--pids-limit=256',
                '--shm-size=64m', '--log-driver=local', '--log-opt=max-size=1m', '--log-opt=max-file=1', '--log-opt=compress=false', '--label', 'busbar.admission.job=' + self.q.receipt['job_id']]
        if service == 'openldap':
            args += ['--hostname', 'busbar-ldap.example.org', '--add-host', 'busbar-ldap.example.org:127.0.0.1']
        capabilities = CAPS + (['KILL'] if service == 'openldap' else [])
        for cap in capabilities:
            args += ['--cap-add', cap]
        for path, options in TMPFS.items():
            args += ['--tmpfs', path + ':' + options]
        for src, dst in writable:
            args += ['--mount', f'type=bind,src={src},dst={dst}']
        for key, value in ENV.get(service, {}).items():
            args += ['--env', key + '=' + value]
        args += [image['Id'], *COMMAND.get(service, [])]
        return args, capabilities

    def control_values(self, actual, image, capabilities):
        host = actual['HostConfig']
        requested = {
            'Image': image['Id'], 'NetworkMode': 'none', 'Privileged': False,
            'ReadonlyRootfs': True, 'PidMode': '', 'IpcMode': 'private',
            'CgroupnsMode': 'private', 'Runtime': self.execution.config.get('runtime', 'runc'),
            'CapDrop': ['ALL'], 'CapAdd': sorted(capabilities),
            'NoNewPrivileges': True, 'Memory': 1073741824, 'MemorySwap': 1073741824,
            'NanoCpus': 1000000000, 'PidsLimit': 256, 'ShmSize': 64 * 1024**2,
            'Tmpfs': TMPFS,
            'ExtraHosts': ['busbar-ldap.example.org:127.0.0.1'] if 'KILL' in capabilities else [],
            'PortBindings': {}, 'Devices': [],
            'LogConfig': {'Type': 'local', 'Config': {'max-size': '1m', 'max-file': '1', 'compress': 'false'}},
        }
        observed = {key: host.get(key) for key in requested}
        observed.update(Image=actual['Image'],
            CapDrop=sorted(set(host['CapDrop'] or [])),
            CapAdd=sorted({cap.removeprefix('CAP_') for cap in host['CapAdd'] or []}),
            NoNewPrivileges='no-new-privileges' in (host['SecurityOpt'] or []),
            ExtraHosts=host.get('ExtraHosts') or [], PortBindings=host.get('PortBindings') or {},
            Devices=host.get('Devices') or [])
        return requested, observed

    def verify(self, actual, image, writable, capabilities=CAPS):
        linux_job_isolation.validate_userns(self.execution.config['isolation'], self.daemon, actual)
        requested, observed = self.control_values(actual, image, capabilities)
        mismatches = {key: {'requested': requested[key], 'observed': observed[key]}
                      for key in requested if observed[key] != requested[key]}
        swap_bound = linux_job_isolation.validate_swap_bound(self.daemon, actual['HostConfig'], 1073741824)
        mismatches.pop('MemorySwap', None)
        if mismatches:
            # Never serialize Config.Env or the full inspection: fixture runtime
            # failures need only bounded control fields, with no image secrets.
            detail = json.dumps(mismatches, sort_keys=True, separators=(',', ':'))
            raise ValueError('fixture runtime controls differ from protected request: ' + detail[:4096])
        mounts = {(m['Source'], m['Destination'], m['RW']) for m in actual['Mounts'] if m['Type'] != 'tmpfs'}
        if mounts != {(str(src), dst, True) for src, dst in writable}:
            raise ValueError('fixture writable mounts differ from bounded storage')
        return swap_bound

    def exec(self, service, args, **kwargs):
        return self.client(['exec', self.peers[service]['name'], *args], **kwargs)

    def wait(self, service, command, timeout=120):
        deadline = time.monotonic() + timeout
        while self.exec(service, command, check=False).returncode:
            if time.monotonic() >= deadline:
                raise RuntimeError(service + ' fixture failed bounded readiness')
            state = json.loads(self.client(['inspect', self.peers[service]['name']]).stdout)[0]['State']
            if not state['Running']:
                raise RuntimeError(service + ' fixture exited during readiness')
            time.sleep(.5)

    def http_ready(self, service, path):
        deadline = time.monotonic() + 90
        while True:
            connection = http.client.HTTPConnection('127.0.0.1', timeout=3)
            stream = socket.socket(socket.AF_UNIX)
            stream.settimeout(3)
            try:
                stream.connect(str(self.execution.fixture_directory / (str(self.peers[service]['port']) + '.sock')))
                connection.sock = stream
                connection.request('GET', path)
                response = connection.getresponse()
                if response.status == 200:
                    return
            except (OSError, http.client.HTTPException):
                pass
            finally:
                connection.close()
                stream.close()
            if time.monotonic() >= deadline:
                raise RuntimeError(service + ' fixture HTTP readiness failed')
            state = json.loads(self.client(['inspect', self.peers[service]['name']]).stdout)[0]['State']
            if not state['Running']:
                raise RuntimeError(service + ' fixture exited during readiness')
            time.sleep(.5)

    def provision(self, requested):
        for service in requested:
            peer = self.start(service)
            port = peer['port']
            if service == 'postgres':
                self.wait(service, ['pg_isready', '-U', 'busbar'])
                token = 'busbar_oracle_' + self.owner.tag.replace('-', '_') + '_v4'
                self.exec(service, ['psql', '-U', 'busbar', '-d', 'busbar_store_qa',
                                    '-v', 'ON_ERROR_STOP=1', '-c', 'CREATE DATABASE ' + token])
                url = f'postgres://busbar:busbar@127.0.0.1:{port}/busbar_store_qa'
                self.q.env.update(BUSBAR_TEST_POSTGRES_URL=url, BUSBAR_TEST_POSTGRES_IMPORT_URL=url,
                                  BUSBAR_TEST_POSTGRES_V4_URL=url.replace('busbar_store_qa', token))
            elif service == 'mysql':
                self.wait(service, ['mysqladmin', 'ping', '--protocol=TCP', '-h', '127.0.0.1', '-ubusbar', '-pbusbar'])
                token = 'busbar_oracle_' + self.owner.tag.replace('-', '_') + '_v4'
                self.exec(service, ['mysql', '-uroot', '-pbusbar', '-e',
                    f"CREATE DATABASE {token}; GRANT ALL ON {token}.* TO 'busbar'@'%'"])
                pem = self.exec(service, ['mysql', '-uroot', '-pbusbar', '-N', '-B', '--raw',
                    '-e', "SHOW STATUS LIKE 'Caching_sha2_password_rsa_public_key'"]).stdout.split('\t', 1)[1]
                match = re.search(r'-----BEGIN (?:RSA )?PUBLIC KEY-----([A-Za-z0-9+/=\s]+)-----END (?:RSA )?PUBLIC KEY-----', pem)
                if match is None:
                    raise RuntimeError('pinned MySQL fixture did not expose its active RSA public key')
                pin = hashlib.sha256(base64.b64decode(''.join(match[1].split()), validate=True)).hexdigest()
                url = f'mysql://busbar:busbar@127.0.0.1:{port}/busbar_store_qa?server_public_key_sha256={pin}'
                self.q.env.update(BUSBAR_TEST_MYSQL_URL=url, BUSBAR_TEST_MYSQL_ROOT_PASSWORD='busbar',
                                  BUSBAR_TEST_MYSQL_V4_URL=url.replace('/busbar_store_qa?', '/' + token + '?'))
            elif service == 'valkey':
                self.wait(service, ['valkey-cli', 'ping'])
                url = f'redis://127.0.0.1:{port}/0'
                self.q.env.update(BUSBAR_TEST_VALKEY_URL=url, BUSBAR_TEST_VALKEY_V4_URL=url,
                                  VALKEY_URL=url, BUSBAR_V4_TRANSPORT_URL=url)
                if self.owner.required.get('server_binary') == service:
                    fixture = self.q.work / 'valkey-native'
                    fixture.mkdir()
                    binary = fixture / 'valkey-server'
                    self.client(['cp', peer['name'] + ':/usr/local/bin/valkey-server', str(binary)])
                    self.q.run('fixture-valkey-server-check', [str(binary), '--version'], timeout=30)
                    self.q.env.update(BUSBAR_V4_TEST_TMP=str(fixture), BUSBAR_VALKEY_SERVER=str(binary))
            elif service == 'wiremock':
                self.http_ready(service, '/__admin/mappings')
                self.q.env['BUSBAR_TEST_WIREMOCK_URL'] = f'http://127.0.0.1:{port}'
            elif service == 'vault':
                self.http_ready(service, '/v1/sys/health')
                self.q.env.update(BUSBAR_TEST_VAULT_ADDR=f'http://127.0.0.1:{port}', BUSBAR_TEST_VAULT_TOKEN='busbar-fixture')
            elif service == 'openldap':
                from native_fixtures import ldap_readiness_command
                self.wait(service, ldap_readiness_command(peer['name'])[3:])
                self.client(['exec', '-i', peer['name'], 'ldapadd', '-x', '-H', 'ldap://127.0.0.1',
                    '-D', 'cn=admin,dc=example,dc=org', '-w', 'adminpassword'],
                    input=(self.q.trusted / 'scripts/fixtures/auth-ldap/seed.ldif').read_bytes(), text=False)
                self.q.env['BUSBAR_TEST_LDAP_URL'] = f'ldap://127.0.0.1:{port}'

    def close(self):
        failed = []
        for name in reversed(self.names):
            result = self.client(['rm', '--force', '--volumes', name], check=False)
            if result.returncode and self.client(['inspect', name], check=False).returncode == 0:
                failed.append(name)
        if failed:
            raise RuntimeError('fixture peer disposal failed: ' + ', '.join(failed))
        self.names.clear()
        for fd in self.namespaces:
            os.close(fd)
        self.namespaces.clear()
        for value in self.q.receipt.get('service_peers', {}).values():
            value['disposed'] = True
        zero_swap = [value['swap_bound'] for value in self.q.receipt.get('service_peers', {}).values()
                     if value.get('swap_bound', {}).get('mechanism') == 'kernel-zero-swap-capacity']
        if zero_swap:
            final = linux_job_isolation.kernel_no_swap()
            for proof in zero_swap:
                proof['after_disposal'] = final


def runtime_controls_probe(config, evidence):
    """Inspect the exact fixture request on the selected daemon without starting peers."""
    evidence = Path(evidence)
    client_home = evidence / 'fixture-probe-client'
    client_home.mkdir(mode=0o700)
    environment = {'PATH': os.defpath, 'HOME': str(client_home), 'DOCKER_CONFIG': str(client_home)}
    def client(args):
        return subprocess.run([config['docker'], '--host', config['docker_host'], *args],
            env=environment, capture_output=True, text=True, check=True, timeout=60)
    peers = Peers.__new__(Peers)
    peers.execution = SimpleNamespace(config=config)
    peers.q = SimpleNamespace(receipt={'job_id': '0'})
    peers.daemon = json.loads(client(['info', '--format', '{{json .}}']).stdout)
    image = json.loads(client(['image', 'inspect', config['image']]).stdout)[0]
    if image['Config'].get('Volumes'):
        raise ValueError('fixture control probe image declares writable volumes')
    record = {'schema': 'busbar.native-fixture-controls-probe/1', 'started': False,
              'engine_version': peers.daemon.get('ServerVersion'), 'image': image['Id'], 'cases': []}
    errors = []
    try:
        for service in ('wiremock', 'openldap'):
            name = 'busbar-fixture-controls-' + uuid.uuid4().hex
            args, capabilities = peers.create_arguments(service, name, image, [])
            case = {'service_controls': service, 'disposed': False}
            record['cases'].append(case)
            try:
                client(args)
                actual = json.loads(client(['inspect', name]).stdout)[0]
                requested, observed = peers.control_values(actual, image, capabilities)
                case.update(requested=requested, observed=observed)
                case['swap_bound'] = peers.verify(actual, image, [], capabilities)
                case['status'] = 'pass'
            except Exception as error:
                case.update(status='refused', error=str(error)[:4096])
                errors.append(str(error)[:4096])
            finally:
                client(['rm', '--force', '--volumes', name])
                case['disposed'] = not client(['ps', '--all', '--quiet', '--filter', 'name=^/' + name + '$']).stdout.strip()
                if not case['disposed']:
                    raise RuntimeError('fixture control probe disposal failed')
                if 'swap_bound' in case:
                    linux_job_isolation.recheck_swap_bound(case['swap_bound'])
        if errors:
            raise ValueError('fixture control probe refused: ' + '; '.join(errors)[:4096])
    finally:
        (evidence / 'fixture-controls-probe.json').write_text(json.dumps(record, indent=2) + '\n')
