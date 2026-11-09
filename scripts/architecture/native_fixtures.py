"""Native CI fixture lifecycle, reusing the existing pinned service catalogue.

Containers are disposable test peers on the existing runner, never cloud resources.
Only this job's named containers and namespaces are removed.
"""
from __future__ import annotations

from pathlib import Path
import socket
import subprocess
import time
import urllib.error
import urllib.request


def ldap_readiness_command(name):
    # The pinned image answers LDAP during bootstrap, then stops that daemon.
    # osixia/docker-openldap v1.5.0 image/service/slapd/startup.sh writes this
    # marker after shutdown; only then probe the final daemon.
    return ['docker', 'exec', name, 'sh', '-ec',
            'test -f "$1"; shift; exec ldapsearch "$@"', 'ldap-ready',
            '/container/run/state/slapd-first-start-done', '-x', '-H', 'ldap://127.0.0.1',
            '-D', 'cn=admin,dc=example,dc=org', '-w', 'adminpassword', '-b', 'dc=example,dc=org']


class Services:
    def __init__(self, qualification, host, all_services=False):
        self.q, self.host = qualification, host
        self.names = []
        self.stores = []
        self.tag = 'boundary-' + qualification.receipt['job_id']
        name = qualification.repository.rsplit('/', 1)[1]
        self.requested = ['postgres', 'mysql', 'valkey', 'vault', 'wiremock', 'openldap'] if all_services else {
            'busbar-store-postgres': ['postgres'], 'busbar-store-mysql': ['mysql'],
            'busbar-store-valkey': ['valkey'], 'busbar-secret-vault': ['vault'],
            'busbar-auth-github': ['wiremock'], 'busbar-auth-ldap': ['openldap'],
        }.get(name, [])
        self.images = {}
        source = qualification.trusted / 'testing/fleet-fixtures/service-images.tsv'
        rows = []
        for line in source.read_text().splitlines():
            if not line or line.startswith('#'):
                rows.append(line)
                continue
            cells = line.split('\t')
            self.images[cells[0]] = cells[1] + '@' + cells[2]
            if cells[0] in ('postgres', 'mysql', 'valkey'):
                with socket.socket() as listener:
                    listener.bind(('127.0.0.1', 0))
                    cells[5] = str(listener.getsockname()[1])
            rows.append('\t'.join(cells))
        table = qualification.work / 'service-images.tsv'
        table.write_text('\n'.join(rows) + '\n')
        qualification.env.update(BUSBAR_STORE_QA_TAG=self.tag, SERVICE_IMAGES_TSV=str(table))
        self.store_script = qualification.trusted / 'testing/fleet-fixtures/store-services.sh'

    def store(self, verb, service, *args):
        output = self.q.run('fixture-' + service + '-' + verb,
            ['bash', str(self.store_script), verb, service, *args], timeout=300)
        return output.read_text().strip()

    def container(self, service, port, options=(), command=()):
        name = 'busbar-' + self.tag + '-' + service
        self.names.append(name)
        self.q.run('fixture-' + service, ['docker', 'run', '--detach', '--rm', '--name', name,
            '--label', 'busbar.admission.job=' + self.q.receipt['job_id'], '-p', f'127.0.0.1::{port}',
            *options, self.images[service], *command], timeout=300)
        mapped = subprocess.check_output(['docker', 'port', name, str(port) + '/tcp'], env=self.q.env, text=True).strip()
        return name, mapped.rsplit(':', 1)[1]

    def http_ready(self, url, timeout=60):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                with urllib.request.urlopen(url, timeout=2) as response:
                    if response.status == 200:
                        return
            except (OSError, urllib.error.URLError):
                pass
            time.sleep(0.5)
        raise RuntimeError('fixture did not become ready within its cap: ' + url)

    def __enter__(self):
        try:
            for service in self.requested:
                if service in ('postgres', 'mysql', 'valkey'):
                    self.stores.append(service)
                    self.q.run('fixture-' + service, ['bash', str(self.store_script), 'up', service], timeout=300)
                    url = self.store('url', service)
                    self.q.env['BUSBAR_TEST_' + service.upper() + '_URL'] = url
                    self.q.env['BUSBAR_TEST_' + service.upper() + '_V4_URL'] = self.store('ns', service, self.tag.replace('-', '_') + '_v4') if service != 'valkey' else url
                    if service == 'postgres':
                        self.q.env['BUSBAR_TEST_POSTGRES_IMPORT_URL'] = url
                    if service == 'mysql':
                        self.q.env['BUSBAR_TEST_MYSQL_ROOT_PASSWORD'] = 'busbar'
                    if service == 'valkey':
                        self.q.env.update(VALKEY_URL=url, BUSBAR_V4_TRANSPORT_URL=url)
                        if self.q.repository == 'GetBusbar/busbar-store-valkey':
                            # The required ignored witnesses launch their own servers,
                            # including Unix sockets and crash/restart lifecycles. Use
                            # the same pinned image as the live fixture, never a
                            # runner-installed executable of an unknown version.
                            fixture = self.q.work / 'valkey-native'
                            fixture.mkdir()
                            server = fixture / 'valkey-server'
                            name = 'busbar-store-qa-valkey-' + self.tag
                            self.q.run('fixture-valkey-server', ['docker', 'cp',
                                name + ':/usr/local/bin/valkey-server', str(server)], timeout=60)
                            self.q.run('fixture-valkey-server-check', [str(server), '--version'], timeout=30)
                            self.q.env.update(BUSBAR_V4_TEST_TMP=str(fixture), BUSBAR_VALKEY_SERVER=str(server))
                elif service == 'vault':
                    _, port = self.container(service, 8200,
                        ['-e', 'VAULT_DEV_ROOT_TOKEN_ID=busbar-fixture', '-e', 'VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200'], ['server', '-dev'])
                    url = 'http://127.0.0.1:' + port
                    self.http_ready(url + '/v1/sys/health')
                    self.q.env.update(BUSBAR_TEST_VAULT_ADDR=url, BUSBAR_TEST_VAULT_TOKEN='busbar-fixture')
                elif service == 'wiremock':
                    _, port = self.container(service, 8080)
                    url = 'http://127.0.0.1:' + port
                    self.http_ready(url + '/__admin/mappings')
                    self.q.env['BUSBAR_TEST_WIREMOCK_URL'] = url
                elif service == 'openldap':
                    seed = self.q.trusted / 'scripts/fixtures/auth-ldap/seed.ldif'
                    name, port = self.container(service, 389, ['-e', 'LDAP_ORGANISATION=Example Org',
                        '-e', 'LDAP_DOMAIN=example.org', '-e', 'LDAP_ADMIN_PASSWORD=adminpassword', '-e', 'LDAP_TLS=false'])
                    deadline = time.monotonic() + 60
                    command = ldap_readiness_command(name)
                    while subprocess.run(command, env=self.q.env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode:
                        if time.monotonic() >= deadline:
                            raise RuntimeError('OpenLDAP fixture failed readiness')
                        time.sleep(0.5)
                    subprocess.run(['docker', 'exec', '-i', name, 'ldapadd', '-x', '-H', 'ldap://127.0.0.1',
                        '-D', 'cn=admin,dc=example,dc=org', '-w', 'adminpassword'], input=seed.read_bytes(), env=self.q.env,
                        stdout=subprocess.DEVNULL, check=True)
                    self.q.env['BUSBAR_TEST_LDAP_URL'] = 'ldap://127.0.0.1:' + port
            # The supported migration witness is produced by the real published 1.5.5
            # artifact, using the repository's existing digest-checked recorder.
            if self.q.repository in ('GetBusbar/busbar', 'GetBusbar/busbar-store-sqlite'):
                fixture = self.q.work / 'sqlite-1.5.5'
                self.q.run('migration-fixture', ['bash', str(self.q.trusted / 'scripts/store-migration-fixture.sh'),
                    'record', 'sqlite', str(fixture)], timeout=900)
                self.q.run('migration-fixture-check', ['bash', str(self.q.trusted / 'scripts/store-migration-fixture.sh'),
                    'check', str(fixture)], timeout=120)
                self.q.env['BUSBAR_TEST_SQLITE_155_FIXTURE'] = str(fixture)
            self.q.receipt['fixture_images'] = {name: self.images[name] for name in self.requested}
            self.q.save()
            return self
        except BaseException:
            self.close()
            raise

    def close(self):
        failed = []
        for name in self.names:
            result = subprocess.run(['docker', 'rm', '--force', name], env=self.q.env, capture_output=True)
            if result.returncode and subprocess.run(['docker', 'inspect', name], env=self.q.env, capture_output=True).returncode == 0:
                failed.append(name)
        for service in self.stores:
            if subprocess.run(['bash', str(self.store_script), 'down', service], env=self.q.env, capture_output=True).returncode:
                failed.append(service)
        self.q.receipt['fixture_cleanup'] = {'removed': not failed, 'remaining': failed}
        self.q.save()
        if failed:
            raise RuntimeError('fixture cleanup failed: ' + ', '.join(failed))

    def __exit__(self, *_):
        self.close()
