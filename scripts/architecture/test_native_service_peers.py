"""Direct regressions for the protected no-network service peer interface."""
import copy
import io
import json
import subprocess
import os
import tarfile
import tempfile
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch, Mock

from native_service_peers import CAPS, TMPFS, Peers, runtime_controls_probe


class PeerControls(unittest.TestCase):
    def test_readiness_failure_is_bounded_redacted_and_collected_before_disposal(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            peers = Peers.__new__(Peers)
            peers.q = SimpleNamespace(evidence=Path(directory))
            peers.peers = {'openldap': {'name': 'fixed-peer'}}
            peers.client = Mock(return_value=SimpleNamespace(returncode=0,
                stdout='x' * 40000 + ' adminpassword busbar-fixture busbar', stderr='adminpassword'))
            result = SimpleNamespace(returncode=1, stdout='', stderr='adminpassword')
            with self.assertRaisesRegex(RuntimeError, 'openldap fixture failed bounded readiness'):
                peers.readiness_failure('openldap', 'failed bounded readiness', result)
            payload = (Path(directory) / 'fixture-openldap-readiness.json').read_text()
            record = json.loads(payload)
            self.assertEqual(record['last_readiness']['returncode'], 1)
            for secret in ('adminpassword', 'busbar-fixture'):
                self.assertNotIn(secret, payload)
            self.assertLessEqual(len(record['logs']['stdout']), 16384)
            self.assertLessEqual(len(record['state']['stdout']), 4096)
            self.assertEqual(record['bootstrap_marker']['returncode'], 0)
            for call in peers.client.call_args_list:
                self.assertEqual(call.kwargs, {'check': False, 'timeout': 5})
                self.assertNotIn('rm', call.args[0])
            self.assertEqual(peers.client.call_args_list[0].args[0],
                             ['inspect', '--format', '{{json .State}}', 'fixed-peer'])

    def test_diagnostic_errors_preserve_readiness_failure_without_command_secrets(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            peers = Peers.__new__(Peers)
            peers.q = SimpleNamespace(evidence=Path(directory))
            peers.peers = {'mysql': {'name': 'fixed-peer'}}
            peers.client = Mock(side_effect=subprocess.TimeoutExpired(['secret'], 5))
            with self.assertRaisesRegex(RuntimeError, 'mysql fixture exited during readiness'):
                peers.readiness_failure('mysql', 'exited during readiness')
            payload = (Path(directory) / 'fixture-mysql-readiness.json').read_text()
            self.assertNotIn('secret', payload)
            self.assertEqual(json.loads(payload)['logs']['collection_error'], 'TimeoutExpired')

    def test_wait_retains_last_error_without_changing_readiness_criterion(self):
        peers = Peers.__new__(Peers)
        peers.peers = {'mysql': {'name': 'fixed-peer'}}
        failed = SimpleNamespace(returncode=1, stdout='', stderr='connection refused')
        peers.exec = Mock(return_value=failed)
        peers.readiness_failure = Mock(side_effect=RuntimeError('readiness failed'))
        with patch('time.monotonic', side_effect=[0, 120]):
            with self.assertRaisesRegex(RuntimeError, 'readiness failed'):
                peers.wait('mysql', ['fixed-probe'])
        peers.readiness_failure.assert_called_once_with('mysql', 'failed bounded readiness', failed)
        peers.exec = Mock(return_value=SimpleNamespace(returncode=0))
        peers.readiness_failure.reset_mock()
        peers.wait('mysql', ['fixed-probe'])
        peers.readiness_failure.assert_not_called()

    def fixture(self):
        peers=Peers.__new__(Peers)
        peers.execution=SimpleNamespace(config={'isolation':{}})
        peers.daemon={'SwapLimit':True}
        host={'Runtime':'runc','NetworkMode':'none','Privileged':False,'ReadonlyRootfs':True,'PidMode':'',
              'IpcMode':'private','CgroupnsMode':'private','CapDrop':['ALL'],
              'CapAdd':['CAP_'+cap for cap in CAPS],'SecurityOpt':['no-new-privileges'],
              'Memory':1073741824,'MemorySwap':1073741824,'NanoCpus':1000000000,
              'PidsLimit':256,'ShmSize':64*1024**2,'Tmpfs':TMPFS,'PortBindings':{},
              'Devices':[],'LogConfig':{'Type':'local','Config':{'max-size':'1m','max-file':'1','compress':'false'}}}
        image={'Id':'sha256:'+'a'*64}
        actual={'Image':image['Id'],'HostConfig':host,
                'Mounts':[{'Type':'bind','Source':'/job/data','Destination':'/data','RW':True}]}
        return peers, image, actual

    def test_weakened_peer_network_resources_and_mounts_are_refused(self):
        peers, image, actual = self.fixture()
        with patch('linux_job_isolation.validate_userns'):
            peers.verify(actual,image,[(Path('/job/data'),'/data')])
            for key,value in [('NetworkMode','bridge'),('Privileged',True),('ReadonlyRootfs',False),
                              ('PidMode','host'),('MemorySwap',-1),('NanoCpus',0),('PidsLimit',-1),
                              ('CapAdd',['SYS_ADMIN']),('PortBindings',{'80/tcp':[{'HostPort':'80'}]})]:
                with self.subTest(key=key):
                    altered=copy.deepcopy(actual);altered['HostConfig'][key]=value
                    with self.assertRaises(ValueError):peers.verify(altered,image,[(Path('/job/data'),'/data')])
            altered=copy.deepcopy(actual)
            altered['HostConfig']['PidMode']='private'
            altered['Config']={'Env':['PRIVATE_TOKEN=must-never-appear']}
            with self.assertRaisesRegex(ValueError, 'protected request:') as failure:
                peers.verify(altered,image,[(Path('/job/data'),'/data')])
            self.assertIn('"PidMode":{"observed":"private","requested":""}', str(failure.exception))
            self.assertNotIn('PRIVATE_TOKEN', str(failure.exception))
            altered['HostConfig']['Runtime']='x'*10000
            with self.assertRaises(ValueError) as failure:
                peers.verify(altered,image,[(Path('/job/data'),'/data')])
            self.assertLessEqual(len(str(failure.exception)), 4160)
            altered=copy.deepcopy(actual);altered['Mounts'].append(
                {'Type':'bind','Source':'/var/run/docker.sock','Destination':'/socket','RW':True})
            with self.assertRaisesRegex(ValueError,'mounts'):peers.verify(altered,image,[(Path('/job/data'),'/data')])

    def test_control_probe_collects_both_flag_sets_and_disposes_without_starting(self):
        for refuses in (False, True):
            with self.subTest(refuses=refuses), tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
                calls=[]
                def run(command, **kwargs):
                    args=command[3:];calls.append(args)
                    payload=({'ServerVersion':'29.1.3'} if args[0]=='info' else
                        [{'Id':'sha256:'+'a'*64,'Config':{}}] if args[0]=='image' else
                        [{'Image':'sha256:'+'a'*64,'HostConfig':{},'Config':{'Env':['SECRET=excluded']}}]
                        if args[0]=='inspect' else '')
                    return subprocess.CompletedProcess(command,0,
                        stdout=json.dumps(payload) if payload else '',stderr='')
                config={'docker':'/fixed/docker','docker_host':'unix:///private',
                        'image':'sha256:'+'a'*64,'runtime':'runc'}
                with patch('subprocess.run',side_effect=run), \
                        patch.object(Peers,'control_values',return_value=({'PidMode':''},{'PidMode':'private'})), \
                        patch.object(Peers,'verify',return_value={},side_effect=ValueError('protected mismatch') if refuses else None):
                    if refuses:
                        with self.assertRaisesRegex(ValueError,'probe refused'):
                            runtime_controls_probe(config,Path(directory))
                    else:
                        runtime_controls_probe(config,Path(directory))
                report=json.loads((Path(directory)/'fixture-controls-probe.json').read_text())
                self.assertEqual(len(report['cases']),2)
                self.assertTrue(all(case['disposed'] for case in report['cases']))
                self.assertEqual([case['status'] for case in report['cases']],
                                 ['refused' if refuses else 'pass']*2)
                self.assertNotIn('SECRET',json.dumps(report))
                self.assertNotIn('start',[call[0] for call in calls])
                self.assertNotIn('pull',[call[0] for call in calls])
                creates=[call for call in calls if call[0]=='create']
                self.assertEqual(len(creates),2)
                for call in creates:
                    self.assertIn('--network=none',call)
                    self.assertIn('--pull=never',call)
                    self.assertIn('--read-only',call)
                self.assertNotIn('KILL',creates[0])
                self.assertIn('KILL',creates[1])
                self.assertIn('busbar-ldap.example.org:127.0.0.1',creates[1])
                self.assertEqual([call[0] for call in calls].count('rm'),2)
                self.assertEqual([call[0] for call in calls].count('ps'),2)

    def test_unaccounted_swap_requires_independent_zero_capacity_proof(self):
        peers, image, actual = self.fixture()
        actual['HostConfig']['MemorySwap'] = -1
        header=b'Filename\tType\tSize\tUsed\tPriority\n'
        def evidence(swaps=header, total=b'SwapTotal: 0 kB\n'):
            return lambda path, *args, **kwargs: io.BytesIO(swaps if str(path)=='/proc/swaps' else total)
        with patch('linux_job_isolation.validate_userns'):
            for advertised in (None, True, 0):
                peers.daemon={'SwapLimit':advertised}
                with self.subTest(advertised=advertised), patch('linux_job_isolation.kernel_no_swap') as proof:
                    with self.assertRaisesRegex(ValueError,'MemorySwap'):
                        peers.verify(actual,image,[(Path('/job/data'),'/data')])
                    proof.assert_not_called()
            peers.daemon={'SwapLimit':False}
            with patch.object(Path,'open',evidence()):
                proof=peers.verify(actual,image,[(Path('/job/data'),'/data')])
            self.assertEqual(proof['observed_memory_swap_bytes'],-1)
            self.assertEqual(proof['requested_memory_swap_bytes'],1073741824)
            self.assertEqual(proof['effective_swap_bytes'],0)
            self.assertEqual(proof['mechanism'],'kernel-zero-swap-capacity')
            for swaps,total in [(header+b'/swap file 1024 0 -2\n',b'SwapTotal: 0 kB\n'),
                                (header,b'SwapTotal: 1024 kB\n'),(b'',b'SwapTotal: 0 kB\n'),
                                (header,b'SwapTotal: 0 kB\nSwapTotal: 0 kB\n'),
                                (header,b'SwapTotal: 0 MB\n'),(header,b'MemTotal: 8192 kB\n')]:
                with self.subTest(swaps=swaps,total=total), patch.object(Path,'open',evidence(swaps,total)):
                    with self.assertRaisesRegex(ValueError,'kernel has swap capacity or invalid evidence'):
                        peers.verify(actual,image,[(Path('/job/data'),'/data')])
            with patch.object(Path,'open',side_effect=PermissionError('unreadable kernel proof')):
                with self.assertRaises(PermissionError):
                    peers.verify(actual,image,[(Path('/job/data'),'/data')])
            # Echoed request bytes alone do not establish kernel enforcement.
            actual['HostConfig']['MemorySwap']=1073741824
            for daemon in ({}, {'SwapLimit':None}, {'SwapLimit':0}, {'SwapLimit':1}):
                peers.daemon=daemon
                with self.subTest(daemon=daemon), patch('linux_job_isolation.kernel_no_swap') as proof:
                    with self.assertRaisesRegex(ValueError,'SwapLimit'):
                        peers.verify(actual,image,[(Path('/job/data'),'/data')])
                    proof.assert_not_called()
            peers.daemon={'SwapLimit':False}
            with patch.object(Path,'open',evidence(header,b'SwapTotal: 1024 kB\n')):
                with self.assertRaisesRegex(ValueError,'kernel has swap capacity'):
                    peers.verify(actual,image,[(Path('/job/data'),'/data')])
            with patch.object(Path,'open',evidence()):
                proof=peers.verify(actual,image,[(Path('/job/data'),'/data')])
            self.assertEqual(proof['observed_memory_swap_bytes'],1073741824)
            self.assertEqual(proof['mechanism'],'kernel-zero-swap-capacity')
            actual['HostConfig']['Memory']=0
            with patch.object(Path,'open',evidence()):
                with self.assertRaisesRegex(ValueError,'Memory'):
                    peers.verify(actual,image,[(Path('/job/data'),'/data')])

    def test_zero_swap_is_rechecked_after_all_peers_are_disposed(self):
        peers=Peers.__new__(Peers)
        peers.names=['first','second'];peers.namespaces=[]
        proofs=[{'mechanism':'kernel-zero-swap-capacity'} for _ in range(2)]
        peers.q=SimpleNamespace(receipt={'service_peers':{
            str(index):{'swap_bound':proof} for index,proof in enumerate(proofs)}})
        peers.client=Mock(return_value=SimpleNamespace(returncode=0))
        def changed():
            self.assertEqual(peers.names,[])
            self.assertTrue(all(value['disposed'] for value in peers.q.receipt['service_peers'].values()))
            raise ValueError('host swap capacity changed')
        with patch('linux_job_isolation.kernel_no_swap',side_effect=changed):
            with self.assertRaisesRegex(ValueError,'host swap capacity changed'):
                peers.close()
        self.assertEqual(peers.client.call_count,2)

    def copy_peer(self):
        peers=Peers.__new__(Peers)
        peers.execution=SimpleNamespace(config={'docker':'docker','docker_host':'unix:///private',
            'isolation':{'uid_map':[0,524288,65536],'gid_map':[0,524288,65536]}},client_env={})
        return peers

    def archive(self, entries):
        output=io.BytesIO()
        with tarfile.open(fileobj=output,mode='w') as archive:
            for name,kind,uid,content in entries:
                entry=tarfile.TarInfo(name);entry.type=kind;entry.uid=uid;entry.gid=uid;entry.mode=0o755
                if kind==tarfile.SYMTYPE:
                    entry.linkname=content;archive.addfile(entry)
                elif kind==tarfile.REGTYPE:
                    entry.size=len(content);archive.addfile(entry,io.BytesIO(content))
                else:archive.addfile(entry)
        output.seek(0)
        return Mock(stdout=output,stderr=io.BytesIO(),wait=Mock(return_value=0),poll=Mock(return_value=0))

    def test_preserves_image_identity_without_double_mapping(self):
        for uid in (100,524388):
            process=self.archive([('.',tarfile.DIRTYPE,uid,None),('./token',tarfile.REGTYPE,uid,b'public')])
            with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory, \
                    patch('subprocess.Popen',return_value=process),patch('os.chown') as chown:
                destination=Path(directory)/'data'
                self.copy_peer().mapped_copy('/home/vault',destination,'fixed-source')
                self.assertEqual((destination/'token').read_bytes(),b'public')
                self.assertTrue(all(call.args[1:3]==(524388,524388) for call in chown.call_args_list))

    def test_image_symlink_cannot_redirect_host_extraction(self):
        process=self.archive([('.',tarfile.DIRTYPE,0,None),('./link',tarfile.SYMTYPE,0,'../outside'),
                              ('./link/escape',tarfile.REGTYPE,0,b'blocked')])
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory, \
                patch('subprocess.Popen',return_value=process),patch('os.chown'):
            destination=Path(directory)/'data'
            with self.assertRaisesRegex(RuntimeError,'indirect'):
                self.copy_peer().mapped_copy('/etc',destination,'fixed-source')
            self.assertFalse((Path(directory)/'outside').exists())

    def test_only_closed_declared_services_can_start(self):
        peers=Peers.__new__(Peers);peers.peers={}
        with self.assertRaisesRegex(ValueError,'unknown'):
            peers.start('http://169.254.169.254')
        peers.peers={'wiremock':{}}
        with self.assertRaisesRegex(ValueError,'duplicate'):
            peers.start('wiremock')

if __name__ == '__main__':unittest.main()
