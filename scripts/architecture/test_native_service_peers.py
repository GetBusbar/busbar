"""Direct regressions for the protected no-network service peer interface."""
import copy
import io
import os
import tarfile
import tempfile
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch, Mock

from native_service_peers import CAPS, TMPFS, Peers


class PeerControls(unittest.TestCase):
    def test_weakened_peer_network_resources_and_mounts_are_refused(self):
        peers=Peers.__new__(Peers)
        peers.execution=SimpleNamespace(config={'isolation':{}})
        peers.daemon={}
        host={'Runtime':'runc','NetworkMode':'none','Privileged':False,'ReadonlyRootfs':True,'PidMode':'',
              'IpcMode':'private','CgroupnsMode':'private','CapDrop':['ALL'],
              'CapAdd':['CAP_'+cap for cap in CAPS],'SecurityOpt':['no-new-privileges'],
              'Memory':1073741824,'MemorySwap':1073741824,'NanoCpus':1000000000,
              'PidsLimit':256,'ShmSize':64*1024**2,'Tmpfs':TMPFS,'PortBindings':{},
              'Devices':[],'LogConfig':{'Type':'local','Config':{'max-size':'1m','max-file':'1','compress':'false'}}}
        image={'Id':'sha256:'+'a'*64}
        actual={'Image':image['Id'],'HostConfig':host,
                'Mounts':[{'Type':'bind','Source':'/job/data','Destination':'/data','RW':True}]}
        with patch('linux_job_isolation.validate_userns'):
            peers.verify(actual,image,[(Path('/job/data'),'/data')])
            for key,value in [('NetworkMode','bridge'),('Privileged',True),('ReadonlyRootfs',False),
                              ('PidMode','host'),('MemorySwap',-1),('NanoCpus',0),('PidsLimit',-1),
                              ('CapAdd',['SYS_ADMIN']),('PortBindings',{'80/tcp':[{'HostPort':'80'}]})]:
                with self.subTest(key=key):
                    altered=copy.deepcopy(actual);altered['HostConfig'][key]=value
                    with self.assertRaises(ValueError):peers.verify(altered,image,[(Path('/job/data'),'/data')])
            altered=copy.deepcopy(actual);altered['Mounts'].append(
                {'Type':'bind','Source':'/var/run/docker.sock','Destination':'/socket','RW':True})
            with self.assertRaisesRegex(ValueError,'mounts'):peers.verify(altered,image,[(Path('/job/data'),'/data')])

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
