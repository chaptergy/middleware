import os
import pytest

from middlewared.test.integration.assets.account import user, group
from middlewared.test.integration.assets.pool import dataset
from middlewared.test.integration.assets.smb import smb_share, smb_mount 
from middlewared.test.integration.utils import call, client, ssh


@pytest.fixture(scope='module')
def setup_smb_tests(request):
    with dataset('smbclient-testing', data={'share_type': 'SMB'}) as ds:
        with user({
            'username': 'smbuser',
            'full_name': 'smbuser',
            'group_create': True,
            'password': 'Abcd1234$' 
        }) as u:
            with smb_share(os.path.join('/mnt', ds), 'client_share') as s:
                try:
                    call('service.start', 'cifs')
                    yield {'dataset': ds, 'share': s, 'user': u}
                finally:
                    call('service.stop', 'cifs')


@pytest.fixture(scope='module')
def mount_share(setup_smb_tests):
    with smb_mount(setup_smb_tests['share']['name'], 'smbuser', 'Abcd1234$') as mp:
        yield setup_smb_tests | {'mountpoint': mp} 


def compare_acls(share_path, local_path):
    local_acl = call('filesystem.getacl', local_path)
    local_acl.pop('path')
    smb_acl = call('filesystem.getacl', share_path)
    smb_acl.pop('path')
    assert local_acl == smb_acl


def test_smb_mount(request, mount_share):
    assert call('filesystem.statfs', mount_share['mountpoint'])['fstype'] == 'cifs'


def test_acl_share_root(request, mount_share):
    compare_acls(mount_share['share']['path'], mount_share['mountpoint'])


def test_acl_share_subdir(request, mount_share):
    call('filesystem.mkdir', {
        'path': os.path.join(mount_share['share']['path'], 'testdir'),
        'options': {'raise_chmod_error': False},
    })

    compare_acls(
        os.path.join(mount_share['share']['path'], 'testdir'),
        os.path.join(mount_share['mountpoint'], 'testdir')
    )


def test_acl_share_file(request, mount_share):
    ssh(f'touch {os.path.join(mount_share["share"]["path"], "testfile")}')

    compare_acls(
        os.path.join(mount_share['share']['path'], 'testfile'),
        os.path.join(mount_share['mountpoint'], 'testfile')
    )
