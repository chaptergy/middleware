import asyncio
import pathlib

from middlewared.service import Service

SCST_TARGETS_ISCSI_ENABLED_PATH = '/sys/kernel/scst_tgt/targets/iscsi/enabled'


class iSCSITargetService(Service):

    class Config:
        namespace = 'iscsi.scst'
        private = True

    def set_cluster_mode(self, path, text):
        pathlib.Path(path).write_text(text)

    async def set_all_cluster_mode(self, value):
        text = f'{int(value)}\n'
        paths = await self.middleware.call('iscsi.scst.cluster_mode_paths')
        if paths:
            await asyncio.gather(*[self.middleware.call('iscsi.scst.set_cluster_mode', path, text) for path in paths])

    def cluster_mode_paths(self):
        scst_tgt_devices = pathlib.Path('/sys/kernel/scst_tgt/devices')
        if scst_tgt_devices.exists():
            return [str(p) for p in scst_tgt_devices.glob('*/cluster_mode')]
        else:
            return []

    def disable(self):
        p = pathlib.Path(SCST_TARGETS_ISCSI_ENABLED_PATH)
        p.write_text('0\n')

    def enable(self):
        p = pathlib.Path(SCST_TARGETS_ISCSI_ENABLED_PATH)
        p.write_text('1\n')

    def enabled(self):
        p = pathlib.Path(SCST_TARGETS_ISCSI_ENABLED_PATH)
        try:
            return p.read_text().strip() == '1'
        except FileNotFoundError:
            return False
