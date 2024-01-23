import enum

from base64 import b64encode, b64decode
from middlewared.service import Service
from middlewared.service_exception import MatchNotFound
from middlewared.plugins.tdb.utils import TDBError

SECRETS_FILE = '/var/db/system/samba4/private/secrets.tdb'


class Secrets(enum.Enum):
    MACHINE_ACCT_PASS = 'SECRETS/$MACHINE.ACC'
    MACHINE_PASSWORD = 'SECRETS/MACHINE_PASSWORD'
    MACHINE_PASSWORD_PREV = 'SECRETS/MACHINE_PASSWORD.PREV'
    MACHINE_LAST_CHANGE_TIME = 'SECRETS/MACHINE_LAST_CHANGE_TIME' 
    MACHINE_SEC_CHANNEL_TYPE = 'SECRETS/MACHINE_SEC_CHANNEL_TYPE'
    MACHINE_TRUST_ACCOUNT_NAME = 'SECRETS/SECRETS_MACHINE_TRUST_ACCOUNT_NAME'
    MACHINE_DOMAIN_INFO = 'SECRETS/MACHINE_DOMAIN_INFO'
    DOMTRUST_ACCT_PASS = 'SECRETS/$DOMTRUST.ACC'
    SALTING_PRINCIPAL = 'SECRETS/SALTING_PRINCIPAL'
    DOMAIN_SID = 'SECRETS/SID'
    SAM_SID = 'SAM/SID'
    PROTECT_IDS = 'SECRETS/PROTECT/IDS'
    DOMAIN_GUID = 'SECRETS/DOMGUID'
    SERVER_GUID = 'SECRETS/GUID'
    LDAP_BIND_PW = 'SECRETS/LDAP_BIND_PW'
    LOCAL_SCHANNEL_KEY = 'SECRETS/LOCAL_SCHANNEL_KEY'
    AUTH_USER = 'SECRETS/AUTH_USER'
    AUTH_DOMAIN = 'SECRETS/AUTH_DOMAIN'
    AUTH_PASSWORD = 'SECRETS/AUTH_PASSWORD'


class ADSecrets(Service):

    class Config:
        namespace = 'directoryservices.secrets'
        cli_private = True
        private = True

    tdb_options = {
        'backend': 'CUSTOM',
        'data_type': 'BYTES'
    }

    async def __fetch(self, key):
        return await self.middleware.call('tdb.fetch', {
            'name': SECRETS_FILE,
            'key': key,
            'tdb-options': self.tdb_options
        })

    async def __store(self, key, value):
        return await self.middleware.call('tdb.store', {
            'name': SECRETS_FILE,
            'key': key,
            'value': value,
            'tdb-options': self.tdb_options
        })

    async def __remove(self, key):
        return await self.middleware.call('tdb.remove', {
            'name': SECRETS_FILE,
            'key': key,
            'tdb-options': self.tdb_options
        })

    async def __wipe(self):
        return await self.middleware.call('tdb.wipe', {
            'name': SECRETS_FILE,
            'tdb-options': self.tdb_options
        })

    async def __flush(self):
        return await self.middleware.call('tdb.flush', {
            'name': SECRETS_FILE,
            'tdb-options': self.tdb_options
        })


    async def __entries(self, filters, options):
        return await self.middleware.call('tdb.entries', {
            'name': SECRETS_FILE,
            'query-filters': filters,
            'query-options': options,
            'tdb-options': self.tdb_options
        })

    def has_domain(self, domain):
        return bool(await self.__fetch(f"{Secrets.MACHINE_LAST_CHANGE_TIME.value}/{domain.upper()}"))

    def last_password_change(self, domain):
        encoded_change_ts = await self.__fetch(
            f"{Secrets.MACHINE_LAST_CHANGE_TIME.value}/{domain.upper()}"
        )
        try:
            bytes_passwd_chng = b64decode(encoded_change_ts)
        except Exception:
            self.logger.warning("Failed to retrieve last password change time for domain "
                                "[%s] from domain secrets. Directory service functionality "
                                "may be impacted.", domain, exc_info=True)
            return None

        return struct.unpack("<L", bytes_passwd_chng)[0]

    def set_ldap_idmap_secret(self, domain, user_dn, secret):
        await self.__store(f'SECRETS/GENERIC/IDMAP_LDAP_{domain.upper()}/{userdn}', b64encode(secret))

    def get_ldap_idmap_secret(self, domain, user_dn):
        return await self.__fetch(f'SECRETS/GENERIC/IDMAP_LDAP_{domain.upper()}/{user_dn}')
