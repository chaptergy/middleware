import asyncio
import base64
import enum
import errno
import io
import os
import shutil
import subprocess
import contextlib
import time
from middlewared.plugins.idmap import DSType
from middlewared.schema import accepts, returns, Dict, Int, List, Patch, Str, OROperator, Password, Ref, Datetime, Bool
from middlewared.service import CallError, ConfigService, CRUDService, job, periodic, private, ValidationErrors
import middlewared.sqlalchemy as sa
from middlewared.utils import filter_list, MIDDLEWARE_RUN_DIR, run, Popen


KRB_TKT_CHECK_INTERVAL = 1800


class keytab(enum.Enum):
    SYSTEM = '/etc/krb5.keytab'
    SAMBA = '/var/db/system/samba4/private/samba.keytab'
    TEST = '/var/db/system/test.keytab'


class krb5ccache(enum.Enum):
    SYSTEM = f'{MIDDLEWARE_RUN_DIR}/krb5cc_0'
    TEMP = f'{MIDDLEWARE_RUN_DIR}/krb5cc_middleware_temp'
    USER = f'{MIDDLEWARE_RUN_DIR}/krb5cc_'


class krb_tkt_flag(enum.Enum):
    FORWARDABLE = 'F'
    FORWARDED = 'f'
    PROXIABLE = 'P'
    PROXY = 'p'
    POSTDATEABLE = 'D'
    POSTDATED = 'd'
    RENEWABLE = 'R'
    INITIAL = 'I'
    INVALID = 'i'
    HARDWARE_AUTHENTICATED = 'H'
    PREAUTHENTICATED = 'A'
    TRANSIT_POLICY_CHECKED = 'T'
    OKAY_AS_DELEGATE = 'O'
    ANONYMOUS = 'a'


class KRB_AppDefaults(enum.Enum):
    FORWARDABLE = ('forwardable', 'boolean')
    PROXIABLE = ('proxiable', 'boolean')
    NO_ADDRESSES = ('no-addresses', 'boolean')
    TICKET_LIFETIME = ('ticket_lifetime', 'time')
    RENEW_LIFETIME = ('renew_lifetime', 'time')
    ENCRYPT = ('encrypt', 'boolean')
    FORWARD = ('forward', 'boolean')

    def __str__(self):
        return self.value[0]

    def parm(self):
        return self.value[0]


class KRB_LibDefaults(enum.Enum):
    DEFAULT_REALM = ('default_realm', 'realm')
    ALLOW_WEAK_CRYPTO = ('allow_weak_crypto', 'boolean')
    CLOCKSKEW = ('clockskew', 'time')
    KDC_TIMEOUT = ('kdc_timeout', 'time')
    DEFAULT_CC_TYPE = ('ccache_type', 'cctype')
    DEFAULT_CC_NAME = ('default_ccache_name', 'ccname')
    DEFAULT_ETYPES = ('default_etypes', 'etypes')
    DEFAULT_AS_ETYPES = ('default_as_etypes', 'etypes')
    DEFAULT_TGS_ETYPES = ('default_tgs_etypes', 'etypes')
    DEFAULT_ETYPES_DES = ('default_etypes_des', 'etypes')
    DEFAULT_KEYTAB_NAME = ('default_keytab_name', 'keytab')
    DNS_LOOKUP_KDC = ('dns_lookup_kdc', 'boolean')
    DNS_LOOKUP_REALM = ('dns_lookup_realm', 'boolean')
    KDC_TIMESYNC = ('kdc_timesync', 'boolean')
    MAX_RETRIES = ('max_retries', 'number')
    LARGE_MSG_SIZE = ('large_msg_size', 'number')
    TICKET_LIFETIME = ('ticket_lifetime', 'time')
    RENEW_LIFETIME = ('renew_lifetime', 'time')
    FORWARDABLE = ('forwardable', 'boolean')
    PROXIABLE = ('proxiable', 'boolean')
    VERIFY_AP_REQ_NOFAIL = ('verify_ap_req_nofail', 'boolean')
    WARN_PWEXPIRE = ('warn_pwexpire', 'time')
    HTTP_PROXY = ('http_proxy', 'proxy-spec')
    DNS_PROXY = ('dns_proxy', 'proxy-spec')
    EXTRA_ADDRESSES = ('extra_addresses', 'address')
    TIME_FORMAT = ('time_format', 'string')
    DATE_FORMAT = ('date_format', 'string')
    LOG_UTC = ('log_utc', 'boolean')
    SCAN_INTERFACES = ('scan_interfaces', 'boolean')
    FCACHE_VERSION = ('fcache_version', 'int')
    KRB4_GET_TICKETS = ('krb4_get_tickets', 'boolean')
    FCC_MIT_TICKETFLAGS = ('fcc-mit-ticketflags', 'boolean')
    RDNS = ('rdns', 'boolean')

    def __str__(self):
        return self.value[0]

    def parm(self):
        return self.value[0]


class KRB_ETYPE(enum.Enum):
    DES_CBC_CRC = 'des-cbc-crc'
    DES_CBC_MD4 = 'des-cbc-md4'
    DES_CBC_MD5 = 'des-cbc-md5'
    DES3_CBC_SHA1 = 'des3-cbc-sha1'
    ARCFOUR_HMAC_MD5 = 'arcfour-hmac-md5'
    AES128_CTS_HMAC_SHA1_96 = 'aes128-cts-hmac-sha1-96'
    AES256_CTS_HMAC_SHA1_96 = 'aes256-cts-hmac-sha1-96'


class KerberosModel(sa.Model):
    __tablename__ = 'directoryservice_kerberossettings'

    id = sa.Column(sa.Integer(), primary_key=True)
    ks_appdefaults_aux = sa.Column(sa.Text())
    ks_libdefaults_aux = sa.Column(sa.Text())


class KerberosService(ConfigService):

    class Config:
        service = "kerberos"
        datastore = 'directoryservice.kerberossettings'
        datastore_prefix = "ks_"
        cli_namespace = "directory_service.kerberos.settings"

    @accepts(Dict(
        'kerberos_settings_update',
        Str('appdefaults_aux', max_length=None),
        Str('libdefaults_aux', max_length=None),
        update=True
    ))
    async def do_update(self, data):
        """
        `appdefaults_aux` add parameters to "appdefaults" section of the krb5.conf file.

        `libdefaults_aux` add parameters to "libdefaults" section of the krb5.conf file.
        """
        verrors = ValidationErrors()

        old = await self.config()
        new = old.copy()
        new.update(data)
        verrors.add_child(
            'kerberos_settings_update',
            await self._validate_appdefaults(new['appdefaults_aux'])
        )
        verrors.add_child(
            'kerberos_settings_update',
            await self._validate_libdefaults(new['libdefaults_aux'])
        )
        verrors.check()

        await self.middleware.call(
            'datastore.update', self._config.datastore, old['id'], new,
            {'prefix': self._config.datastore_prefix}
        )

        await self.middleware.call('etc.generate', 'kerberos')
        return await self.config()

    @private
    @accepts(Ref('kerberos-options'))
    async def ccache_path(self, data):
        krb_ccache = krb5ccache[data['ccache']]

        path_out = krb_ccache.value
        if krb_ccache == krb5ccache.USER:
            path_out += str(data['ccache_uid'])

        return path_out

    @private
    @accepts(Dict(
        'kerberos-options',
        Str('ccache', enum=[x.name for x in krb5ccache], default=krb5ccache.SYSTEM.name),
        Int('ccache_uid', default=0),
        register=True
    ))
    async def _klist_test(self, data):
        """
        Returns false if there is not a TGT or if the TGT has expired.
        """
        ccache_path = await self.ccache_path(data)

        klist = await run(['klist', '-s', '-c', ccache_path], check=False)
        if klist.returncode != 0:
            return False

        return True

    @private
    def generate_stub_config(self, realm, kdc=None):
        if os.path.exists('/etc/krb5.conf'):
            return

        def write_libdefaults(krb_file):
            dflt_realm = KRB_LibDefaults.DEFAULT_REALM.parm()
            dnslookup_realm = KRB_LibDefaults.DNS_LOOKUP_REALM.parm()
            dnslookup_kdc = KRB_LibDefaults.DNS_LOOKUP_KDC.parm()
            ccache_dir = KRB_LibDefaults.DEFAULT_CC_NAME.parm()

            krb_file.write('[libdefaults]\n')
            krb_file.write(f'\t{dflt_realm} = {realm}\n')
            krb_file.write(f'\t{dnslookup_realm} = false\n')
            krb_file.write(f'\t{dnslookup_kdc} = {"false" if kdc else "true"}\n')
            krb_file.write(f'\t{ccache_dir} = FILE:{krb5ccache.SYSTEM.value}\n')

        def write_realms(krb_file):
            krb_file.write('[realms]\n')
            krb_file.write(f'\t{realm} =' + '{\n')
            if kdc:
                krb_file.write(f'\t\tkdc = {kdc}\n')
            krb_file.write('\t}\n')

        with open('/etc/krb5.conf', 'w') as f:
            write_libdefaults(f)
            write_realms(f)
            f.flush()
            os.fsync(f.fileno())

    @private
    async def check_ticket(self):
        valid_ticket = await self._klist_test()
        if not valid_ticket:
            raise CallError("Kerberos ticket is required.", errno.ENOKEY)

        return

    @private
    async def _validate_param_type(self, data):
        supported_validation_types = [
            'boolean',
            'cctype',
            'etypes',
            'keytab',
        ]
        if data['ptype'] not in supported_validation_types:
            return

        if data['ptype'] == 'boolean':
            if data['value'].upper() not in ['YES', 'TRUE', 'NO', 'FALSE']:
                raise CallError(f'[{data["value"]}] is not boolean')

        if data['ptype'] == 'etypes':
            for e in data['value'].split(' '):
                try:
                    KRB_ETYPE(e)
                except Exception:
                    raise CallError(f'[{e}] is not a supported encryption type')

        if data['ptype'] == 'cctype':
            available_types = ['FILE', 'MEMORY', 'DIR']
            if data['value'] not in available_types:
                raise CallError(f'[{data["value"]}] is an unsupported cctype. '
                                f'Available types are {", ".join(available_types)}. '
                                'This parameter is case-sensitive')

        if data['ptype'] == 'keytab':
            try:
                keytab(data['value'])
            except Exception:
                raise CallError(f'{data["value"]} is an unsupported keytab path')

    @private
    async def _validate_appdefaults(self, appdefaults):
        verrors = ValidationErrors()
        for line in appdefaults.splitlines():
            param = line.split('=')
            if len(param) == 2 and (param[1].strip())[0] != '{':
                validated_param = list(filter(
                    lambda x: param[0].strip() in (x.value)[0], KRB_AppDefaults
                ))

                if not validated_param:
                    verrors.add(
                        'kerberos_appdefaults',
                        f'{param[0]} is an invalid appdefaults parameter.'
                    )
                    continue

                try:
                    await self._validate_param_type({
                        'ptype': (validated_param[0]).value[1],
                        'value': param[1].strip()
                    })
                except Exception as e:
                    verrors.add(
                        'kerberos_appdefaults',
                        f'{param[0]} has invalid value: {e.errmsg}.'
                    )
                    continue

        return verrors

    @private
    async def _validate_libdefaults(self, libdefaults):
        verrors = ValidationErrors()
        for line in libdefaults.splitlines():
            param = line.split('=')
            if len(param) == 2:
                validated_param = list(filter(
                    lambda x: param[0].strip() in (x.value)[0], KRB_LibDefaults
                ))

                if not validated_param:
                    verrors.add(
                        'kerberos_libdefaults',
                        f'{param[0]} is an invalid libdefaults parameter.'
                    )
                    continue

                try:
                    await self._validate_param_type({
                        'ptype': (validated_param[0]).value[1],
                        'value': param[1].strip()
                    })
                except Exception as e:
                    verrors.add(
                        'kerberos_libdefaults',
                        f'{param[0]} has invalid value: {e.errmsg}.'
                    )

            else:
                verrors.add('kerberos_libdefaults', f'{line} is an invalid libdefaults parameter.')

        return verrors

    @private
    @accepts(Dict(
        "get-kerberos-creds",
        Str("dstype", required=True, enum=[x.name for x in DSType]),
        OROperator(
            Dict(
                'ad_parameters',
                Str('bindname'),
                Str('bindpw'),
                Str('domainname'),
                Str('kerberos_principal')
            ),
            Dict(
                'ldap_parameters',
                Str('binddn'),
                Str('bindpw'),
                Int('kerberos_realm'),
                Str('kerberos_principal')
            ),
            name='conf',
            required=True
        )
    ))
    async def get_cred(self, data):
        '''
        Get kerberos cred from directory services config to use for `do_kinit`.
        '''
        conf = data.get('conf', {})
        if conf.get('kerberos_principal'):
            return {'kerberos_principal': conf['kerberos_principal']}

        verrors = ValidationErrors()
        dstype = DSType[data['dstype']]
        if dstype is DSType.DS_TYPE_ACTIVEDIRECTORY:
            for k in ['bindname', 'bindpw', 'domainname']:
                if not conf.get(k):
                    verrors.add(f'conf.{k}', 'Parameter is required.')

            verrors.check()
            return {
                'username': f'{conf["bindname"]}@{conf["domainname"].upper()}',
                'password': conf['bindpw']
            }

        for k in ['binddn', 'bindpw', 'kerberos_realm']:
            if not conf.get(k):
                verrors.add(f'conf.{k}', 'Parameter is required.')

        verrors.check()
        krb_realm = await self.middleware.call(
            'kerberos.realm.query',
            [('id', '=', conf['kerberos_realm'])],
            {'get': True}
        )
        bind_cn = (conf['binddn'].split(','))[0].split("=")
        return {
            'username': f'{bind_cn[1]}@{krb_realm["realm"]}',
            'password': conf['bindpw']
        }

    @private
    @accepts(Dict(
        'do_kinit',
        OROperator(
            Dict(
                'kerberos_username_password',
                Str('username', required=True),
                Password('password', required=True),
                register=True
            ),
            Dict(
                'kerberos_keytab',
                Str('kerberos_principal', required=True),
            ),
            name='krb5_cred',
            required=True,
        ),
        Patch(
            'kerberos-options',
            'kinit-options',
            ('add', {'name': 'renewal_period', 'type': 'int', 'default': 7}),
            ('add', {'name': 'lifetime', 'type': 'int', 'default': 0}),
            ('add', {
                'name': 'kdc_override',
                'type': 'dict',
                'args': [Str('domain', default=None), Str('kdc', default=None)]
            }),
        )
    ))
    async def do_kinit(self, data):
        ccache = krb5ccache[data['kinit-options']['ccache']]
        creds = data['krb5_cred']
        has_principal = 'kerberos_principal' in creds
        ccache_uid = data['kinit-options']['ccache_uid']
        ccache_path = await self.ccache_path({
            'ccache': data['kinit-options']['ccache'],
            'ccache_uid': data['kinit-options']['ccache_uid']
        })

        if ccache == krb5ccache.USER:
            if has_principal:
                raise CallError('User-specific ccache not permitted with keytab-based kinit')

            if ccache_uid == 0:
                raise CallError('User-specific ccache not permitted for uid 0')

        cmd = ['kinit', '-V', '-r', str(data['kinit-options']['renewal_period']), '-c', ccache_path]
        lifetime = data['kinit-options']['lifetime']

        if lifetime != 0:
            minutes = f'{lifetime}m'
            cmd.extend(['-l', minutes])

        if data['kinit-options']['kdc_override']['kdc'] is not None:
            override = data['kinit-options']['kdc_override']
            if override['domain'] is None:
                raise CallError('Domain missing from KDC override')

            await self.middleware.call(
                'kerberos.generate_stub_config',
                override['domain'], override['kdc']
            )

        if has_principal:
            principals = await self.middleware.call('kerberos.keytab.kerberos_principal_choices')
            if creds['kerberos_principal'] not in principals:
                self.logger.debug('Selected kerberos principal [%s] not available in keytab principals: %s. '
                                  'Regenerating kerberos keytab from configuration file.',
                                  creds['kerberos_principal'], ','.join(principals))
                await self.middleware.call('etc.generate', 'kerberos')

            cmd.extend(['-k', creds['kerberos_principal']])
            kinit = await run(cmd, check=False)
            if kinit.returncode != 0:
                raise CallError(f"kinit with principal [{creds['kerberos_principal']}] "
                                f"failed: {kinit.stderr.decode()}")
            return

        cmd.append(creds['username'])
        kinit = await Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE
        )

        output = await kinit.communicate(input=creds['password'].encode())
        if kinit.returncode != 0:
            raise CallError(f"kinit with password failed: {output[1].decode()}")

        if ccache == krb5ccache.USER:
            await self.middleware.run_in_thread(os.chown, ccache_path, ccache_uid, -1)

        return

    @private
    async def _kinit(self):
        """
        For now we only check for kerberos realms explicitly configured in AD and LDAP.
        """
        ad = await self.middleware.call('activedirectory.config')
        ldap = await self.middleware.call('ldap.config')
        await self.middleware.call('etc.generate', 'kerberos')
        payload = {}

        if ad['enable']:
            payload = {
                'dstype': DSType.DS_TYPE_ACTIVEDIRECTORY.name,
                'conf': {
                    'bindname': ad['bindname'],
                    'bindpw': ad.get('bindpw', ''),
                    'domainname': ad['domainname'],
                    'kerberos_principal': ad['kerberos_principal'],
                }
            }

        if ldap['enable'] and ldap['kerberos_realm']:
            payload = {
                'dstype': DSType.DS_TYPE_LDAP.name,
                'conf': {
                    'binddn': ldap['binddn'],
                    'bindpw': ldap['bindpw'],
                    'kerberos_realm': ldap['kerberos_realm'],
                    'kerberos_principal': ldap['kerberos_principal'],
                }
            }

        if not payload:
            return

        cred = await self.get_cred(payload)
        await self.do_kinit({'krb5_cred': cred})

    @private
    async def parse_klist(self, klistbuf):
        tickets = klistbuf.splitlines()

        ticket_cache = None
        default_principal = None
        tlen = len(tickets)

        parsed_klist = []
        for idx, e in enumerate(tickets):
            if e.startswith('Ticket cache'):
                cache_type, cache_name = e.strip('Ticket cache: ').split(':', 1)
                if cache_type == 'FILE':
                    cache_name = krb5ccache(cache_name.strip()).name

                ticket_cache = {
                    'type': cache_type,
                    'name': cache_name
                }

            if e.startswith('Default'):
                default_principal = (e.split(':')[1]).strip()
                continue

            if e and e[0].isdigit():
                d = e.split("  ")
                issued = time.mktime(time.strptime(d[0], "%m/%d/%y %H:%M:%S"))
                expires = time.mktime(time.strptime(d[1], "%m/%d/%y %H:%M:%S"))
                client = default_principal
                server = d[2]
                renew_until = 0
                flags = ''
                etype = None

                for i in range(idx + 1, idx + 3):
                    if i >= tlen:
                        break
                    if tickets[i][0].isdigit():
                        break
                    if tickets[i].startswith("\tEtype"):
                        etype = tickets[i].strip()
                        break

                    if tickets[i].startswith("\trenew"):
                        ts, flags = tickets[i].split(",")
                        renew_until = time.mktime(time.strptime(ts.strip('\trenew until '), "%m/%d/%y %H:%M:%S"))
                        flags = flags.split("Flags: ")[1]
                        continue

                    extra = tickets[i].split(", ", 1)
                    flags = extra[0][7:].strip()
                    etype = extra[1].strip()

                parsed_klist.append({
                    'issued': issued,
                    'expires': expires,
                    'renew_until': renew_until,
                    'client': client,
                    'server': server,
                    'etype': etype,
                    'flags': [krb_tkt_flag(f).name for f in flags],
                })

        return {
            'default_principal': default_principal,
            'ticket_cache': ticket_cache,
            'tickets': parsed_klist,
        }

    @private
    @accepts(Patch(
        'kerberos-options',
        'klist-options',
        ('add', {'name': 'timeout', 'type': 'int', 'default': 10}),
    ))
    async def klist(self, data):
        ccache = krb5ccache[data['ccache']].value

        try:
            klist = await asyncio.wait_for(
                self.middleware.create_task(run(['klist', '-ef', ccache], check=False, stdout=subprocess.PIPE)),
                timeout=data['timeout']
            )
        except asyncio.TimeoutError:
            raise CallError(f'Attempt to list kerberos tickets timed out after {data["timeout"]} seconds')

        if klist.returncode != 0:
            raise CallError(f'klist failed with error: {klist.stderr.decode()}')

        return await self.parse_klist(klist.stdout.decode())

    @private
    async def renew(self):
        if not await self._klist_test():
            self.logger.warning('Kerberos ticket is unavailable. Performing kinit.')
            return await self.start()

        tgt_info = await self.klist()
        if not tgt_info:
            return await self.start()

        current_time = time.time()

        ticket = filter_list(
            tgt_info['tickets'],
            [['client', '=', tgt_info['default_principal']], ['server', '^', 'krbtgt']],
            {'get': True}
        )

        remaining = ticket['expires'] - current_time
        if remaining < 0:
            self.logger.warning('Kerberos ticket expired. Performing kinit.')
            return await self.start()

        if remaining > KRB_TKT_CHECK_INTERVAL:
            return tgt_info

        if krb_tkt_flag.RENEWABLE.name not in ticket['flags']:
            self.logger.debug("Kerberos ticket is not renewable. Performing kinit.")
            return await self.start()

        if (2 * KRB_TKT_CHECK_INTERVAL) + current_time > ticket['renew_until']:
            # getting close to time when we can no longer renew. Better to kinit again.
            return await self.start()

        try:
            kinit = await asyncio.wait_for(self.middleware.create_task(run(['kinit', '-R'], check=False)), timeout=15)
            if kinit.returncode != 0:
                raise CallError(f'kinit -R failed with error: {kinit.stderr.decode()}')
        except asyncio.TimeoutError:
            raise CallError('Attempt to renew kerberos TGT failed after 15 seconds.')

        self.logger.debug('Successfully renewed kerberos TGT')
        return await self.klist()

    @private
    async def status(self):
        """
        Experience in production environments has indicated that klist can hang
        indefinitely. Fail if we hang for more than 10 seconds. This should force
        a kdestroy and new attempt to kinit (depending on why we are checking status).
        _klist_test will return false if there is not a TGT or if the TGT has expired.
        """
        try:
            ret = await asyncio.wait_for(self.middleware.create_task(self._klist_test()), timeout=10.0)
            return ret
        except asyncio.TimeoutError:
            self.logger.debug('kerberos ticket status check timed out after 10 seconds.')
            return False

    @private
    @accepts(Ref('kerberos-options'))
    async def kdestroy(self, data):
        kdestroy = await run(['kdestroy', '-c', krb5ccache[data['ccache']].value], check=False)
        if kdestroy.returncode != 0:
            raise CallError(f'kdestroy failed with error: {kdestroy.stderr.decode()}')

        return

    @private
    async def stop(self):
        renewal_job = await self.middleware.call(
            'core.get_jobs',
            [['method', '=', 'kerberos.wait_for_renewal'], ['state', '=', 'RUNNING']]
        )
        if renewal_job:
            await self.middleware.call('core.job_abort', renewal_job[0]['id'])

        await self.kdestroy()
        return

    @private
    async def start(self, realm=None, kinit_timeout=30):
        """
        kinit can hang because it depends on DNS. If it has not returned within
        30 seconds, it is safe to say that it has failed.
        """
        await self.middleware.call('etc.generate', 'kerberos')
        try:
            await asyncio.wait_for(self.middleware.create_task(self._kinit()), timeout=kinit_timeout)
        except asyncio.TimeoutError:
            raise CallError(f'Timed out hung kinit after [{kinit_timeout}] seconds')

        await self.middleware.call('kerberos.wait_for_renewal')
        return await self.klist()

    @private
    @job(lock="kerberos_renew_watch", transient=True, lock_queue_size=1)
    async def wait_for_renewal(self, job):
        klist = await self.klist()

        while True:
            now = time.time()

            ticket = filter_list(
                klist['tickets'],
                [['client', '=', klist['default_principal']], ['server', '^', 'krbtgt']],
                {'get': True}
            )

            timestr = time.strftime("%m/%d/%y %H:%M:%S UTC", time.gmtime(ticket['expires']))
            job.set_description(f'Waiting to renew kerberos ticket. Current ticket expires: {timestr}')

            if (ticket['expires'] - (now + KRB_TKT_CHECK_INTERVAL)) > 0:
                await asyncio.sleep(KRB_TKT_CHECK_INTERVAL)
                klist = await self.klist()
                continue

            klist = await self.renew()


class KerberosRealmModel(sa.Model):
    __tablename__ = 'directoryservice_kerberosrealm'

    id = sa.Column(sa.Integer(), primary_key=True)
    krb_realm = sa.Column(sa.String(120))
    krb_kdc = sa.Column(sa.String(120))
    krb_admin_server = sa.Column(sa.String(120))
    krb_kpasswd_server = sa.Column(sa.String(120))

    __table_args__ = (
        sa.Index("directoryservice_kerberosrealm_krb_realm", "krb_realm", unique=True),
    )


class KerberosRealmService(CRUDService):
    class Config:
        datastore = 'directoryservice.kerberosrealm'
        datastore_prefix = 'krb_'
        datastore_extend = 'kerberos.realm.kerberos_extend'
        namespace = 'kerberos.realm'
        cli_namespace = 'directory_service.kerberos.realm'

    @private
    async def kerberos_extend(self, data):
        for param in ['kdc', 'admin_server', 'kpasswd_server']:
            data[param] = data[param].split(' ') if data[param] else []

        return data

    @private
    async def kerberos_compress(self, data):
        for param in ['kdc', 'admin_server', 'kpasswd_server']:
            data[param] = ' '.join(data[param])

        return data

    ENTRY = Patch(
        'kerberos_realm_create', 'kerberos_realm_entry',
        ('add', Int('id')),
    )

    @accepts(
        Dict(
            'kerberos_realm_create',
            Str('realm', required=True),
            List('kdc'),
            List('admin_server'),
            List('kpasswd_server'),
            register=True
        )
    )
    async def do_create(self, data):
        """
        Create a new kerberos realm. This will be automatically populated during the
        domain join process in an Active Directory environment. Kerberos realm names
        are case-sensitive, but convention is to only use upper-case.

        Entries for kdc, admin_server, and kpasswd_server are not required.
        If they are unpopulated, then kerberos will use DNS srv records to
        discover the correct servers. The option to hard-code them is provided
        due to AD site discovery. Kerberos has no concept of Active Directory
        sites. This means that middleware performs the site discovery and
        sets the kerberos configuration based on the AD site.
        """
        verrors = ValidationErrors()

        verrors.add_child('kerberos_realm_create', await self._validate(data))

        verrors.check()

        data = await self.kerberos_compress(data)
        id_ = await self.middleware.call(
            'datastore.insert', self._config.datastore, data,
            {'prefix': self._config.datastore_prefix}
        )
        await self.middleware.call('etc.generate', 'kerberos')
        await self.middleware.call('service.restart', 'cron')
        return await self.get_instance(id_)

    @accepts(
        Int('id', required=True),
        Patch(
            "kerberos_realm_create",
            "kerberos_realm_update",
            ("attr", {"update": True})
        )
    )
    async def do_update(self, id_, data):
        """
        Update a kerberos realm by id. This will be automatically populated during the
        domain join process in an Active Directory environment. Kerberos realm names
        are case-sensitive, but convention is to only use upper-case.
        """
        old = await self.get_instance(id_)
        new = old.copy()
        new.update(data)

        data = await self.kerberos_compress(new)
        id_ = await self.middleware.call(
            'datastore.update', self._config.datastore, id_, new,
            {'prefix': self._config.datastore_prefix}
        )

        await self.middleware.call('etc.generate', 'kerberos')
        return await self.get_instance(id_)

    @accepts(Int('id'))
    async def do_delete(self, id_):
        """
        Delete a kerberos realm by ID.
        """
        await self.middleware.call('datastore.delete', self._config.datastore, id_)
        await self.middleware.call('etc.generate', 'kerberos')

    @private
    async def _validate(self, data):
        verrors = ValidationErrors()
        realms = await self.query()
        for realm in realms:
            if realm['realm'].upper() == data['realm'].upper():
                verrors.add('kerberos_realm', f'kerberos realm with name {realm["realm"]} already exists.')
        return verrors


class KerberosKeytabModel(sa.Model):
    __tablename__ = 'directoryservice_kerberoskeytab'

    id = sa.Column(sa.Integer(), primary_key=True)
    keytab_file = sa.Column(sa.EncryptedText())
    keytab_name = sa.Column(sa.String(120), unique=True)


class KerberosKeytabService(CRUDService):
    class Config:
        datastore = 'directoryservice.kerberoskeytab'
        datastore_prefix = 'keytab_'
        namespace = 'kerberos.keytab'
        cli_namespace = 'directory_service.kerberos.keytab'

    ENTRY = Patch(
        'kerberos_keytab_create', 'kerberos_keytab_entry',
        ('add', Int('id')),
    )

    @accepts(
        Dict(
            'kerberos_keytab_create',
            Str('file', max_length=None),
            Str('name'),
            register=True
        )
    )
    async def do_create(self, data):
        """
        Create a kerberos keytab. Uploaded keytab files will be merged with the system
        keytab under /etc/krb5.keytab.

        `file` b64encoded kerberos keytab
        `name` name for kerberos keytab
        """
        verrors = ValidationErrors()

        verrors.add_child('kerberos_principal_create', await self._validate(data))

        verrors.check()

        id_ = await self.middleware.call(
            'datastore.insert', self._config.datastore, data,
            {'prefix': self._config.datastore_prefix}
        )
        await self.middleware.call('etc.generate', 'kerberos')

        return await self.get_instance(id_)

    @accepts(
        Int('id', required=True),
        Patch(
            'kerberos_keytab_create',
            'kerberos_keytab_update',
        )
    )
    async def do_update(self, id_, data):
        """
        Update kerberos keytab by id.
        """
        old = await self.get_instance(id_)
        new = old.copy()
        new.update(data)

        verrors = ValidationErrors()

        verrors.add_child('kerberos_principal_update', await self._validate(new))

        verrors.check()

        await self.middleware.call(
            'datastore.update', self._config.datastore, id_, new,
            {'prefix': self._config.datastore_prefix}
        )
        await self.middleware.call('etc.generate', 'kerberos')

        return await self.get_instance(id_)

    @accepts(Int('id'))
    async def do_delete(self, id_):
        """
        Delete kerberos keytab by id, and force regeneration of
        system keytab.
        """
        kt = await self.get_instance(id_)
        if kt['name'] == 'AD_MACHINE_ACCOUNT':
            if (await self.middleware.call('activedirectory.get_state')) != 'DISABLED':
                raise CallError(
                    'Active Directory machine account keytab may not be deleted while '
                    'the Active Directory service is enabled.'
                )

        await self.middleware.call('datastore.delete', self._config.datastore, id_)
        await self.middleware.call('etc.generate', 'kerberos')
        await self._cleanup_kerberos_principals()
        await self.middleware.call('kerberos.stop')
        try:
            await self.middleware.call('kerberos.start')
        except Exception as e:
            self.logger.debug(
                'Failed to start kerberos service after deleting keytab entry: %s' % e
            )

    @accepts(Dict(
        'keytab_data',
        Str('name', required=True),
    ))
    @returns(Ref('kerberos_keytab_entry'))
    @job(lock='upload_keytab', pipes=['input'], check_pipes=True)
    async def upload_keytab(self, job, data):
        """
        Upload a keytab file. This method expects the keytab file to be uploaded using
        the /_upload/ endpoint.
        """
        ktmem = io.BytesIO()
        await self.middleware.run_in_thread(shutil.copyfileobj, job.pipes.input.r, ktmem)
        b64kt = base64.b64encode(ktmem.getvalue())
        return await self.middleware.call('kerberos.keytab.create',
                                          {'name': data['name'], 'file': b64kt.decode()})

    @private
    async def legacy_validate(self, keytab):
        err = await self._validate({'file': keytab})
        try:
            err.check()
        except Exception as e:
            raise CallError(e)

    @private
    async def _cleanup_kerberos_principals(self):
        principal_choices = await self.middleware.call('kerberos.keytab.kerberos_principal_choices')
        ad = await self.middleware.call('activedirectory.config')
        ldap = await self.middleware.call('ldap.config')
        if ad['kerberos_principal'] and ad['kerberos_principal'] not in principal_choices:
            await self.middleware.call('activedirectory.update', {'kerberos_principal': ''})
        if ldap['kerberos_principal'] and ldap['kerberos_principal'] not in principal_choices:
            await self.middleware.call('ldap.update', {'kerberos_principal': ''})

    @private
    async def do_ktutil_list(self, data):
        kt = data.get("kt_name", keytab.SYSTEM.value)
        ktutil = await run(["klist", "-tek", kt], check=False)
        if ktutil.returncode != 0:
            raise CallError(ktutil.stderr.decode())
        ret = ktutil.stdout.decode().splitlines()
        if len(ret) < 4:
            return []

        return '\n'.join(ret[3:])

    @private
    async def _validate(self, data):
        """
        For now validation is limited to checking if we can resolve the hostnames
        configured for the kdc, admin_server, and kpasswd_server can be resolved
        by DNS, and if the realm can be resolved by DNS.
        """
        verrors = ValidationErrors()
        try:
            decoded = base64.b64decode(data['file'])
        except Exception as e:
            verrors.add("kerberos.keytab_create", f"Keytab is a not a properly base64-encoded string: [{e}]")
            return verrors

        with open(keytab['TEST'].value, "wb") as f:
            f.write(decoded)

        try:
            await self.do_ktutil_list({"kt_name": keytab['TEST'].value})
        except CallError as e:
            verrors.add("kerberos.keytab_create", f"Failed to validate keytab: [{e.errmsg}]")

        os.unlink(keytab['TEST'].value)

        return verrors

    @private
    async def _ktutil_list(self, keytab_file=keytab['SYSTEM'].value):
        keytab_entries = []
        try:
            kt_list_output = await self.do_ktutil_list({"kt_name": keytab_file})
        except Exception as e:
            self.logger.warning("Failed to list kerberos keytab [%s]: %s",
                                keytab_file, e)
            kt_list_output = None

        if not kt_list_output:
            return keytab_entries

        for idx, line in enumerate(kt_list_output.splitlines()):
            fields = line.split()
            keytab_entries.append({
                'slot': idx + 1,
                'kvno': int(fields[0]),
                'principal': fields[3],
                'etype': fields[4][1:-1].strip('DEPRECATED:'),
                'etype_deprecated': fields[4][1:].startswith('DEPRECATED'),
                'date': time.strptime(fields[1], '%m/%d/%y'),
            })

        return keytab_entries

    @accepts()
    @returns(List(
        'system-keytab',
        items=[
            Dict(
                'keytab-entry',
                Int('slot'),
                Int('kvno'),
                Str('principal'),
                Str('etype'),
                Bool('etype_deprecated'),
                Datetime('date')
            )
        ]
    ))
    async def system_keytab_list(self):
        """
        Returns content of system keytab (/etc/krb5.keytab).
        """
        kt_list = await self._ktutil_list()
        parsed = []
        for entry in kt_list:
            entry['date'] = time.mktime(entry['date'])
            parsed.append(entry)

        return parsed

    @private
    async def _get_nonsamba_principals(self, keytab_list):
        """
        Generate list of Kerberos principals that are not the AD machine account.
        """
        ad = await self.middleware.call('activedirectory.config')
        return filter_list(keytab_list, [['principal', 'Crnin', ad['netbiosname']]])

    @private
    async def _generate_tmp_keytab(self):
        """
        Generate a temporary keytab to separate out the machine account keytab principal.
        ktutil copy returns 1 even if copy succeeds.
        """
        with contextlib.suppress(OSError):
            os.remove(keytab['SAMBA'].value)

        kt_copy = await Popen(['ktutil'],
                              stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE,
                              stdin=subprocess.PIPE)
        output = await kt_copy.communicate(
            f'rkt {keytab.SYSTEM.value}\nwkt {keytab.SAMBA.value}\nq\n'.encode()
        )
        if output[1]:
            raise CallError(f"failed to generate [{keytab['SAMBA'].value}]: {output[1].decode()}")

    @private
    async def _prune_keytab_principals(self, to_delete=[]):
        """
        Delete all keytab entries from the tmp keytab that are not samba entries.
        The pruned keytab must be written to a new file to avoid duplication of
        entries.
        """
        rkt = f"rkt {keytab.SAMBA.value}"
        wkt = "wkt /var/db/system/samba4/samba_mit.keytab"
        delents = "\n".join(f"delent {x['slot']}" for x in reversed(to_delete))
        ktutil_remove = await Popen(['ktutil'],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    stdin=subprocess.PIPE)
        output = await ktutil_remove.communicate(
            f'{rkt}\n{delents}\n{wkt}\nq\n'.encode()
        )
        if output[1]:
            raise CallError(output[1].decode())

        with contextlib.suppress(OSError):
            os.remove(keytab.SAMBA.value)

        os.rename("/var/db/system/samba4/samba_mit.keytab", keytab.SAMBA.value)

    @private
    async def kerberos_principal_choices(self):
        """
        Keytabs typically have multiple entries for same principal (differentiated by enc_type).
        Since the enctype isn't relevant in this situation, only show unique principal names.

        Return empty list if system keytab doesn't exist.
        """
        if not os.path.exists(keytab['SYSTEM'].value):
            return []

        try:
            keytab_list = await self._ktutil_list()
        except Exception as e:
            self.logger.trace('"ktutil list" failed. Generating empty list of kerberos principal choices. Error: %s' % e)
            return []

        kerberos_principals = []
        for entry in keytab_list:
            if entry['principal'] not in kerberos_principals:
                kerberos_principals.append(entry['principal'])

        return sorted(kerberos_principals)

    @private
    async def has_nfs_principal(self):
        """
        This method checks whether the kerberos keytab contains an nfs service principal
        """
        principals = await self.kerberos_principal_choices()
        for p in principals:
            if p.startswith("nfs/"):
                return True

        return False

    @private
    async def store_samba_keytab(self):
        """
        Samba will automatically generate system keytab entries for the AD machine account
        (netbios name with '$' appended), and maintain them through machine account password changes.

        Copy the system keytab, parse it, and update the corresponding keytab entry in the freenas configuration
        database.

        The current system kerberos keytab and compare with a cached copy before overwriting it when a new
        keytab is generated through middleware 'etc.generate kerberos'.
        """
        if not os.path.exists(keytab['SYSTEM'].value):
            return False

        encoded_keytab = None
        keytab_list = await self._ktutil_list()
        items_to_remove = await self._get_nonsamba_principals(keytab_list)
        await self._generate_tmp_keytab()
        await self._prune_keytab_principals(items_to_remove)
        with open(keytab['SAMBA'].value, 'rb') as f:
            encoded_keytab = base64.b64encode(f.read())

        if not encoded_keytab:
            self.logger.debug(f"Failed to generate b64encoded version of {keytab['SAMBA'].name}")
            return False

        keytab_file = encoded_keytab.decode()
        entry = await self.query([('name', '=', 'AD_MACHINE_ACCOUNT')])
        if not entry:
            await self.middleware.call(
                'datastore.insert', self._config.datastore,
                {'name': 'AD_MACHINE_ACCOUNT', 'file': keytab_file},
                {'prefix': self._config.datastore_prefix}
            )
        else:
            await self.middleware.call(
                'datastore.update', self._config.datastore, entry[0]['id'],
                {'name': 'AD_MACHINE_ACCOUNT', 'file': keytab_file},
                {'prefix': self._config.datastore_prefix}
            )

        return True

    @periodic(3600)
    @private
    async def check_updated_keytab(self):
        """
        Check mtime of current kerberos keytab. If it has changed since last check,
        assume that samba has updated it behind the scenes and that the configuration
        database needs to be updated to reflect the change.
        """
        if not await self.middleware.call('system.ready'):
            return

        old_mtime = 0
        ad_state = await self.middleware.call('activedirectory.get_state')
        if ad_state == 'DISABLED' or not os.path.exists(keytab['SYSTEM'].value):
            return

        if await self.middleware.call('cache.has_key', 'KEYTAB_MTIME'):
            old_mtime = await self.middleware.call('cache.get', 'KEYTAB_MTIME')

        new_mtime = (os.stat(keytab['SYSTEM'].value)).st_mtime
        if old_mtime == new_mtime:
            return

        ts = await self.middleware.call('directoryservices.get_last_password_change')
        if ts['dbconfig'] == ts['secrets']:
            return

        self.logger.debug("Machine account password has changed. Stored copies of "
                          "kerberos keytab and directory services secrets will now "
                          "be updated.")

        await self.middleware.call('directoryservices.secrets.backup')
        await self.store_samba_keytab()
        self.logger.trace('Updating stored AD machine account kerberos keytab')
        await self.middleware.call(
            'cache.put',
            'KEYTAB_MTIME',
            (os.stat(keytab['SYSTEM'].value)).st_mtime
        )
