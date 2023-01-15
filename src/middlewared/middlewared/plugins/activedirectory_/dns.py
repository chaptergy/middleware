import dns
import enum
import errno
import ipaddress
import socket

from middlewared.service import CallError, private, Service


class SRV(enum.Enum):
    DOMAINCONTROLLER = '_ldap._tcp.dc._msdcs.'
    FORESTGLOBALCATALOG = '_ldap._tcp.gc._msdcs.'
    GLOBALCATALOG = '_gc._tcp.'
    KERBEROS = '_kerberos._tcp.'
    KERBEROSDOMAINCONTROLLER = '_kerberos._tcp.dc._msdcs.'
    KPASSWD = '_kpasswd._tcp.'
    LDAP = '_ldap._tcp.'
    PDC = '_ldap._tcp.pdc._msdcs.'


class ActiveDirectoryService(Service):

    class Config:
        service = "activedirectory"

    @private
    async def unregister_dns(self, ad):
        if not ad['allow_dns_updates']:
            return

        netbiosname = (await self.middleware.call('smb.config'))['netbiosname_local']
        domain = ad['domainname']

        hostname = f'{netbiosname}.{domain}'
        try:
            dns_addresses = set([x['address'] for x in await self.middleware.call('dnsclient.forward_lookup', {
                'names': [hostname]
            })])
        except dns.resolver.NXDOMAIN:
            self.logger.warning(
                f'DNS lookup of {hostname}. failed with NXDOMAIN. '
                'This may indicate that DNS entries for the computer account have already been deleted; '
                'however, it may also indicate the presence of larger underlying DNS configuration issues.'
            )
            return

        ips_in_use = set([x['address'] for x in await self.middleware.call('interface.ip_in_use')])
        if not dns_addresses & ips_in_use:
            # raise a CallError here because we don't want someone fat-fingering
            # input and removing an unrelated computer in the domain.
            raise CallError(
                f'DNS records indicate that {hostname} may be associated '
                'with a different computer in the domain. Forward lookup returned the '
                f'following results: {", ".join(dns_addresses)}.'
            )

        payload = []

        for ip in dns_addresses:
            addr = ipaddress.ip_address(ip)
            payload.append({
                'command': 'DELETE',
                'name': hostname,
                'address': str(addr),
                'type': 'A' if addr.version == 4 else 'AAAA'
            })

        try:
            await self.middleware.call('dns.nsupdate', {'ops': payload})
        except CallError as e:
            self.logger.warning(f'Failed to update DNS with payload [{payload}]: {e.errmsg}')

    @private
    async def register_dns(self, ad, smb, smb_ha_mode):
        if not ad['allow_dns_updates']:
            return

        await self.middleware.call('kerberos.check_ticket')

        hostname = f'{smb["netbiosname_local"]}.{ad["domainname"]}.'
        if smb_ha_mode == 'CLUSTERED':
            vips = (await self.middleware.call('smb.bindip_choices')).values()
        else:
            vips = [i['address'] for i in (await self.middleware.call('interface.ip_in_use'))]

        smb_bind_ips = smb['bindip'] if smb['bindip'] else vips
        to_register = set(vips) & set(smb_bind_ips)

        hostname = f'{smb["netbiosname_local"]}.{ad["domainname"]}.'

        payload = []

        for ip in to_register:
            addr = ipaddress.ip_address(ip)
            payload.append({
                'command': 'ADD',
                'name': hostname,
                'address': str(addr),
                'type': 'A' if addr.version == 4 else 'AAAA'
            })

        try:
            await self.middleware.call('dns.nsupdate', {'ops': payload})
        except CallError as e:
            self.logger.warning(f'Failed to update DNS with payload [{payload}]: {e.errmsg}')

    @private
    def port_is_listening(self, host, port, timeout=1):
        ret = False

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if timeout:
            s.settimeout(timeout)

        try:
            s.connect((host, port))
            ret = True

        except Exception as e:
            self.logger.debug("connection to %s failed with error: %s",
                              host, e)
            ret = False

        finally:
            s.close()

        return ret

    @private
    async def check_nameservers(self, domain, site=None):
        def get_host(srv_prefix):
            if site and site != 'Default-First-Site-Name':
                if 'msdcs' in srv_prefix.value:
                    parts = srv_prefix.value.split('.')
                    srv = '.'.join([parts[0], parts[1]])
                    msdcs = '.'.join([parts[2], parts[3]])
                    return f"{srv}.{site}._sites.{msdcs}.{domain}"

                else:
                    return f"{srv_prefix.value}{site}._sites.{domain}."

            return f"{srv_prefix.value}{domain}."

        targets = [get_host(srv_record) for srv_record in [
            SRV.DOMAINCONTROLLER,
            SRV.GLOBALCATALOG,
            SRV.KERBEROS,
            SRV.KERBEROSDOMAINCONTROLLER,
            SRV.KPASSWD,
            SRV.LDAP,
            SRV.PDC
        ]]

        for entry in await self.middleware.call('dns.query'):
            try:
                servers = await self.middleware.call('dnsclient.forward_lookup', {
                    'names': targets,
                    'record_type': 'SRV',
                    'dns_client_options': {'nameservers': [entry['nameserver']]},
                    'query-options': {'order_by': ['priority', 'weight']}
                })
            except dns.resolver.NXDOMAIN:
                raise CallError(
                    f'Nameserver {entry["nameserver"]} failed to resolve SRV records for domain {domain}. '
                    'This may indicate a DNS misconfiguration on the TrueNAS server.',
                    errno.EINVAL
                )

            for name in targets:
                if not any([lambda resp: resp['name'].casefold() == name.casefold(), servers]):
                    raise CallError(
                        f'Forward lookup of "{name}" failed with nameserver {entry["nameserver"]}. '
                        'This may indicate a DNS misconfiguration on the remote nameserver.',
                        errno.ENOENT
                    )

    @private
    def get_n_working_servers(self, domain, srv=SRV.DOMAINCONTROLLER.name, site=None, cnt=1, timeout=10, verbose=False):
        srv_prefix = SRV[srv]
        if site and site != 'Default-First-Site-Name':
            if 'msdcs' in srv_prefix.value:
                parts = srv_prefix.value.split('.')
                srv = '.'.join([parts[0], parts[1]])
                msdcs = '.'.join([parts[2], parts[3]])
                host = f"{srv}.{site}._sites.{msdcs}.{domain}"
            else:
                host = f"{srv_prefix.value}{site}._sites.{domain}."
        else:
            host = f"{srv_prefix.value}{domain}."

        servers = self.middleware.call_sync('dnsclient.forward_lookup', {
            'names': [host], 'record_type': 'SRV', 'query-options': {'order_by': ['priority', 'weight']}
        })

        output = []
        for server in servers:
            if len(output) == cnt:
                break

            if self.port_is_listening(server['target'], server['port'], timeout=timeout):
                output.append({'host': server['target'], 'port': server['port']})

        if verbose:
            self.logger.debug('Request for %d of server type [%s] returned: %s',
                              cnt, srv, output)

        return output

    @private
    async def netbiosname_is_ours(self, netbios_name, domain_name):
        try:
            dns_addresses = set([x['address'] for x in await self.middleware.call('dnsclient.forward_lookup', {
                'names': [f'{netbios_name}.{domain_name}']
            })])
        except dns.resolver.NXDOMAIN:
            raise CallError(f'DNS forward lookup of [{netbios_name}] failed.', errno.ENOENT)

        ips_in_use = set([x['address'] for x in await self.middleware.call('interface.ip_in_use')])

        return bool(dns_addresses & ips_in_use)