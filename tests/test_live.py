"""Live tests: every operation of the fortigatev2 connector against a real
FortiGate (see .env.live). Run with ``pytest --live``.

Each resource family runs a create -> read -> update -> delete lifecycle through
the connector, and every write is verified independently by reading the object
back over plain REST (tests/fgt_rest.py). Everything created is named
``fsrtest-<run>-*`` (or uses RFC 5737 / RFC 3849 documentation addresses) and is
purged before and after the session, so a failed run never leaves debris.

Firewall policies are created with ``status disable`` and the application /
web-filter profiles are fresh test profiles that no policy references, so the
suite never changes what traffic the FortiGate passes.
"""
import copy
import itertools
import time
import uuid

import pytest
from connectors.core.connector import ConnectorError

from fortigatev2.connector import FortiGate
from fortigatev2.operation import check_health
from tests.fgt_rest import POLICY_ID_BASE, PREFIX

pytestmark = pytest.mark.live

RUN = uuid.uuid4().hex[:6]
_policy_ids = itertools.count(POLICY_ID_BASE)


def policy_id():
    return next(_policy_ids)


def name(suffix):
    return '{}{}-{}'.format(PREFIX, RUN, suffix)


def run(config, operation, params=None):
    """Dispatch exactly the way FortiSOAR does: Connector.execute()."""
    return FortiGate().execute(copy.deepcopy(config), operation, copy.deepcopy(params or {}))


@pytest.fixture(scope='session', autouse=True)
def purge(fgt):
    fgt.purge_test_objects()
    yield
    fgt.purge_test_objects()


@pytest.fixture(scope='session')
def interfaces(fgt):
    names = [i['name'] for i in fgt.results('cmdb/system/interface') if i.get('vdom') == fgt.vdom]
    physical = [i['name'] for i in fgt.results('cmdb/system/interface')
                if i.get('vdom') == fgt.vdom and i.get('type') in ('physical', 'aggregate', 'vlan')]
    src = physical[0]
    dst = physical[1] if len(physical) > 1 else names[0]
    return src, dst


# --------------------------------------------------------------------------- health / misc
class TestHealthAndLookups:
    def test_check_health(self, live_config):
        assert check_health(live_config) is True

    def test_check_health_bad_key(self, live_config):
        with pytest.raises(ConnectorError) as err:
            check_health(dict(live_config, api_key='not-a-real-key'))
        assert 'Unauthorized' in str(err.value) or '401' in str(err.value)

    def test_check_health_url_profile_without_table(self, live_config, fgt):
        """Regression: a web-filter profile with no URL filter table attached
        (urlfilter-table 0, the factory 'default') used to 404 the health check."""
        profile = name('wf-hc')
        fgt.post('cmdb/webfilter/profile', {'name': profile})
        assert fgt.results('cmdb/webfilter/profile/' + profile)[0]['web']['urlfilter-table'] == 0
        assert check_health(dict(live_config, url_block_policy=profile)) is True

    def test_get_country_names(self, live_config):
        countries = run(live_config, 'get_country_names')
        assert 'Canada' in countries and len(countries) > 200

    def test_get_system_events(self, live_config):
        res = run(live_config, 'get_system_events', {'location': 'Memory', 'rows': '5', 'start': '0'})
        assert res['status'] == 'success'
        assert len(res['results']) <= 5
        # the 'system' event log also carries other event subtypes (e.g. security-rating)
        assert all(r['type'] == 'event' for r in res['results'])

    def test_get_system_events_filter(self, live_config):
        res = run(live_config, 'get_system_events', {'location': 'Memory', 'rows': '20',
                                                     'filter': 'level=="notice"'})
        assert res['status'] == 'success'
        assert res['results'], 'expected at least one notice-level system event'
        assert all(r['level'] == 'notice' for r in res['results'])

    def test_get_user_list_login_details(self, live_config):
        res = run(live_config, 'get_user_list_login_details', {'username': 'admin'})
        # either a log row for the admin login, or the explicit not-found envelope
        assert res.get('logdesc') == 'Admin login successful' or res.get('message') == 'Login details not found'


# --------------------------------------------------------------------------- addresses
class TestAddresses:
    def test_ipv4_subnet_lifecycle(self, live_config, fgt):
        addr = name('net4')
        run(live_config, 'create_address', {'address_category': 'IPv4 Address', 'name': addr, 'type': 'Subnet',
                                            'subnet': '192.0.2.10', 'comment': 'fsr test',
                                            'allow-routing': 'Enable'})
        obj = fgt.results('cmdb/firewall/address/' + addr)[0]
        assert obj['subnet'] == '192.0.2.10 255.255.255.255'
        assert obj['comment'] == 'fsr test' and obj['allow-routing'] == 'enable'

        got = run(live_config, 'get_addresses', {'address_category': 'IPv4 Address', 'name': addr})
        assert got['results'][0]['name'] == addr
        listed = run(live_config, 'get_addresses', {'address_category': 'IPv4 Address'})
        assert addr in [a['name'] for a in listed['results']]

        run(live_config, 'update_address', {'address_category': 'IPv4 Address', 'name': addr, 'type': 'Subnet',
                                            'subnet': '192.0.2.11', 'comment': 'updated',
                                            'new_name': addr + '-r'})
        obj = fgt.results('cmdb/firewall/address/' + addr + '-r')[0]
        assert obj['subnet'] == '192.0.2.11 255.255.255.255' and obj['comment'] == 'updated'

        run(live_config, 'delete_address', {'address_category': 'IPv4 Address', 'name': addr + '-r'})
        assert not fgt.exists('cmdb/firewall/address/' + addr + '-r')

    def test_ipv4_subnet_with_prefix(self, live_config, fgt):
        """A CIDR subnet (the natural input for a 'Subnet' address) must be accepted."""
        addr = name('cidr4')
        run(live_config, 'create_address', {'address_category': 'IPv4 Address', 'name': addr, 'type': 'Subnet',
                                            'subnet': '192.0.2.0/28'})
        assert fgt.results('cmdb/firewall/address/' + addr)[0]['subnet'] == '192.0.2.0 255.255.255.240'

    def test_ipv4_iprange_lifecycle(self, live_config, fgt):
        addr = name('range4')
        run(live_config, 'create_address', {'address_category': 'IPv4 Address', 'name': addr, 'type': 'IP Range',
                                            'start_ip': '192.0.2.20', 'end_ip': '192.0.2.29'})
        obj = fgt.results('cmdb/firewall/address/' + addr)[0]
        assert (obj['type'], obj['start-ip'], obj['end-ip']) == ('iprange', '192.0.2.20', '192.0.2.29')
        # update_address's IP Range fields are named start-ip / end-ip in info.json
        run(live_config, 'update_address', {'address_category': 'IPv4 Address', 'name': addr, 'type': 'IP Range',
                                            'start-ip': '192.0.2.30', 'end-ip': '192.0.2.39'})
        obj = fgt.results('cmdb/firewall/address/' + addr)[0]
        assert (obj['start-ip'], obj['end-ip']) == ('192.0.2.30', '192.0.2.39')

    def test_ipv4_fqdn(self, live_config, fgt):
        addr = name('fqdn4')
        run(live_config, 'create_address', {'address_category': 'IPv4 Address', 'name': addr, 'type': 'FQDN',
                                            'fqdn': 'fsrtest.example.com'})
        obj = fgt.results('cmdb/firewall/address/' + addr)[0]
        assert (obj['type'], obj['fqdn']) == ('fqdn', 'fsrtest.example.com')
        run(live_config, 'update_address', {'address_category': 'IPv4 Address', 'name': addr, 'type': 'FQDN',
                                            'fqdn': 'fsrtest2.example.com'})
        assert fgt.results('cmdb/firewall/address/' + addr)[0]['fqdn'] == 'fsrtest2.example.com'

    def test_ipv4_geography(self, live_config, fgt):
        addr = name('geo4')
        run(live_config, 'create_address', {'address_category': 'IPv4 Address', 'name': addr, 'type': 'Geography',
                                            'country': 'Canada'})
        obj = fgt.results('cmdb/firewall/address/' + addr)[0]
        assert (obj['type'], obj['country']) == ('geography', 'CA')

    def test_ipv4_mac_single_and_range(self, live_config, fgt):
        single, rng = name('mac1'), name('macr')
        run(live_config, 'create_address', {'address_category': 'IPv4 Address', 'name': single,
                                            'type': 'Device (MAC Address)', 'scope': 'Single Address',
                                            'mac_addrs': '02:00:5e:10:00:01'})
        assert fgt.results('cmdb/firewall/address/' + single)[0]['macaddr'][0]['macaddr'] == '02:00:5e:10:00:01'
        run(live_config, 'create_address', {'address_category': 'IPv4 Address', 'name': rng,
                                            'type': 'Device (MAC Address)', 'scope': 'Address Range',
                                            'start_mac': '02:00:5e:10:00:10', 'end_mac': '02:00:5e:10:00:1f'})
        assert fgt.results('cmdb/firewall/address/' + rng)[0]['macaddr'][0]['macaddr'] == \
            '02:00:5e:10:00:10-02:00:5e:10:00:1f'

    def test_update_mac_range(self, live_config, fgt):
        """update_address's info.json names the MAC range fields start-mac / end-mac."""
        addr = name('macu')
        fgt.post('cmdb/firewall/address', {'name': addr, 'type': 'mac', 'macaddr': [{'macaddr': '02:00:5e:10:00:01'}]})
        run(live_config, 'update_address', {'address_category': 'IPv4 Address', 'name': addr,
                                            'type': 'Device (MAC Address)', 'scope': 'Address Range',
                                            'start-mac': '02:00:5e:10:00:20', 'end-mac': '02:00:5e:10:00:2f'})
        assert fgt.results('cmdb/firewall/address/' + addr)[0]['macaddr'][0]['macaddr'] == \
            '02:00:5e:10:00:20-02:00:5e:10:00:2f'

    def test_ipv6_lifecycle(self, live_config, fgt):
        addr = name('net6')
        run(live_config, 'create_address', {'address_category': 'IPv6 Address', 'name': addr,
                                            'type': 'IPv6 Subnet', 'subnet': '2001:db8:10::/64'})
        assert fgt.results('cmdb/firewall/address6/' + addr)[0]['ip6'] == '2001:db8:10::/64'
        got = run(live_config, 'get_addresses', {'address_category': 'IPv6 Address', 'name': addr})
        assert got['results'][0]['name'] == addr
        run(live_config, 'update_address', {'address_category': 'IPv6 Address', 'name': addr,
                                            'type': 'IPv6 Subnet', 'subnet': '2001:db8:11::/64',
                                            'comment': 'v6 updated'})
        obj = fgt.results('cmdb/firewall/address6/' + addr)[0]
        assert obj['ip6'] == '2001:db8:11::/64' and obj['comment'] == 'v6 updated'
        run(live_config, 'delete_address', {'address_category': 'IPv6 Address', 'name': addr})
        assert not fgt.exists('cmdb/firewall/address6/' + addr)

    def test_ipv6_range_fqdn_geo(self, live_config, fgt):
        run(live_config, 'create_address', {'address_category': 'IPv6 Address', 'name': name('range6'),
                                            'type': 'IPv6 Range', 'start_ip': '2001:db8::1',
                                            'end_ip': '2001:db8::ff'})
        obj = fgt.results('cmdb/firewall/address6/' + name('range6'))[0]
        assert (obj['type'], obj['start-ip'], obj['end-ip']) == ('iprange', '2001:db8::1', '2001:db8::ff')
        run(live_config, 'create_address', {'address_category': 'IPv6 Address', 'name': name('fqdn6'),
                                            'type': 'IPv6 FQDN', 'fqdn': 'fsrtest6.example.com'})
        assert fgt.results('cmdb/firewall/address6/' + name('fqdn6'))[0]['fqdn'] == 'fsrtest6.example.com'
        run(live_config, 'create_address', {'address_category': 'IPv6 Address', 'name': name('geo6'),
                                            'type': 'IPv6 Geography', 'country': 'Canada'})
        assert fgt.results('cmdb/firewall/address6/' + name('geo6'))[0]['country'] == 'CA'

    def test_delete_address_default_category(self, live_config, fgt):
        """info.json defaults address_category to 'IPv4' for delete_address -- a
        playbook that keeps the default must still delete the IPv4 object."""
        addr = name('dflt4')
        fgt.post('cmdb/firewall/address', {'name': addr, 'subnet': '192.0.2.40/32'})
        run(live_config, 'delete_address', {'address_category': 'IPv4', 'name': addr})
        assert not fgt.exists('cmdb/firewall/address/' + addr)

    def test_create_duplicate_address_errors(self, live_config, fgt):
        addr = name('dup4')
        fgt.post('cmdb/firewall/address', {'name': addr, 'subnet': '192.0.2.41/32'})
        with pytest.raises(ConnectorError) as err:
            run(live_config, 'create_address', {'address_category': 'IPv4 Address', 'name': addr,
                                                'type': 'Subnet', 'subnet': '192.0.2.41'})
        assert 'already exists' in str(err.value)

    def test_name_with_space_and_slash(self, live_config, fgt):
        """Names are escaped as a single REST path segment."""
        addr = name('sp ace/24')
        run(live_config, 'create_address', {'address_category': 'IPv4 Address', 'name': addr, 'type': 'Subnet',
                                            'subnet': '192.0.2.64/28'})
        got = run(live_config, 'get_addresses', {'address_category': 'IPv4 Address', 'name': addr})
        assert got['results'][0]['name'] == addr
        run(live_config, 'update_address', {'address_category': 'IPv4 Address', 'name': addr, 'type': 'Subnet',
                                            'subnet': '192.0.2.80/28', 'comment': 'escaped'})
        assert fgt.results('cmdb/firewall/address/' + fgt.key(addr))[0]['comment'] == 'escaped'
        run(live_config, 'delete_address', {'address_category': 'IPv4 Address', 'name': addr})
        assert not fgt.exists('cmdb/firewall/address/' + fgt.key(addr))

    def test_get_missing_address_errors(self, live_config):
        with pytest.raises(ConnectorError) as err:
            run(live_config, 'get_addresses', {'address_category': 'IPv4 Address', 'name': name('nope')})
        assert 'not found' in str(err.value)


# --------------------------------------------------------------------------- address groups
class TestAddressGroups:
    @pytest.fixture(scope='class')
    def members(self, fgt):
        names = [name('gm1'), name('gm2'), name('gm3')]
        for i, n in enumerate(names):
            fgt.post('cmdb/firewall/address', {'name': n, 'subnet': '198.51.100.{}/32'.format(50 + i)})
        fgt.post('cmdb/firewall/address6', {'name': name('gm6a'), 'ip6': '2001:db8:50::1/128'})
        fgt.post('cmdb/firewall/address6', {'name': name('gm6b'), 'ip6': '2001:db8:50::2/128'})
        return names

    def test_ipv4_group_lifecycle(self, live_config, fgt, members):
        grp = name('grp4')
        run(live_config, 'create_address_group', {'address_group_category': 'IPv4 Group', 'group_name': grp,
                                                  'member': '{}, {}'.format(members[0], members[1]),
                                                  'type': 'Group', 'comment': 'grp test'})
        obj = fgt.results('cmdb/firewall/addrgrp/' + grp)[0]
        assert {m['name'] for m in obj['member']} == {members[0], members[1]}
        assert obj['comment'] == 'grp test'

        got = run(live_config, 'get_address_groups', {'address_group_category': 'IPv4 Group', 'group_name': grp})
        assert got['results'][0]['name'] == grp
        listed = run(live_config, 'get_address_groups', {'address_group_category': 'IPv4 Group'})
        assert grp in [g['name'] for g in listed['results']]

        run(live_config, 'update_address_group', {'address_group_category': 'IPv4 Group', 'group_name': grp,
                                                  'add_member': members[2], 'remove_member': members[0],
                                                  'comment': 'grp updated'})
        obj = fgt.results('cmdb/firewall/addrgrp/' + grp)[0]
        assert {m['name'] for m in obj['member']} == {members[1], members[2]}
        assert obj['comment'] == 'grp updated'

        run(live_config, 'update_address_group', {'address_group_category': 'IPv4 Group', 'group_name': grp,
                                                  'new_group_name': grp + '-r'})
        assert fgt.exists('cmdb/firewall/addrgrp/' + grp + '-r')

        run(live_config, 'delete_address_group', {'address_group_category': 'IPv4 Group',
                                                  'group_name': grp + '-r'})
        assert not fgt.exists('cmdb/firewall/addrgrp/' + grp + '-r')

    def test_ipv4_group_exclude(self, live_config, fgt, members):
        grp = name('grpx')
        run(live_config, 'create_address_group', {'address_group_category': 'IPv4 Group', 'group_name': grp,
                                                  'member': 'all', 'exclude': True,
                                                  'exclude_member': members[0]})
        obj = fgt.results('cmdb/firewall/addrgrp/' + grp)[0]
        assert obj['exclude'] == 'enable'
        assert [m['name'] for m in obj['exclude-member']] == [members[0]]
        run(live_config, 'update_address_group', {'address_group_category': 'IPv4 Group', 'group_name': grp,
                                                  'exclude': True, 'add_exclude_member': members[1],
                                                  'remove_exclude_member': members[0]})
        obj = fgt.results('cmdb/firewall/addrgrp/' + grp)[0]
        assert [m['name'] for m in obj['exclude-member']] == [members[1]]

    def test_ipv6_group_lifecycle(self, live_config, fgt, members):
        grp = name('grp6')
        run(live_config, 'create_address_group', {'address_group_category': 'IPv6 Group', 'group_name': grp,
                                                  'member': name('gm6a')})
        assert [m['name'] for m in fgt.results('cmdb/firewall/addrgrp6/' + grp)[0]['member']] == [name('gm6a')]
        got = run(live_config, 'get_address_groups', {'address_group_category': 'IPv6 Group', 'group_name': grp})
        assert got['results'][0]['name'] == grp
        run(live_config, 'update_address_group', {'address_group_category': 'IPv6 Group', 'group_name': grp,
                                                  'add_member': name('gm6b')})
        assert {m['name'] for m in fgt.results('cmdb/firewall/addrgrp6/' + grp)[0]['member']} == \
            {name('gm6a'), name('gm6b')}
        run(live_config, 'delete_address_group', {'address_group_category': 'IPv6 Group', 'group_name': grp})
        assert not fgt.exists('cmdb/firewall/addrgrp6/' + grp)

    def test_delete_group_default_category(self, live_config, fgt, members):
        """delete_address_group's info.json default is 'IPv4' (not an option value)."""
        grp = name('grpd')
        fgt.post('cmdb/firewall/addrgrp', {'name': grp, 'member': [{'name': members[0]}]})
        run(live_config, 'delete_address_group', {'address_group_category': 'IPv4', 'group_name': grp})
        assert not fgt.exists('cmdb/firewall/addrgrp/' + grp)


# --------------------------------------------------------------------------- services
class TestServices:
    def test_service_lifecycle(self, live_config, fgt):
        svc = name('svc')
        run(live_config, 'create_firewall_service', {'name': svc, 'protocol': 'TCP/UDP/SCTP',
                                                     'tcp_portrange': '8443', 'comment': 'svc test',
                                                     'category': 'General', 'visibility': 'Enable'})
        obj = fgt.results('cmdb/firewall.service/custom/' + svc)[0]
        assert obj['protocol'].startswith('TCP/UDP') and (obj['tcp-portrange'], obj['comment']) == ('8443', 'svc test')

        got = run(live_config, 'get_firewall_services', {'name': svc})
        assert got['results'][0]['name'] == svc
        listed = run(live_config, 'get_firewall_services', {})
        assert svc in [s['name'] for s in listed['results']]

        run(live_config, 'update_firewall_service', {'name': svc, 'protocol': 'TCP/UDP/SCTP',
                                                     'tcp_portrange': '8443 9443', 'udp_portrange': '5353',
                                                     'new_name': svc + '-r'})
        obj = fgt.results('cmdb/firewall.service/custom/' + svc + '-r')[0]
        assert (obj['tcp-portrange'], obj['udp-portrange']) == ('8443 9443', '5353')

        run(live_config, 'delete_firewall_service', {'name': svc + '-r'})
        assert not fgt.exists('cmdb/firewall.service/custom/' + svc + '-r')

    def test_default_protocol_all(self, live_config, fgt):
        """5.4.0 playbooks carry the old info.json default protocol 'All' (FortiOS only knows 'ALL'):
        create must still work, and an update must not reset the service's protocol/ports."""
        svc_all, svc_tcp = name('svcall'), name('svctcp')
        run(live_config, 'create_firewall_service', {'name': svc_all, 'protocol': 'All'})
        # FortiOS accepts protocol ALL over REST but stores its default TCP/UDP protocol
        assert fgt.exists('cmdb/firewall.service/custom/' + svc_all)
        fgt.post('cmdb/firewall.service/custom', {'name': svc_tcp, 'tcp-portrange': '8443'})
        run(live_config, 'update_firewall_service', {'name': svc_tcp, 'protocol': 'All', 'comment': 'only comment'})
        obj = fgt.results('cmdb/firewall.service/custom/' + svc_tcp)[0]
        assert obj['protocol'].startswith('TCP/UDP') and obj['tcp-portrange'] == '8443'
        assert obj['comment'] == 'only comment'

    def test_service_icmp_and_ip(self, live_config, fgt):
        run(live_config, 'create_firewall_service', {'name': name('icmp'), 'protocol': 'ICMP',
                                                     'icmptype': 8, 'icmpcode': 0})
        obj = fgt.results('cmdb/firewall.service/custom/' + name('icmp'))[0]
        assert (obj['protocol'], obj['icmptype']) == ('ICMP', 8)
        run(live_config, 'create_firewall_service', {'name': name('ipproto'), 'protocol': 'IP',
                                                     'protocol-number': 47})
        obj = fgt.results('cmdb/firewall.service/custom/' + name('ipproto'))[0]
        assert (obj['protocol'], obj['protocol-number']) == ('IP', 47)

    def test_service_iprange(self, live_config, fgt):
        run(live_config, 'create_firewall_service', {'name': name('svcrng'), 'protocol': 'TCP/UDP/SCTP',
                                                     'address': 'IP Range', 'iprange': '192.0.2.1-192.0.2.9',
                                                     'tcp_portrange': '22'})
        assert fgt.results('cmdb/firewall.service/custom/' + name('svcrng'))[0]['iprange'] == \
            '192.0.2.1-192.0.2.9'

    def test_service_group_lifecycle(self, live_config, fgt):
        svc, grp = name('gsvc'), name('sgrp')
        fgt.post('cmdb/firewall.service/custom', {'name': svc, 'tcp-portrange': '8080'})
        run(live_config, 'create_service_group', {'name': grp, 'members': '{}, HTTP'.format(svc),
                                                  'comment': 'sg test'})
        obj = fgt.results('cmdb/firewall.service/group/' + grp)[0]
        assert {m['name'] for m in obj['member']} == {svc, 'HTTP'} and obj['comment'] == 'sg test'

        got = run(live_config, 'get_service_groups', {'name': grp})
        assert got['results'][0]['name'] == grp
        listed = run(live_config, 'get_service_groups', {})
        assert grp in [g['name'] for g in listed['results']]

        run(live_config, 'update_service_group', {'name': grp, 'add_member': 'HTTPS', 'remove_member': 'HTTP',
                                                  'comment': 'sg updated', 'new_name': grp + '-r'})
        obj = fgt.results('cmdb/firewall.service/group/' + grp + '-r')[0]
        assert {m['name'] for m in obj['member']} == {svc, 'HTTPS'} and obj['comment'] == 'sg updated'

        run(live_config, 'delete_service_group', {'name': grp + '-r'})
        assert not fgt.exists('cmdb/firewall.service/group/' + grp + '-r')


# --------------------------------------------------------------------------- policies
class TestPolicies:
    @pytest.fixture(scope='class')
    def addr(self, fgt):
        fgt.post('cmdb/firewall/address', {'name': name('pol-src'), 'subnet': '192.0.2.60/32'})
        fgt.post('cmdb/firewall/address', {'name': name('pol-src2'), 'subnet': '192.0.2.61/32'})
        return name('pol-src'), name('pol-src2')

    def _policy_by_name(self, fgt, policy_name):
        hits = [p for p in fgt.results('cmdb/firewall/policy') if p.get('name') == policy_name]
        return hits[0] if hits else None

    def test_policy_lifecycle(self, live_config, fgt, interfaces, addr):
        pname = name('pol')[:35]
        res = run(live_config, 'create_policy', {
            'name': pname, 'srcintf': interfaces[0], 'dstintf': interfaces[1], 'srcaddr': addr[0],
            'dstaddr': 'all', 'service': 'HTTP, HTTPS', 'schedule': 'always', 'status': 'Disable',
            'action': 'Accept', 'logtraffic': 'All', 'comment': 'created by fsr test',
            'additional_args': {'policyid': policy_id()}})
        policyid = res['mkey']
        obj = fgt.results('cmdb/firewall/policy/{}'.format(policyid))[0]
        assert obj['name'] == pname and obj['status'] == 'disable' and obj['action'] == 'accept'
        assert {s['name'] for s in obj['service']} == {'HTTP', 'HTTPS'}
        assert obj['comments'] == 'created by fsr test'

        one = run(live_config, 'get_list_of_policies', {'policyid': str(policyid)})
        assert one['results'][0]['name'] == pname
        listed = run(live_config, 'get_list_of_policies', {})
        assert pname in [p['name'] for r in listed['result'] for p in r['results']]

        run(live_config, 'update_policy', {'policyid': str(policyid), 'add_srcaddr': addr[1],
                                           'remove_srcaddr': addr[0], 'remove_service': 'HTTP',
                                           'action': 'Deny', 'comment': 'updated by fsr test'})
        obj = fgt.results('cmdb/firewall/policy/{}'.format(policyid))[0]
        assert [a['name'] for a in obj['srcaddr']] == [addr[1]]
        assert [s['name'] for s in obj['service']] == ['HTTPS']
        assert obj['action'] == 'deny' and obj['comments'] == 'updated by fsr test'
        assert obj['status'] == 'disable'

        run(live_config, 'delete_policy', {'policyid': str(policyid)})
        assert not fgt.exists('cmdb/firewall/policy/{}'.format(policyid))

    def test_policy_with_security_profile_and_nat(self, live_config, fgt, interfaces, addr):
        pname = name('polsp')[:35]
        res = run(live_config, 'create_policy', {
            'name': pname, 'srcintf': interfaces[0], 'dstintf': interfaces[1], 'srcaddr': addr[0],
            'dstaddr': 'all', 'service': 'ALL', 'schedule': 'always', 'status': 'Disable', 'action': 'Accept',
            'inspection_mode': 'Flow Based', 'nat': True, 'ip_pool_config': 'Use Outgoing Interface Address',
            'security_profile_name': ['Application Control'], 'application_list': 'default',
            'additional_args': {'logtraffic-start': 'enable', 'policyid': policy_id()}})
        obj = fgt.results('cmdb/firewall/policy/{}'.format(res['mkey']))[0]
        assert obj['nat'] == 'enable' and obj['application-list'] == 'default'
        assert obj['logtraffic-start'] == 'enable'

        run(live_config, 'update_policy', {'policyid': str(res['mkey']),
                                           'security_profile_names_to_disable': ['Application Control']})
        assert fgt.results('cmdb/firewall/policy/{}'.format(res['mkey']))[0]['application-list'] == ''

    def test_policy_minimal_params_from_playbook(self, live_config, fgt, interfaces, addr):
        """FortiSOAR sends unset optional fields as None -- e.g. security_profile_name."""
        pname = name('polnull')[:35]
        res = run(live_config, 'create_policy', {
            'name': pname, 'srcintf': interfaces[0], 'dstintf': interfaces[1], 'srcaddr': addr[0],
            'dstaddr': 'all', 'service': 'ALL', 'schedule': 'always', 'status': 'Disable', 'action': 'Deny',
            'security_profile_name': None, 'comment': None, 'nat': None, 'logtraffic': None,
            'additional_args': {'policyid': policy_id()}})
        assert fgt.exists('cmdb/firewall/policy/{}'.format(res['mkey']))

    def test_get_missing_policy_errors(self, live_config):
        with pytest.raises(ConnectorError) as err:
            run(live_config, 'get_list_of_policies', {'policyid': '999999'})
        assert 'not found' in str(err.value)


# --------------------------------------------------------------------------- IP blocking
class TestQuarantineBasedIPBlock:
    IPS = ['198.51.100.10', '198.51.100.11']

    def test_block_get_unblock(self, live_config, fgt):
        res = run(live_config, 'block_ip_new', {'method': 'Quarantine Based', 'ip_addresses': ', '.join(self.IPS),
                                                'time_to_live': 'Custom Time', 'duration': 600})
        assert sorted(res['newly_blocked']) == self.IPS and not res['error_with_block']
        banned = {b['ip_address'] for b in fgt.results('monitor/user/banned/select')}
        assert set(self.IPS) <= banned

        again = run(live_config, 'block_ip_new', {'method': 'Quarantine Based', 'ip_addresses': self.IPS[0],
                                                  'time_to_live': '1 Hour'})
        assert again['already_blocked'] == [self.IPS[0]]

        listed = run(live_config, 'get_blocked_ip', {'method': 'Quarantine Based'})
        assert set(self.IPS) <= {b['ip_address'] for r in listed['result'] for b in r['results']}

        res = run(live_config, 'unblock_ip', {'method': 'Quarantine Based', 'ip_addresses': self.IPS})
        assert sorted(res['newly_unblocked']) == self.IPS
        assert not set(self.IPS) & {b['ip_address'] for b in fgt.results('monitor/user/banned/select')}

        missing = run(live_config, 'unblock_ip', {'method': 'Quarantine Based', 'ip_addresses': self.IPS[0]})
        assert missing['ip_not_exist'] == [self.IPS[0]]

    def test_deprecated_block_ip(self, live_config, fgt):
        ip = '198.51.100.12'
        res = run(live_config, 'block_ip', {'method': 'Quarantine Based', 'ip_addresses': ip,
                                            'time_to_live': '1 Hour'})
        assert res['newly_blocked'] == [ip]
        run(live_config, 'unblock_ip', {'method': 'Quarantine Based', 'ip_addresses': ip})

    def test_invalid_ip_rejected(self, live_config):
        with pytest.raises(ConnectorError):
            run(live_config, 'block_ip_new', {'method': 'Quarantine Based', 'ip_addresses': 'not-an-ip',
                                              'time_to_live': '1 Hour'})


class TestPolicyBasedIPBlock:
    @pytest.fixture(scope='class')
    def block_policy(self, fgt, interfaces):
        seed4, seed6 = name('seed4'), name('seed6')
        grp4, grp6 = name('blk4'), name('blk6')
        fgt.post('cmdb/firewall/address', {'name': seed4, 'subnet': '192.0.2.250/32'})
        fgt.post('cmdb/firewall/address6', {'name': seed6, 'ip6': '2001:db8:ff::250/128'})
        fgt.post('cmdb/firewall/addrgrp', {'name': grp4, 'member': [{'name': seed4}]})
        fgt.post('cmdb/firewall/addrgrp6', {'name': grp6, 'member': [{'name': seed6}]})
        pname = name('blkpol')[:35]
        fgt.post('cmdb/firewall/policy', {
            'policyid': policy_id(), 'name': pname, 'status': 'disable', 'action': 'deny', 'schedule': 'always',
            'srcintf': [{'name': interfaces[0]}], 'dstintf': [{'name': interfaces[1]}],
            'srcaddr': [{'name': grp4}], 'dstaddr': [{'name': 'all'}],
            'srcaddr6': [{'name': grp6}], 'dstaddr6': [{'name': 'all'}], 'service': [{'name': 'ALL'}]})
        return {'policy': pname, 'grp4': grp4, 'grp6': grp6, 'seed4': seed4}

    def _members(self, fgt, path):
        return {m['name'] for m in fgt.results(path)[0]['member']}

    @pytest.mark.parametrize('is_new', [True, False])
    def test_ipv4_block_get_unblock(self, live_config, fgt, block_policy, is_new):
        ips = ['192.0.2.{}'.format(70 + int(is_new)), '192.0.2.{}'.format(80 + int(is_new))]
        grp_path = 'cmdb/firewall/addrgrp/' + block_policy['grp4']
        res = run(live_config, 'block_ip_new', {'method': 'Policy Based', 'ip_block_policy': block_policy['policy'],
                                                'ip_type': 'IPv4', 'ip_group_name': block_policy['grp4'],
                                                'ip': ', '.join(ips), 'is_new': is_new,
                                                'ngfw_mode': 'Profile Based'})
        assert sorted(res['newly_blocked']) == sorted(ips) and not res['error_with_block']
        assert set(ips) <= self._members(fgt, grp_path)
        assert block_policy['seed4'] in self._members(fgt, grp_path), 'existing members must be kept'

        listed = run(live_config, 'get_blocked_ip', {'method': 'Policy Based',
                                                     'ip_block_policy': block_policy['policy'],
                                                     'ip_group_name': block_policy['grp4']})
        assert set(ips) <= set(listed['addrgrp'][0]['member'])

        again = run(live_config, 'block_ip_new', {'method': 'Policy Based',
                                                  'ip_block_policy': block_policy['policy'], 'ip_type': 'IPv4',
                                                  'ip_group_name': block_policy['grp4'], 'ip': ips[0] + ', 192.0.2.99',
                                                  'is_new': is_new})
        assert again['already_blocked'] == [ips[0]]
        ips.append('192.0.2.99')

        res = run(live_config, 'unblock_ip', {'method': 'Policy Based', 'ip_block_policy': block_policy['policy'],
                                              'ip_type': 'IPv4', 'ip_group_name': block_policy['grp4'],
                                              'ip': ', '.join(ips)})
        assert sorted(res['newly_unblocked']) == sorted(ips)
        assert not set(ips) & self._members(fgt, grp_path)
        assert block_policy['seed4'] in self._members(fgt, grp_path)
        # unblock also removes the per-IP address objects it created
        assert not any(fgt.exists('cmdb/firewall/address/' + ip) for ip in ips)

    def test_ipv6_block_unblock(self, live_config, fgt, block_policy):
        ip = '2001:db8:ff::70'
        grp_path = 'cmdb/firewall/addrgrp6/' + block_policy['grp6']
        res = run(live_config, 'block_ip_new', {'method': 'Policy Based', 'ip_block_policy': block_policy['policy'],
                                                'ip_type': 'IPv6', 'ip_group_name': block_policy['grp6'],
                                                'ip': ip, 'is_new': True})
        assert res['newly_blocked'] == [ip]
        assert ip in self._members(fgt, grp_path)
        res = run(live_config, 'unblock_ip', {'method': 'Policy Based', 'ip_block_policy': block_policy['policy'],
                                              'ip_type': 'IPv6', 'ip_group_name': block_policy['grp6'], 'ip': ip})
        assert res['newly_unblocked'] == [ip]
        assert ip not in self._members(fgt, grp_path)

    def test_group_not_in_policy_errors(self, live_config, fgt, block_policy):
        with pytest.raises(ConnectorError) as err:
            run(live_config, 'block_ip_new', {'method': 'Policy Based', 'ip_block_policy': block_policy['policy'],
                                              'ip_type': 'IPv4', 'ip_group_name': name('nogrp'),
                                              'ip': '192.0.2.77', 'is_new': True})
        assert 'not exist' in str(err.value)

    def test_accept_policy_rejected(self, live_config, fgt, interfaces, block_policy):
        pname = name('acc')[:35]
        fgt.post('cmdb/firewall/policy', {
            'policyid': policy_id(), 'name': pname, 'status': 'disable', 'action': 'accept', 'schedule': 'always',
            'srcintf': [{'name': interfaces[0]}], 'dstintf': [{'name': interfaces[1]}],
            'srcaddr': [{'name': block_policy['grp4']}], 'dstaddr': [{'name': 'all'}], 'service': [{'name': 'ALL'}]})
        with pytest.raises(ConnectorError) as err:
            run(live_config, 'block_ip_new', {'method': 'Policy Based', 'ip_block_policy': pname, 'ip_type': 'IPv4',
                                              'ip_group_name': block_policy['grp4'], 'ip': '192.0.2.78',
                                              'is_new': True})
        assert 'deny' in str(err.value)


# --------------------------------------------------------------------------- applications
class TestApplications:
    APPS = ['BitTorrent', 'Telegram']

    @pytest.fixture(scope='class')
    def app_config(self, live_config, fgt):
        profile = name('app')
        # first entry is the block rule, second a catch-all pass (same shape as factory 'block-high-risk')
        fgt.post('cmdb/application/list', {'name': profile, 'entries': [
            {'id': 1, 'action': 'block', 'application': [], 'category': [{'id': 2}]},
            {'id': 2, 'action': 'pass'}]})
        return dict(live_config, app_block_policy=profile)

    def _blocked_ids(self, fgt, profile):
        entries = fgt.results('cmdb/application/list/' + profile)[0]['entries']
        return {a['id'] for e in entries if e['action'] == 'block' for a in e['application']}

    def test_get_list_of_applications(self, live_config):
        res = run(live_config, 'get_list_of_applications')
        names = {a['name'] for a in res['results']}
        assert set(self.APPS) <= names

    def test_block_get_unblock(self, app_config, fgt):
        apps = run(app_config, 'get_list_of_applications')['results']
        ids = {a['name']: a['id'] for a in apps if a['name'] in self.APPS}

        res = run(app_config, 'block_applications', {'app_list': ', '.join(self.APPS)})
        assert all(r['status'] == 'Successful' for r in res), res
        assert set(ids.values()) <= self._blocked_ids(fgt, app_config['app_block_policy'])

        again = run(app_config, 'block_applications', {'app_list': self.APPS[0]})
        assert again[0]['message'] == 'Application already blocked'

        blocked = run(app_config, 'get_blocked_applications')
        assert set(self.APPS) <= {a['name'] for a in blocked}

        res = run(app_config, 'unblock_applications', {'app_list': ', '.join(self.APPS)})
        assert all(r['message'] == 'Application unblock successfully' for r in res), res
        assert not set(ids.values()) & self._blocked_ids(fgt, app_config['app_block_policy'])

    def test_unknown_application(self, app_config):
        res = run(app_config, 'block_applications', {'app_list': 'NoSuchApp-fsrtest'})
        assert res == [{'message': 'Application not found in Fortinet FortiGate database', 'status': 'Failed',
                        'name': 'NoSuchApp-fsrtest'}]

    def test_block_lands_in_block_entry(self, live_config, fgt):
        """When the first entry of the profile is NOT a block rule, the app must
        still end up in a block rule -- never silently in a pass/monitor rule."""
        profile = name('apppass')
        fgt.post('cmdb/application/list', {'name': profile, 'entries': [
            {'id': 1, 'action': 'pass', 'category': [{'id': 2}]},
            {'id': 2, 'action': 'block', 'category': [{'id': 6}]}]})
        cfg = dict(live_config, app_block_policy=profile)
        run(cfg, 'block_applications', {'app_list': self.APPS[0]})
        blocked = run(cfg, 'get_blocked_applications')
        assert self.APPS[0] in {a['name'] for a in blocked}

    def test_profile_not_configured(self, live_config):
        with pytest.raises(ConnectorError) as err:
            run(live_config, 'get_blocked_applications')
        assert 'not defined' in str(err.value)


# --------------------------------------------------------------------------- URLs
class TestURLs:
    @pytest.fixture(scope='class')
    def url_config(self, live_config, fgt):
        profile = name('wf')
        fgt.post('cmdb/webfilter/profile', {'name': profile})   # no URL filter table attached yet
        return dict(live_config, url_block_policy=profile)

    def _entries(self, fgt, profile):
        table = fgt.results('cmdb/webfilter/profile/' + profile)[0]['web']['urlfilter-table']
        return fgt.results('cmdb/webfilter/urlfilter/{}'.format(table))[0]['entries'] if table else []

    def test_empty_profile(self, url_config):
        assert run(url_config, 'get_blocked_urls') == []

    def test_block_get_unblock(self, url_config, fgt):
        profile = url_config['url_block_policy']
        urls = ['fsrtest-bad.example.com', 'fsrtest-worse.example.com/path']
        res = run(url_config, 'block_url', {'url': ', '.join(urls)})
        assert sorted(res['newly_blocked']) == sorted(urls)
        assert {e['url'] for e in self._entries(fgt, profile) if e['action'] == 'block'} == set(urls)

        again = run(url_config, 'block_url', {'url': urls[0] + ', fsrtest-third.example.com'})
        assert again['already_blocked'] == [urls[0]] and again['newly_blocked'] == ['fsrtest-third.example.com']
        urls.append('fsrtest-third.example.com')

        blocked = run(url_config, 'get_blocked_urls')
        assert {b['url'] for b in blocked} == set(urls)

        res = run(url_config, 'unblock_url', {'url': ', '.join(urls[:2]) + ', fsrtest-never.example.com'})
        assert sorted(res['newly_unblocked']) == sorted(urls[:2])
        assert res['not_exist'] == ['fsrtest-never.example.com']
        assert {e['url'] for e in self._entries(fgt, profile)} == {urls[2]}

    def test_unblock_on_profile_without_table(self, live_config, fgt):
        profile = name('wf2')
        fgt.post('cmdb/webfilter/profile', {'name': profile})
        res = run(dict(live_config, url_block_policy=profile), 'unblock_url', {'url': 'fsrtest.example.com'})
        assert res['not_exist'] == ['fsrtest.example.com']

    def test_profile_not_configured(self, live_config):
        with pytest.raises(ConnectorError) as err:
            run(live_config, 'get_blocked_urls')
        assert 'not defined' in str(err.value)

    def test_unknown_profile(self, live_config):
        with pytest.raises(ConnectorError) as err:
            run(dict(live_config, url_block_policy=name('nope')), 'get_blocked_urls')
        assert 'not found' in str(err.value)


# --------------------------------------------------------------------------- quarantine hosts
class TestQuarantineHosts:
    MACS = ['02:00:5e:fe:00:01', '02:00:5e:fe:00:02']

    def _quarantined(self, fgt):
        return {m['mac'] for t in fgt.get('cmdb/user/quarantine')['results']['targets'] for m in t['macs']}

    def test_quarantine_get_unquarantine(self, live_config, fgt):
        res = run(live_config, 'quarantine_host', {'macs': ', '.join(self.MACS)})
        assert sorted(res['newly_quarantine']) == self.MACS and not res['not_quarantine']
        assert set(self.MACS) <= self._quarantined(fgt)

        again = run(live_config, 'quarantine_host', {'macs': self.MACS[0]})
        assert again['already_quarantine'] == [self.MACS[0]]

        listed = run(live_config, 'get_quarantine_hosts')
        assert set(self.MACS) <= {m['mac'] for t in listed['results']['targets'] for m in t['macs']}

        res = run(live_config, 'unquarantine_host', {'macs': self.MACS[0]})
        assert res['newly_unquarantine'] == [self.MACS[0]]
        assert self._quarantined(fgt) & set(self.MACS) == {self.MACS[1]}

        res = run(live_config, 'unquarantine_host', {'macs': self.MACS[1] + ', 02:00:5e:fe:00:99'})
        assert res['newly_unquarantine'] == [self.MACS[1]] and res['not_exist'] == ['02:00:5e:fe:00:99']
        assert not self._quarantined(fgt) & set(self.MACS)

    def test_invalid_mac(self, live_config, fgt):
        res = run(live_config, 'quarantine_host', {'macs': 'zz:zz'})
        assert res['not_quarantine'] == ['zz:zz'] and res['newly_quarantine'] == []


# --------------------------------------------------------------------------- users
class TestUsers:
    @pytest.fixture(scope='class')
    def groups(self, fgt):
        g1, g2 = name('ug1'), name('ug2')
        fgt.post('cmdb/user/group', {'name': g1, 'group-type': 'firewall'})
        fgt.post('cmdb/user/group', {'name': g2, 'group-type': 'firewall'})
        return g1, g2

    def _group_members(self, fgt, group):
        return {m['name'] for m in fgt.results('cmdb/user/group/' + group)[0]['member']}

    def test_user_lifecycle(self, live_config, fgt, groups):
        user = name('user')
        run(live_config, 'create_user', {'user_type': 'Local User', 'name': user, 'passwd': 'Fsr-Test-Pw-1!',
                                         'status': 'Enable', 'email-to': 'fsrtest@example.com',
                                         'user_group': 'Enable', 'user_group_name': groups[0]})
        obj = fgt.results('cmdb/user/local/' + user)[0]
        assert (obj['type'], obj['status'], obj['email-to']) == ('password', 'enable', 'fsrtest@example.com')
        assert user in self._group_members(fgt, groups[0])

        got = run(live_config, 'get_users', {'name': user})
        assert got['results'][0]['name'] == user
        listed = run(live_config, 'get_users', {'start': 0, 'count': 1000})
        assert user in [u['name'] for u in listed['results']]

        run(live_config, 'update_user', {'user_type': 'Local User', 'name': user, 'status': 'Disable',
                                         'user_group_name': groups[1], 'user_group_name_to_remove': groups[0]})
        assert fgt.results('cmdb/user/local/' + user)[0]['status'] == 'disable'
        assert user in self._group_members(fgt, groups[1])
        assert user not in self._group_members(fgt, groups[0])

        # FortiOS refuses to delete a user that is still a group member (-23)
        with pytest.raises(ConnectorError) as err:
            run(live_config, 'delete_user', {'name': user})
        assert 'used by other' in str(err.value)
        run(live_config, 'update_user', {'user_type': 'Local User', 'name': user,
                                         'user_group_name_to_remove': groups[1]})
        run(live_config, 'delete_user', {'name': user})
        assert not fgt.exists('cmdb/user/local/' + user)

    def test_update_user_minimal_params_from_playbook(self, live_config, fgt):
        """FortiSOAR sends unset text fields as None/''. Only a status change requested."""
        user = name('user2')
        fgt.post('cmdb/user/local', {'name': user, 'type': 'password', 'passwd': 'Fsr-Test-Pw-1!'})
        run(live_config, 'update_user', {'user_type': 'Local User', 'name': user, 'new_username': None,
                                         'passwd': None, 'status': 'Disable', 'user_group_name': None,
                                         'user_group_name_to_remove': None, 'two-factor': None})
        assert fgt.results('cmdb/user/local/' + user)[0]['status'] == 'disable'

    def test_rename_user(self, live_config, fgt):
        user = name('user3')
        fgt.post('cmdb/user/local', {'name': user, 'type': 'password', 'passwd': 'Fsr-Test-Pw-1!'})
        run(live_config, 'update_user', {'user_type': 'Local User', 'name': user, 'new_username': user + '-r',
                                         'user_group_name': '', 'user_group_name_to_remove': ''})
        assert fgt.exists('cmdb/user/local/' + user + '-r')
        assert not fgt.exists('cmdb/user/local/' + user)

    def test_activation_code_requires_contact(self, live_config, fgt):
        user = name('user4')
        with pytest.raises(ConnectorError) as err:
            run(live_config, 'create_user', {'user_type': 'Local User', 'name': user, 'passwd': 'Fsr-Test-Pw-1!',
                                             'send_activation_code': 'Enable', 'activation_method': 'Email'})
        assert 'Email address is required' in str(err.value)


# --------------------------------------------------------------------------- external dynamic lists
class TestEDL:
    @pytest.fixture(scope='class')
    def edl(self, fgt):
        edl = name('edl')
        fgt.post('cmdb/system/external-resource', {'name': edl, 'type': 'address', 'update-method': 'push',
                                                   'resource': ''})
        # a new push list rejects updates ("External resource has not been loaded") for ~10s
        for _ in range(20):
            res = fgt.post('monitor/system/external-resource/dynamic',
                           {'commands': [{'name': edl, 'command': 'snapshot', 'entries': []}]})
            if res['results'][0]['status'] == 'success':
                return edl
            time.sleep(2)
        pytest.fail('external resource {} never finished loading'.format(edl))

    @staticmethod
    def _wait_entries(live_config, edl, predicate):
        """Pushed entries show up in entry-list a few seconds after the push."""
        for _ in range(15):
            got = run(live_config, 'get_entries_from_edl', {'mkey': edl})
            entries = {e['entry'] for e in got['results'].get('entries', [])}
            if predicate(entries):
                return entries
            time.sleep(2)
        raise AssertionError('EDL entries never matched; last seen {}'.format(entries))

    def test_modify_and_get(self, live_config, edl):
        entries = ['192.0.2.120', '192.0.2.121', '192.0.2.128/30']
        res = run(live_config, 'modify_entries_in_edl', {'mkey': edl, 'action': 'Add', 'entries': entries})
        assert res['status'] == 'success' and res['results'][0]['status'] == 'success'
        self._wait_entries(live_config, edl, lambda seen: set(entries) <= seen)

        counts = run(live_config, 'get_entries_from_edl', {'mkey': edl, 'counts_only': True})
        assert counts['results']['valid_count'] == 3

        run(live_config, 'modify_entries_in_edl', {'mkey': edl, 'action': 'Remove', 'entries': entries[0]})
        self._wait_entries(live_config, edl, lambda seen: seen == set(entries[1:]))

        run(live_config, 'modify_entries_in_edl', {'mkey': edl, 'action': 'Snapshot', 'entries': '192.0.2.200'})
        self._wait_entries(live_config, edl, lambda seen: seen == {'192.0.2.200'})

    def test_status_only(self, live_config, edl):
        res = run(live_config, 'get_entries_from_edl', {'mkey': edl, 'status_only': True})
        assert res['status'] == 'success'

    def test_unknown_edl(self, live_config):
        with pytest.raises(ConnectorError):
            run(live_config, 'modify_entries_in_edl', {'mkey': name('nope'), 'action': 'Add',
                                                       'entries': '192.0.2.1'})


# --------------------------------------------------------------------------- CLI over SSH
class TestExecuteCommand:
    @pytest.fixture
    def ssh(self, env):
        if not env.get('FGT_SSH_USER'):
            pytest.skip('FGT_SSH_USER / FGT_SSH_PASSWORD / FGT_SSH_PORT not set (.env.live)')
        return {'username': env['FGT_SSH_USER'], 'password': env.get('FGT_SSH_PASSWORD'),
                'port': int(env.get('FGT_SSH_PORT', 22)), 'timeout': 30}

    def test_non_interactive(self, live_config, ssh):
        res = run(live_config, 'execute_command', dict(ssh, cmd_list='get system status'))
        assert res[0]['command'] == 'get system status'
        assert any('Version' in line for line in res[0]['output'])

    def test_interactive(self, live_config, ssh):
        res = run(live_config, 'execute_command', dict(ssh, interactive=True,
                                                       cmd_list=['config system global', 'show', 'end']))
        assert [r['command'] for r in res] == ['config system global', 'show', 'end']

    def test_bad_command(self, live_config, ssh):
        with pytest.raises(ConnectorError):
            run(live_config, 'execute_command', dict(ssh, cmd_list='get nosuch thing'))
