"""Offline tests: no FortiGate needed. FortiOS is mocked with `responses`, so these
pin the exact REST requests each operation makes plus the regressions found by the
live suite (tests/test_live.py).
"""
import json
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest
import requests
import responses
from connectors.core.connector import ConnectorError

from fortigatev2.connector import FortiGate
from fortigatev2.operation import check_health, fortigate_operations

BASE = 'https://fgt.example.com:443/api/v2/'
CONFIG = {'address': 'fgt.example.com', 'port': 443, 'api_key': 'k', 'vdom': 'root', 'verify_ssl': False,
          'url_block_policy': '', 'app_block_policy': ''}
VDOM = {'results': [{'name': 'root'}], 'matched_count': 1, 'status': 'success'}
OK = {'status': 'success', 'http_status': 200, 'mkey': 'x'}
INFO = json.loads((Path(__file__).resolve().parent.parent / 'fortigatev2' / 'info.json').read_text())


def run(operation, params=None, config=None):
    return FortiGate().execute(dict(config or CONFIG), operation, dict(params or {}))


def body(call):
    return json.loads(call.request.body) if call.request.body else None


_active = {}


def calls(method, fragment):
    return [c for c in _active['mock'].calls
            if c.request.method == method and fragment.lower() in c.request.url.lower()]


@pytest.fixture
def fgt():
    with responses.RequestsMock(assert_all_requests_are_fired=False) as mock:
        mock.get(BASE + 'cmdb/system/vdom', json=VDOM)
        _active['mock'] = mock
        yield mock


# --------------------------------------------------------------------------- metadata
def test_every_info_operation_is_implemented():
    declared = {op['operation'] for op in INFO['operations']}
    assert declared == set(fortigate_operations)


def test_select_defaults_are_valid_options():
    """A select's default must be one of its options; otherwise playbooks keep a value the
    code doesn't recognise (delete_address 'IPv4' used to hit the IPv6 table)."""
    bad = []

    def walk(op, params):
        for p in params:
            if p.get('type') == 'select' and p.get('value') not in (None, '') and p.get('options'):
                if p['value'] not in p['options']:
                    bad.append((op, p['name'], p['value']))
            for sub in (p.get('onchange') or {}).values():
                walk(op, sub)
    for op in INFO['operations']:
        walk(op['operation'], op['parameters'])
    assert bad == []


def test_no_duplicate_parameter_names_per_branch():
    dupes = []

    def walk(op, params):
        names = [p['name'] for p in params]
        dupes.extend((op, n) for n in set(names) if names.count(n) > 1)
        for p in params:
            for sub in (p.get('onchange') or {}).values():
                walk(op, sub)
    for op in INFO['operations']:
        walk(op['operation'], op['parameters'])
    assert dupes == []


# --------------------------------------------------------------------------- health / transport
def test_check_health_ok(fgt):
    fgt.get(BASE + 'cmdb/firewall/policy/', json={'results': [], 'status': 'success'})
    assert check_health(CONFIG) is True


def test_check_health_unauthorized(fgt):
    fgt.replace(responses.GET, BASE + 'cmdb/system/vdom', status=401, body='')
    with pytest.raises(ConnectorError) as err:
        check_health(CONFIG)
    assert 'Unauthorized' in str(err.value)


def test_check_health_unreachable():
    with responses.RequestsMock() as mock:
        mock.get(BASE + 'cmdb/system/vdom', body=requests.exceptions.ConnectionError('refused'))
        with pytest.raises(ConnectorError) as err:
            check_health(CONFIG)
    assert 'Invalid endpoint or credentials' in str(err.value)


def test_check_health_url_profile_without_table(fgt):
    """Regression: url_block_policy pointing at a profile with urlfilter-table 0 used to
    request webfilter/urlfilter/0 and fail the health check with a 404."""
    fgt.get(BASE + 'cmdb/firewall/policy/', json={'results': [], 'status': 'success'})
    fgt.get(BASE + 'cmdb/webfilter/profile', json={'results': [{'name': 'default', 'web': {'urlfilter-table': 0}}]})
    assert check_health(dict(CONFIG, url_block_policy='default')) is True
    assert not calls('GET', 'webfilter/urlfilter')


def test_default_header_not_shared_between_calls(fgt):
    fgt.get(BASE + 'cmdb/firewall/address/', json={'results': []})
    run('get_addresses', {}, dict(CONFIG, api_key='first'))
    run('get_addresses', {}, dict(CONFIG, api_key='second'))
    assert calls('GET', 'firewall/address')[-1].request.headers['Authorization'] == 'Bearer second'


# --------------------------------------------------------------------------- addresses
@pytest.mark.parametrize('subnet, sent', [('192.0.2.1', '192.0.2.1/32'), ('192.0.2.0/24', '192.0.2.0/24'),
                                          ('192.0.2.0 255.255.255.0', '192.0.2.0 255.255.255.0')])
def test_create_address_subnet_forms(fgt, subnet, sent):
    fgt.post(BASE + 'cmdb/firewall/address/', json=OK)
    run('create_address', {'address_category': 'IPv4 Address', 'name': 'a', 'type': 'Subnet', 'subnet': subnet})
    assert body(calls('POST', 'firewall/address')[0])['subnet'] == sent


def test_update_address_range_uses_info_json_names(fgt):
    fgt.put(BASE + 'cmdb/firewall/address/a', json=OK)
    run('update_address', {'address_category': 'IPv4 Address', 'name': 'a', 'type': 'IP Range',
                           'start-ip': '192.0.2.1', 'end-ip': '192.0.2.9'})
    sent = body(calls('PUT', 'firewall/address/a')[0])
    assert (sent['type'], sent['start-ip'], sent['end-ip']) == ('iprange', '192.0.2.1', '192.0.2.9')


def test_update_address_mac_range_uses_info_json_names(fgt):
    fgt.put(BASE + 'cmdb/firewall/address/a', json=OK)
    run('update_address', {'address_category': 'IPv4 Address', 'name': 'a', 'type': 'Device (MAC Address)',
                           'scope': 'Address Range', 'start-mac': '02:00:00:00:00:01', 'end-mac': '02:00:00:00:00:09'})
    assert body(calls('PUT', 'firewall/address/a')[0])['macaddr'] == [{'macaddr': '02:00:00:00:00:01-02:00:00:00:00:09'}]


@pytest.mark.parametrize('category, path', [('IPv4', 'firewall/address/'), ('IPv4 Address', 'firewall/address/'),
                                            ('IPv6 Address', 'firewall/address6/')])
def test_delete_address_category(fgt, category, path):
    fgt.delete(BASE + 'cmdb/' + path + 'a%2fb', json=OK)
    run('delete_address', {'address_category': category, 'name': 'a/b'})
    assert calls('DELETE', path + 'a%2fb')


@pytest.mark.parametrize('category, path', [('IPv4', 'firewall/addrgrp/'), ('IPv6 Group', 'firewall/addrgrp6/')])
def test_delete_address_group_category(fgt, category, path):
    fgt.delete(BASE + 'cmdb/' + path + 'g', json=OK)
    run('delete_address_group', {'address_group_category': category, 'group_name': 'g'})
    assert calls('DELETE', path + 'g')


def test_create_address_geography_maps_country_code(fgt):
    fgt.post(BASE + 'cmdb/firewall/address/', json=OK)
    run('create_address', {'address_category': 'IPv4 Address', 'name': 'a', 'type': 'Geography', 'country': 'Canada'})
    assert body(calls('POST', 'firewall/address')[0])['country'] == 'CA'


def test_update_address_group_merges_members(fgt):
    fgt.get(BASE + 'cmdb/firewall/addrgrp/g', json={'results': [{'name': 'g', 'member': [{'name': 'a'}, {'name': 'b'}]}]})
    fgt.put(BASE + 'cmdb/firewall/addrgrp/g', json=OK)
    run('update_address_group', {'address_group_category': 'IPv4 Group', 'group_name': 'g',
                                 'add_member': 'c', 'remove_member': 'a'})
    assert sorted(m['name'] for m in body(calls('PUT', 'addrgrp/g')[0])['member']) == ['b', 'c']


# --------------------------------------------------------------------------- policies
POLICY = {'name': 'p', 'srcintf': 'port1', 'dstintf': 'port2', 'srcaddr': 'a', 'dstaddr': 'all',
          'service': 'HTTP, HTTPS', 'schedule': 'always', 'status': 'Disable', 'action': 'Accept'}


def test_create_policy_body(fgt):
    fgt.post(BASE + 'cmdb/firewall/policy/', json=OK)
    run('create_policy', dict(POLICY, comment='hello', additional_args={'policyid': 9900}))
    sent = body(calls('POST', 'firewall/policy')[0])
    assert sent['comments'] == 'hello' and 'comment' not in sent
    assert sent['service'] == [{'name': 'HTTP'}, {'name': 'HTTPS'}]
    assert (sent['status'], sent['action'], sent['policyid']) == ('disable', 'accept', 9900)


def test_create_policy_null_optional_fields(fgt):
    """FortiSOAR sends unset optional fields as None (used to raise len(None))."""
    fgt.post(BASE + 'cmdb/firewall/policy/', json=OK)
    run('create_policy', dict(POLICY, security_profile_name=None, additional_args=None, comment=None, nat=None))
    sent = body(calls('POST', 'firewall/policy')[0])
    assert 'utm-status' not in sent and 'comments' not in sent


def test_create_policy_security_profile(fgt):
    fgt.post(BASE + 'cmdb/firewall/policy/', json=OK)
    run('create_policy', dict(POLICY, security_profile_name=['Application Control'], application_list='default'))
    sent = body(calls('POST', 'firewall/policy')[0])
    assert sent['utm-status'] == 'enable' and sent['application-list'] == {'q_origin_key': 'default'}


def test_update_policy_merges_addresses(fgt):
    fgt.get(BASE + 'cmdb/firewall/policy/7', json={'results': [
        {'srcaddr': [{'name': 'a'}], 'dstaddr': [{'name': 'all'}], 'service': [{'name': 'HTTP'}]}]})
    fgt.put(BASE + 'cmdb/firewall/policy/7', json=OK)
    run('update_policy', {'policyid': '7', 'add_srcaddr': 'b', 'remove_srcaddr': 'a', 'remove_service': 'HTTP',
                          'security_profile_names_to_disable': ['Web Filter']})
    sent = body(calls('PUT', 'firewall/policy/7')[0])
    assert sent['srcaddr'] == [{'name': 'b'}] and sent['service'] == [{'name': 'NONE'}]
    assert sent['webfilter-profile'] == ''


# --------------------------------------------------------------------------- services
SERVICE_SCHEMA = {'results': {'children': {'protocol': {'options': [
    {'name': 'TCP/UDP/UDP-Lite/SCTP'}, {'name': 'ICMP'}, {'name': 'IP'}, {'name': 'ALL'}]}}}}


@pytest.fixture
def service_api(fgt):
    fgt.get(BASE + 'cmdb/firewall.service/custom/', json=SERVICE_SCHEMA,
            match=[responses.matchers.query_param_matcher({'vdom': 'root', 'action': 'schema'})])
    fgt.post(BASE + 'cmdb/firewall.service/custom/', json=OK)
    fgt.put(BASE + 'cmdb/firewall.service/custom/s', json=OK)
    return fgt


def test_service_tcp_protocol_mapped_to_firmware_spelling(service_api):
    run('create_firewall_service', {'name': 's', 'protocol': 'TCP/UDP/SCTP', 'tcp_portrange': '8443'})
    assert body(calls('POST', 'firewall.service/custom')[0])['protocol'] == 'TCP/UDP/UDP-Lite/SCTP'


def test_service_legacy_tcp_kept_on_old_firmware(fgt):
    fgt.get(BASE + 'cmdb/firewall.service/custom/', json={'results': {'children': {'protocol': {'options': [
        {'name': 'TCP/UDP/SCTP'}, {'name': 'ICMP'}]}}}},
        match=[responses.matchers.query_param_matcher({'vdom': 'root', 'action': 'schema'})])
    fgt.post(BASE + 'cmdb/firewall.service/custom/', json=OK)
    run('create_firewall_service', {'name': 's', 'protocol': 'TCP/UDP/SCTP'})
    assert body(calls('POST', 'firewall.service/custom')[0])['protocol'] == 'TCP/UDP/SCTP'


def test_service_old_default_all(service_api):
    run('create_firewall_service', {'name': 's', 'protocol': 'All'})
    assert body(calls('POST', 'firewall.service/custom')[0])['protocol'] == 'ALL'
    run('update_firewall_service', {'name': 's', 'protocol': 'All', 'comment': 'c'})
    assert 'protocol' not in body(calls('PUT', 'firewall.service/custom/s')[0])


def test_service_icmp_fields_applied_after_protocol(service_api):
    run('create_firewall_service', {'name': 's', 'protocol': 'ICMP', 'icmptype': 8, 'icmpcode': 0})
    follow_up = body(calls('PUT', 'firewall.service/custom/s')[0])
    assert follow_up == {'icmptype': 8, 'icmpcode': 0}


def test_service_ip_protocol_number_applied_after_protocol(service_api):
    run('create_firewall_service', {'name': 's', 'protocol': 'IP', 'protocol-number': 47})
    assert body(calls('PUT', 'firewall.service/custom/s')[0]) == {'protocol-number': 47}


def test_service_group_update(fgt):
    fgt.get(BASE + 'cmdb/firewall.service/group/g', json={'results': [{'name': 'g', 'member': [{'name': 'HTTP'}]}]})
    fgt.put(BASE + 'cmdb/firewall.service/group/g', json=OK)
    run('update_service_group', {'name': 'g', 'remove_member': 'HTTP', 'new_name': 'g2'})
    sent = body(calls('PUT', 'service/group/g')[0])
    assert sent == {'name': 'g2', 'member': [{'name': 'NONE'}]}


# --------------------------------------------------------------------------- applications
APPS = {'results': [{'id': 1, 'name': 'BitTorrent'}, {'id': 2, 'name': 'Telegram'}]}


def _app_profile(entries):
    return {'status': 'success', 'results': [{'name': 'prof', 'entries': entries}]}


def test_block_application_goes_into_block_entry(fgt):
    fgt.get(BASE + 'cmdb/application/name', json=APPS)
    fgt.get(BASE + 'cmdb/application/list/prof', json=_app_profile([
        {'id': 1, 'q_origin_key': 1, 'action': 'pass', 'application': []},
        {'id': 2, 'q_origin_key': 2, 'action': 'block', 'application': []}]))
    fgt.put(BASE + 'cmdb/application/list/prof', json={'status': 'success'})
    run('block_applications', {'app_list': 'BitTorrent'}, dict(CONFIG, app_block_policy='prof'))
    entries = body(calls('PUT', 'application/list/prof')[0])['entries']
    assert entries[0]['application'] == [] and entries[1]['application'] == [{'id': 1, 'q_origin_key': 1}]


def test_block_application_creates_block_entry_when_none(fgt):
    fgt.get(BASE + 'cmdb/application/name', json=APPS)
    fgt.get(BASE + 'cmdb/application/list/prof', json=_app_profile([
        {'id': 1, 'q_origin_key': 1, 'action': 'pass', 'application': []}]))
    fgt.put(BASE + 'cmdb/application/list/prof', json={'status': 'success'})
    run('block_applications', {'app_list': 'Telegram'}, dict(CONFIG, app_block_policy='prof'))
    entries = body(calls('PUT', 'application/list/prof')[0])['entries']
    assert [(e['id'], e['action']) for e in entries] == [(1, 'block'), (2, 'pass')]
    assert entries[0]['application'] == [{'id': 2, 'q_origin_key': 2}]


def test_block_application_on_empty_profile(fgt):
    fgt.get(BASE + 'cmdb/application/name', json=APPS)
    fgt.get(BASE + 'cmdb/application/list/prof', json=_app_profile([]))
    fgt.put(BASE + 'cmdb/application/list/prof', json={'status': 'success'})
    res = run('block_applications', {'app_list': 'Telegram'}, dict(CONFIG, app_block_policy='prof'))
    assert res[0]['status'] == 'Successful'


def test_get_blocked_applications(fgt):
    fgt.get(BASE + 'cmdb/application/name', json=APPS)
    fgt.get(BASE + 'cmdb/application/list/prof', json=_app_profile([
        {'id': 1, 'action': 'block', 'application': [{'id': 2}]}, {'id': 2, 'action': 'pass', 'application': [{'id': 1}]}]))
    res = run('get_blocked_applications', {}, dict(CONFIG, app_block_policy='prof'))
    assert [a['name'] for a in res] == ['Telegram']


# --------------------------------------------------------------------------- URLs
def test_block_url_bootstraps_url_filter_table(fgt):
    fgt.get(BASE + 'cmdb/webfilter/profile', json={'results': [{'name': 'wf', 'web': {'urlfilter-table': 0}}]})
    fgt.post(BASE + 'cmdb/webfilter/urlfilter', json={'status': 'success', 'mkey': 5})
    fgt.put(BASE + 'cmdb/webfilter/profile/wf', json={'status': 'success'})
    res = run('block_url', {'url': 'bad.example.com'}, dict(CONFIG, url_block_policy='wf'))
    assert res['newly_blocked'] == ['bad.example.com']
    table = body(calls('POST', 'webfilter/urlfilter')[0])
    assert table['name'] == 'wf' and table['entries'][0]['url'] == 'bad.example.com'
    assert body(calls('PUT', 'webfilter/profile/wf')[0]) == {'web': {'urlfilter-table': 5}}


def test_block_url_appends_to_existing_table(fgt):
    fgt.get(BASE + 'cmdb/webfilter/profile', json={'results': [{'name': 'wf', 'web': {'urlfilter-table': 3}}]})
    fgt.get(BASE + 'cmdb/webfilter/urlfilter/3', json={'mkey': 3, 'results': [
        {'entries': [{'url': 'old.example.com', 'action': 'block'}]}]})
    fgt.put(BASE + 'cmdb/webfilter/urlfilter/3', json={'status': 'success'})
    res = run('block_url', {'url': 'old.example.com, new.example.com'}, dict(CONFIG, url_block_policy='wf'))
    assert res['already_blocked'] == ['old.example.com'] and res['newly_blocked'] == ['new.example.com']
    assert [e['url'] for e in body(calls('PUT', 'urlfilter/3')[0])['entries']] == ['old.example.com', 'new.example.com']


def test_unblock_url_without_table(fgt):
    fgt.get(BASE + 'cmdb/webfilter/profile', json={'results': [{'name': 'wf', 'web': {'urlfilter-table': 0}}]})
    res = run('unblock_url', {'url': 'x.example.com'}, dict(CONFIG, url_block_policy='wf'))
    assert res['not_exist'] == ['x.example.com'] and not calls('PUT', 'urlfilter')


# --------------------------------------------------------------------------- IP blocking / quarantine
def test_quarantine_block_ip_request(fgt):
    fgt.get(BASE + 'monitor/user/banned/select', json={'results': [], 'status': 'success'})
    fgt.post(BASE + 'monitor/user/banned/add_users', json={'status': 'success'})
    res = run('block_ip_new', {'method': 'Quarantine Based', 'ip_addresses': '198.51.100.1',
                               'time_to_live': 'Custom Time', 'duration': 300})
    assert res['newly_blocked'] == ['198.51.100.1']
    assert body(calls('POST', 'banned/add_users')[0]) == {'ip_addresses': ['198.51.100.1'], 'expiry': 300, 'src': 'ips'}


def test_block_ip_rejects_bad_ip(fgt):
    with pytest.raises(ConnectorError):
        run('block_ip_new', {'method': 'Quarantine Based', 'ip_addresses': 'nope', 'time_to_live': '1 Hour'})


def test_quarantine_host_invalid_mac_reported_flat(fgt):
    fgt.get(BASE + 'cmdb/user/quarantine', json={'results': {'targets': []}})
    fgt.put(BASE + 'cmdb/user/quarantine', json={'status': 'error'})
    res = run('quarantine_host', {'macs': '02:00:00:00:00:01, zz'})
    assert res['not_quarantine'] == ['zz', '02:00:00:00:00:01']


# --------------------------------------------------------------------------- users
def test_create_user_null_phone_and_cloud_token(fgt):
    fgt.post(BASE + 'cmdb/user/local/', json=OK)
    run('create_user', {'user_type': 'Local User', 'name': 'u', 'passwd': 'p', 'two-factor': 'Enable',
                        'auth_type': 'FortiToken Cloud', 'country_code': None, 'phone_number': None})
    sent = body(calls('POST', 'user/local')[0])
    assert sent['two-factor'] == 'fortitoken-cloud' and 'sms-phone' not in sent
    assert sent['type'] == 'password'


def test_update_user_sends_only_fortios_fields(fgt):
    fgt.put(BASE + 'cmdb/user/local/u', json=OK)
    run('update_user', {'user_type': 'Local User', 'name': 'u', 'new_username': None, 'status': 'Disable',
                        'user_group_name': None, 'user_group_name_to_remove': '', 'two-factor': None,
                        'vdom': None, 'sms': 'Enable', 'country_code': '+1', 'phone_number': '5550100'})
    assert body(calls('PUT', 'user/local/u')[0]) == {'name': 'u', 'status': 'disable', 'sms-phone': '+15550100'}


def test_update_user_rename_and_groups(fgt):
    fgt.put(BASE + 'cmdb/user/local/u', json=OK)
    fgt.get(BASE + 'cmdb/user/group/g1', json={'results': [{'name': 'g1', 'member': []}]})
    fgt.put(BASE + 'cmdb/user/group/g1', json=OK)
    run('update_user', {'user_type': 'Local User', 'name': 'u', 'new_username': 'u2', 'user_group_name': 'g1'})
    assert body(calls('PUT', 'user/local/u')[0])['name'] == 'u2'
    assert body(calls('PUT', 'user/group/g1')[0])['member'] == [{'name': 'u2'}]


def test_activation_code_needs_email(fgt):
    fgt.post(BASE + 'cmdb/user/local/', json=OK)
    with pytest.raises(ConnectorError) as err:
        run('create_user', {'user_type': 'Local User', 'name': 'u', 'passwd': 'p', 'send_activation_code': 'Enable',
                            'activation_method': 'Email'})
    assert 'Email address is required' in str(err.value)


# --------------------------------------------------------------------------- EDL / events / misc
def test_modify_edl_request(fgt):
    fgt.post(BASE + 'monitor/system/external-resource/dynamic',
             json={'status': 'success', 'results': [{'name': 'edl', 'status': 'success'}]})
    run('modify_entries_in_edl', {'mkey': 'edl', 'action': 'Add', 'entries': '192.0.2.1, 192.0.2.2'})
    assert body(calls('POST', 'external-resource/dynamic')[0]) == {
        'commands': [{'name': 'edl', 'command': 'add', 'entries': ['192.0.2.1', '192.0.2.2']}]}


def test_modify_edl_surfaces_per_command_error(fgt):
    fgt.post(BASE + 'monitor/system/external-resource/dynamic', json={'status': 'success', 'results': [
        {'name': 'edl', 'status': 'error', 'error': 'External resource has not been loaded.'}]})
    with pytest.raises(ConnectorError) as err:
        run('modify_entries_in_edl', {'mkey': 'edl', 'action': 'Add', 'entries': '192.0.2.1'})
    assert 'not been loaded' in str(err.value)


def test_get_edl_entries_query(fgt):
    fgt.get(BASE + 'monitor/system/external-resource/entry-list', json={'results': {'entries': []}})
    run('get_entries_from_edl', {'mkey': 'edl', 'counts_only': True, 'status_only': False})
    query = parse_qs(urlparse(calls('GET', 'entry-list')[0].request.url).query)
    assert query == {'mkey': ['edl'], 'counts_only': ['True'], 'vdom': ['root']}


def test_get_system_events_filter_encoding(fgt):
    fgt.get(BASE + 'log/memory/event/system', json={'results': [], 'percent_logs_processed': 100})
    run('get_system_events', {'location': 'Memory', 'rows': '5', 'filter': 'level=="notice"'})
    assert 'filter=level%3D%3D%22notice%22' in calls('GET', 'event/system')[0].request.url


def test_get_country_names():
    assert 'Canada' in run('get_country_names')


def test_unknown_operation_raises():
    with pytest.raises(ConnectorError):
        run('no_such_operation')


# --------------------------------------------------------------------------- path escaping
@pytest.mark.parametrize('operation, params, path', [
    ('get_users', {'name': 'a?b#c'}, 'cmdb/user/local/a%3Fb%23c'),
    ('delete_user', {'name': '../system/admin'}, 'cmdb/user/local/..%2Fsystem%2Fadmin'),
    ('get_address_groups', {'address_group_category': 'IPv4 Group', 'group_name': 'grp a/b'},
     'cmdb/firewall/addrgrp/grp%20a%2Fb'),
    ('delete_address', {'address_category': 'IPv4 Address', 'name': 'net 10/8'}, 'cmdb/firewall/address/net%2010%2F8'),
    ('get_firewall_services', {'name': 'svc?x'}, 'cmdb/firewall.service/custom/svc%3Fx'),
    ('delete_service_group', {'name': 'g#1'}, 'cmdb/firewall.service/group/g%231'),
    ('delete_policy', {'policyid': '7?x=1'}, 'cmdb/firewall/policy/7%3Fx%3D1'),
])
def test_names_are_escaped_as_one_path_segment(fgt, operation, params, path):
    """Object names from playbook params must never add path segments or a query string."""
    fgt.add(responses.GET, BASE + path, json={'results': [{'name': 'x'}]})
    fgt.add(responses.DELETE, BASE + path, json=OK)
    run(operation, params)
    sent = [c.request.url for c in _active['mock'].calls if 'system/vdom' not in c.request.url]
    assert sent and all(urlparse(u).path == urlparse(BASE + path).path for u in sent), sent
    assert all(not urlparse(u).query or 'vdom=' in urlparse(u).query for u in sent)


# --------------------------------------------------------------------------- generic REST call
def test_execute_api_request_get_sends_key_and_vdom(fgt):
    fgt.get(BASE + 'monitor/system/status', json={'results': {'version': 'v7'}, 'status': 'success'})
    out = run('execute_api_request', {'endpoint': '/api/v2/monitor/system/status'})
    assert out['results']['version'] == 'v7'
    call = calls('GET', 'monitor/system/status')[0]
    assert call.request.headers['Authorization'] == 'Bearer k'
    assert parse_qs(urlparse(call.request.url).query)['vdom'] == ['root']


def test_execute_api_request_query_params_and_explicit_vdom(fgt):
    fgt.get(BASE + 'cmdb/firewall/address', json={'results': []})
    run('execute_api_request', {'endpoint': 'api/v2/cmdb/firewall/address', 'query_params': '{"vdom": "other", "count": 5}'})
    query = parse_qs(urlparse(calls('GET', 'firewall/address')[0].request.url).query)
    assert query['vdom'] == ['other'] and query['count'] == ['5']


def test_execute_api_request_post_sends_json_body(fgt):
    fgt.post(BASE + 'cmdb/firewall/address', json=OK)
    run('execute_api_request', {'endpoint': '/api/v2/cmdb/firewall/address', 'method': 'post',
                                'request_body': {'name': 'a', 'subnet': '192.0.2.1/32'}})
    call = calls('POST', 'firewall/address')[0]
    assert body(call) == {'name': 'a', 'subnet': '192.0.2.1/32'}
    assert call.request.headers['Content-Type'] == 'application/json'
    assert call.request.headers['Authorization'] == 'Bearer k'


def test_execute_api_request_delete_has_no_body(fgt):
    fgt.delete(BASE + 'cmdb/firewall/address/a', json=OK)
    run('execute_api_request', {'endpoint': '/api/v2/cmdb/firewall/address/a', 'method': 'DELETE',
                                'request_body': '{"ignored": 1}'})
    assert body(calls('DELETE', 'firewall/address/a')[0]) is None


def test_execute_api_request_auth_failure_surfaced(fgt):
    fgt.get(BASE + 'monitor/system/status', status=401, body='')
    with pytest.raises(ConnectorError, match='Unauthorized'):
        run('execute_api_request', {'endpoint': '/api/v2/monitor/system/status'})


def test_execute_api_request_forbidden_is_an_error(fgt):
    fgt.get(BASE + 'monitor/system/status', status=403,
            json={'status': 'error', 'http_status': 403, 'error': -37})
    with pytest.raises(ConnectorError, match='HTTP 403'):
        run('execute_api_request', {'endpoint': '/api/v2/monitor/system/status'})


@pytest.mark.parametrize('endpoint', [
    'https://evil.example.com/api/v2/x', 'http://evil.example.com', '//evil.example.com/api/v2/x', 'ftp://x/y',
    '/api/v2/../x', '/api/v2/%2e%2e/x', '/api/v2/%252e%252e/x', '/api/v2/%25252e%25252e/x',
    '/api/v2/..%5cx', '/api/v2\\x'])
def test_execute_api_request_refuses_anything_that_could_send_the_key_elsewhere(fgt, endpoint):
    with pytest.raises(ConnectorError, match='path on the configured server'):
        run('execute_api_request', {'endpoint': endpoint})
    assert not fgt.calls


def test_execute_api_request_validates_input(fgt):
    with pytest.raises(ConnectorError, match='Endpoint is required'):
        run('execute_api_request', {})
    with pytest.raises(ConnectorError, match='Method must be'):
        run('execute_api_request', {'endpoint': '/api/v2/monitor/system/status', 'method': 'TRACE'})
    with pytest.raises(ConnectorError, match='valid JSON'):
        run('execute_api_request', {'endpoint': '/api/v2/x', 'request_body': '{nope'})
    with pytest.raises(ConnectorError, match='JSON object'):
        run('execute_api_request', {'endpoint': '/api/v2/x', 'query_params': '[1]'})
    assert not fgt.calls


def test_playbook_collection_version_matches_info():
    pb = json.loads((Path(__file__).resolve().parent.parent / 'fortigatev2' / 'playbooks' / 'playbooks.json').read_text())
    assert pb['data'][0]['name'].endswith(' - ' + INFO['version'])
