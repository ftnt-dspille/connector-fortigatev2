"""Thin direct FortiOS REST client used by the live tests for fixture setup,
independent verification (read back what the connector claims it did) and
cleanup. Deliberately does NOT reuse the connector's own request code.
"""
from urllib.parse import quote

import requests
import urllib3

urllib3.disable_warnings()

PREFIX = 'fsrtest-'
# Test policies are created at fixed high IDs so a script that writes policies by
# low ID (1, 2, ...) can never take them over; cleanup sweeps the whole range.
POLICY_ID_BASE = 9900
POLICY_ID_MAX = 9999


class FortiGateRest:
    def __init__(self, config):
        self.base = '{}:{}/api/v2/'.format(config['address'].rstrip('/'), config['port'])
        self.vdom = config.get('vdom') or 'root'
        self.session = requests.Session()
        self.session.verify = config.get('verify_ssl', False)
        self.session.headers['Authorization'] = 'Bearer {}'.format(config['api_key'])

    def _call(self, method, path, body=None, params=None, ok404=False):
        query = {'vdom': self.vdom}
        query.update(params or {})
        resp = self.session.request(method, self.base + path, json=body, params=query, timeout=60)
        if ok404 and resp.status_code == 404:
            return None
        if not resp.ok:
            raise AssertionError('{} {} -> {} {}'.format(method, path, resp.status_code, resp.text[:500]))
        return resp.json()

    def get(self, path, **params):
        return self._call('GET', path, params=params)

    def results(self, path, **params):
        data = self._call('GET', path, params=params, ok404=True)
        return [] if data is None else data.get('results', [])

    def exists(self, path):
        return bool(self.results(path))

    def post(self, path, body):
        return self._call('POST', path, body=body)

    def put(self, path, body):
        return self._call('PUT', path, body=body)

    def delete(self, path):
        return self._call('DELETE', path, ok404=True)

    @staticmethod
    def key(name):
        return quote(str(name), safe='')

    # ---- cleanup -----------------------------------------------------------------
    def purge_test_objects(self):
        """Delete everything this suite may have created, in dependency order."""
        for policy in self.results('cmdb/firewall/policy'):
            if str(policy.get('name', '')).startswith(PREFIX) or POLICY_ID_BASE <= policy['policyid'] <= POLICY_ID_MAX:
                self.delete('cmdb/firewall/policy/{}'.format(policy['policyid']))
        for path in ('cmdb/firewall/addrgrp', 'cmdb/firewall/addrgrp6'):
            for grp in self.results(path):
                if grp['name'].startswith(PREFIX):
                    self.delete('{}/{}'.format(path, self.key(grp['name'])))
        for path in ('cmdb/firewall/address', 'cmdb/firewall/address6'):
            for addr in self.results(path):
                name = addr['name']
                # policy-based block_ip names address objects after the bare IP
                if name.startswith(PREFIX) or name.startswith(('192.0.2.', '198.51.100.', '203.0.113.', '2001:db8')):
                    self.delete('{}/{}'.format(path, self.key(name)))
        for grp in self.results('cmdb/firewall.service/group'):
            if grp['name'].startswith(PREFIX):
                self.delete('cmdb/firewall.service/group/{}'.format(self.key(grp['name'])))
        for svc in self.results('cmdb/firewall.service/custom'):
            if svc['name'].startswith(PREFIX):
                self.delete('cmdb/firewall.service/custom/{}'.format(self.key(svc['name'])))
        for grp in self.results('cmdb/user/group'):
            if grp['name'].startswith(PREFIX):
                self.delete('cmdb/user/group/{}'.format(self.key(grp['name'])))
        for user in self.results('cmdb/user/local'):
            if user['name'].startswith(PREFIX):
                self.delete('cmdb/user/local/{}'.format(self.key(user['name'])))
        for prof in self.results('cmdb/webfilter/profile'):
            if prof['name'].startswith(PREFIX):
                self.delete('cmdb/webfilter/profile/{}'.format(self.key(prof['name'])))
        for table in self.results('cmdb/webfilter/urlfilter'):
            if str(table.get('name', '')).startswith(PREFIX):
                self.delete('cmdb/webfilter/urlfilter/{}'.format(table['id']))
        for app_list in self.results('cmdb/application/list'):
            if app_list['name'].startswith(PREFIX):
                self.delete('cmdb/application/list/{}'.format(self.key(app_list['name'])))
        for res in self.results('cmdb/system/external-resource'):
            if res['name'].startswith(PREFIX):
                self.delete('cmdb/system/external-resource/{}'.format(self.key(res['name'])))
        quarantine = self.get('cmdb/user/quarantine')['results']
        targets = [t for t in quarantine.get('targets', []) if not str(t.get('entry', '')).startswith(PREFIX)
                   and t.get('description') != 'Quarantined by FortiSOAR']
        if len(targets) != len(quarantine.get('targets', [])):
            self.put('cmdb/user/quarantine', {'targets': targets})
        banned = [b['ip_address'] for b in self.results('monitor/user/banned/select')
                  if b['ip_address'].startswith(('192.0.2.', '198.51.100.', '203.0.113.', '2001:db8'))]
        if banned:
            self._call('POST', 'monitor/user/banned/clear_users', body={'ip_addresses': banned})
