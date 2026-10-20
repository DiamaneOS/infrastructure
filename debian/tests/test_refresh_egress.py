# SPDX-License-Identifier: Apache-2.0
"""refresh-egress with stand-ins for the host: the GrapheneOS mirror account's rules."""
import ipaddress
from pathlib import Path
import runpy
import socket
import sys
import time
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
DEBIAN = ROOT / 'debian'
UIDS = {'www-data': 33, 'diamaneos-apps-mirror': 991}
# Documentation addresses stand in for public ones.
PUBLIC = ipaddress.ip_network('203.0.113.0/24')


class RefreshEgressTests(unittest.TestCase):
    def run_refresh(self, role, failing=(), seen=None):
        sys.path.insert(0, str(DEBIAN))
        self.addCleanup(sys.path.remove, str(DEBIAN))
        import egress_config
        policies = []

        def user(name):
            if name not in UIDS:
                raise KeyError(name)
            return types.SimpleNamespace(pw_uid=UIDS[name])

        def lookup(name, *args, **kwargs):
            if name in failing:
                raise socket.gaierror('fixture lookup failure')
            return [(socket.AF_INET, 0, 0, '', ('203.0.113.7' if name == 'apps.grapheneos.org' else '203.0.113.9', 0))]

        real = ipaddress.ip_address

        class _Public:
            def __init__(self, found):
                self.found, self.version, self.is_global = found, found.version, found in PUBLIC

            def __str__(self):
                return str(self.found)

        with mock.patch.object(Path, 'read_text', lambda self, *a, **k: role + '\n'), \
                mock.patch('pwd.getpwnam', user), mock.patch('socket.getaddrinfo', lookup), \
                mock.patch('ipaddress.ip_address', lambda v: _Public(real(v))), \
                mock.patch.object(egress_config, 'load_destinations', lambda: {}), \
                mock.patch.object(egress_config, 'load_seen', lambda: seen or {}), \
                mock.patch.object(egress_config, 'save_seen', lambda value: None), \
                mock.patch('subprocess.run', lambda args, input=None, **k: policies.append(input)):
            runpy.run_path(str(DEBIAN / 'refresh-egress'), run_name='__main__')
        return policies[-1]

    def test_mirror_account_reaches_only_apps_grapheneos_org(self):
        for role in ('primary', 'mirror'):
            with self.subTest(role=role):
                policy = self.run_refresh(role)
                self.assertIn('elements = { 203.0.113.7 }', policy.split('set grapheneos4')[1].split('}')[0] + '}')
                rules = [line.strip() for line in policy.splitlines() if 'skuid 991' in line]
                self.assertEqual(rules[-1], 'meta skuid 991 reject')
                self.assertIn('meta skuid 991 ip daddr @grapheneos4 tcp dport 443 accept', rules)
                self.assertFalse([r for r in rules if 'accept' in r and 'grapheneos' not in r
                                  and 'established' not in r and '127.0.0.53' not in r])

    def test_mirror_lookup_failure_keeps_the_other_destinations(self):
        policy = self.run_refresh('primary', failing={'apps.grapheneos.org'},
                                  seen={'grapheneos4': {'203.0.113.8': time.time() - 60}})
        self.assertIn('meta skuid 33 ip daddr @https4 tcp dport 443 accept', policy)
        self.assertIn('203.0.113.9', policy.split('set https4')[1].split('}')[0])
        self.assertIn('meta skuid 991 reject', policy)
        # The mirror keeps the address it resolved within the last hour.
        self.assertIn('203.0.113.8', policy.split('set grapheneos4')[1].split('}')[0])

    def test_other_lookup_failures_still_stop_the_refresh(self):
        with self.assertRaises(SystemExit):
            self.run_refresh('primary', failing={'supl.google.com'})


if __name__ == '__main__':
    unittest.main()
