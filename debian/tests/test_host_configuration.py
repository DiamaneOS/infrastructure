# SPDX-License-Identifier: Apache-2.0
import base64
import copy
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
KEYS = [base64.b64encode(bytes([n]) * 32).decode() for n in (1, 2, 3)]
WIREGUARD = {'listen_port': 51000, 'address': '172.31.255.1/32',
             'peers': [{'address': '172.31.255.2/32', 'public_key': KEYS[0]}]}
HEALTH = {'name': 'monitor', 'public_key': KEYS[1], 'address': '172.31.255.3/32',
          'tcp_ports': [22], 'reporter': 'health-reporter'}
CONFIG = {'hostname': 'server.example.org', 'admin_user': 'admin', 'management_mode': 'wireguard',
          'management_cidrs': [], 'interface': 'eth0', 'network_file': '10-eth0.network',
          'bandwidth_mbit': None, 'wireguard': WIREGUARD}
RULES = ('        iifname "wg-mgmt" ip saddr { 172.31.255.2 } tcp dport 22 ct state new accept\n'
         '        iifname "wg-mgmt" drop\n'
         '        udp dport 51000 ct state new accept\n')
TUNNEL = ('[Interface]\nAddress = 172.31.255.1/32\nListenPort = 51000\nPrivateKey = PRIVATE\n\n'
          f'[Peer]\nPublicKey = {KEYS[0]}\nAllowedIPs = 172.31.255.2/32\n')
REPORTER = '''Match Address 172.31.255.3
    AllowUsers health-reporter
Match all
# Require global PermitUserEnvironment=no and no broader environment override.
Match User health-reporter
    AuthenticationMethods publickey
    PubkeyAuthentication yes
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    PermitTTY no
    DisableForwarding yes
    PermitUserRC no
    AcceptEnv LANG LC_ALL
    AllowAgentForwarding no
    X11Forwarding no
    ForceCommand diamaneos-host-health-v1
    AuthorizedKeysFile /etc/diamaneos-monitoring/health-reporter.authorized_keys

Match all
'''


def load():
    loader = importlib.machinery.SourceFileLoader('configure_host', str(ROOT / 'debian/host/configure-host'))
    module = importlib.util.module_from_spec(importlib.util.spec_from_loader(loader.name, loader))
    loader.exec_module(module)
    return module


class HostConfigurationTest(unittest.TestCase):
    def setUp(self):
        self.host = load()

    def config(self, **changes):
        config = copy.deepcopy(CONFIG)
        config.update(copy.deepcopy(changes))
        return config

    def test_without_the_new_fields_the_output_is_unchanged(self):
        config = self.config()
        settings = self.host.wireguard_settings(config)
        self.assertIsNone(self.host.health_peer(config, settings))
        self.assertEqual(RULES, self.host.management_rules(config))
        self.assertEqual(TUNNEL, self.host.wireguard_text(settings, 'PRIVATE'))
        self.assertEqual({'/etc/ssh/sshd_config.d/00-diamaneos-admin.conf': 'AllowUsers admin\n'},
                         self.host.sshd_files('admin', None))
        self.assertFalse(self.host.downloads_moved(config, None))

    def test_health_peer_gets_its_tunnel_port_and_reporter_login(self):
        config = self.config(health_peer=HEALTH)
        settings = self.host.wireguard_settings(config)
        health = self.host.health_peer(config, settings)
        self.assertEqual(RULES.replace('        iifname "wg-mgmt" drop\n',
                                       '        iifname "wg-mgmt" ip saddr 172.31.255.3 tcp dport 22 ct state new accept\n'
                                       '        iifname "wg-mgmt" drop\n'), self.host.management_rules(config))
        self.assertEqual(TUNNEL + f'\n# Restricted host-health peer: monitor\n[Peer]\nPublicKey = {KEYS[1]}\n'
                         'AllowedIPs = 172.31.255.3/32\n', self.host.wireguard_text(settings, 'PRIVATE', health))
        self.assertEqual({'/etc/ssh/sshd_config.d/00-diamaneos-admin.conf': 'AllowUsers admin health-reporter\n',
                          '/etc/ssh/sshd_config.d/01-diamaneos-health.conf': REPORTER},
                         self.host.sshd_files('admin', health))
        config['health_peer']['tcp_ports'] = [22, 9100]
        self.assertIn('ip saddr 172.31.255.3 tcp dport { 22, 9100 } ct state new accept\n',
                      self.host.management_rules(config))

    def test_invalid_health_peers_are_refused(self):
        changes = {'missing field': {'tcp_ports': None}, 'extra field': {'endpoint': 'monitor.example.org'},
                   'name': {'name': 'Monitor peer'}, 'public address': {'address': '192.0.2.3/32'},
                   'network': {'address': '172.31.255.0/24'}, 'own address': {'address': '172.31.255.1/32'},
                   'peer address': {'address': '172.31.255.2/32'}, 'peer key': {'public_key': KEYS[0]},
                   'key': {'public_key': 'not-a-key'}, 'no ports': {'tcp_ports': []},
                   'unsorted ports': {'tcp_ports': [443, 22]}, 'repeated port': {'tcp_ports': [22, 22]},
                   'port zero': {'tcp_ports': [0]}, 'port text': {'tcp_ports': ['22']},
                   'too many ports': {'tcp_ports': list(range(1, 10))}, 'root reporter': {'reporter': 'root'},
                   'admin reporter': {'reporter': 'admin'}, 'reporter name': {'reporter': 'Health Reporter'}}
        for name, change in changes.items():
            peer = {**HEALTH, **change}
            if change.get('tcp_ports', 0) is None:
                del peer['tcp_ports']
            config = self.config(health_peer=peer)
            with self.subTest(name), self.assertRaises(ValueError):
                self.host.management_rules(config)
        config = self.config(management_mode='key-only', health_peer=HEALTH)
        del config['wireguard']
        with self.assertRaisesRegex(ValueError, 'health peer require'):
            self.host.management_rules(config)

    def test_downloads_moved_needs_download_addresses(self):
        self.assertTrue(self.host.downloads_moved({'downloads_moved': True}, ['203.0.113.7/32']))
        self.assertFalse(self.host.downloads_moved({'downloads_moved': False}, []))
        for config, downloads in (({'downloads_moved': True}, None), ({'downloads_moved': True}, []),
                                  ({'downloads_moved': 'yes'}, ['203.0.113.7/32'])):
            with self.subTest(config=config, downloads=downloads), self.assertRaises(ValueError):
                self.host.downloads_moved(config, downloads)

    def test_main_writes_the_reporter_files_only_with_a_health_peer(self):
        for health in (None, HEALTH):
            with self.subTest(health=health is not None), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                config = self.config(download_addresses=['203.0.113.7'], downloads_moved=True)
                if health:
                    config['health_peer'] = health
                _, tunnels = self.run_main(root, config)
                sshd = root / 'etc/ssh/sshd_config.d'
                self.assertEqual(self.host.sshd_files('admin', self.host.health_peer(config, self.host.wireguard_settings(config))),
                                 {'/' + str(path.relative_to(root)): path.read_text()
                                  for path in sshd.iterdir() if path.name != '01-diamaneos-health.conf' or health})
                # Without the field a hand-made reporter file is left as it is.
                self.assertEqual('kept\n' if not health else REPORTER, (sshd / '01-diamaneos-health.conf').read_text())
                self.assertEqual(self.host.management_rules(config), (root / 'etc/diamaneos/management.nft').read_text())
                self.assertEqual(0o600, (root / 'etc/diamaneos/management.nft').stat().st_mode & 0o777)
                self.assertEqual([self.host.health_peer(config, self.host.wireguard_settings(config))],
                                 [call[1] for call in tunnels])
                self.assertEqual('[Address]\nAddress=203.0.113.7/32\n',
                                 (root / 'etc/systemd/network/10-eth0.network.d/60-diamaneos-addresses.conf').read_text())
        with tempfile.TemporaryDirectory() as temp, self.assertRaises(SystemExit):
            self.run_main(Path(temp), self.config(downloads_moved=True))

    def run_main(self, root, config):
        """main() with every absolute path below root, commands recorded and the tunnel step recorded."""
        host_json = json.dumps(config)
        (root / 'sys/class/net/eth0').mkdir(parents=True)
        (root / 'etc/ssh/sshd_config.d').mkdir(parents=True)
        (root / 'etc/ssh/sshd_config.d/01-diamaneos-health.conf').write_text('kept\n')
        (root / 'etc/hosts').write_text('127.0.0.1 localhost\n')

        class HostFile:
            def stat(self):
                return types.SimpleNamespace(st_uid=0, st_mode=0o100600)

            def read_text(self):
                return host_json

        def path(*parts):
            name = Path(*parts)
            if str(name) == '/etc/diamaneos/host.json':
                return HostFile()
            return name if name.is_relative_to(root) else root / str(name).lstrip('/')
        commands, tunnels = [], []
        fake = types.SimpleNamespace(run=lambda argv, **kwargs: commands.append(argv),
                                     check_output=lambda argv, **kwargs: b'1000\n')
        with patch.object(self.host, 'Path', path), patch.object(self.host, 'subprocess', fake), \
                patch.object(self.host, 'configure_wireguard', lambda *args: tunnels.append(args)), \
                patch.dict(os.environ, {'SUDO_USER': 'admin'}):
            self.host.main()
        return commands, tunnels


if __name__ == '__main__':
    unittest.main()
