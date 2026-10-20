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
KEYS = [base64.b64encode(bytes([n]) * 32).decode() for n in (1, 2, 3, 4)]
WIREGUARD = {'listen_port': 51000, 'address': '172.31.255.1/32',
             'peers': [{'address': '172.31.255.2/32', 'public_key': KEYS[0]}]}
HEALTH = {'name': 'monitor', 'public_key': KEYS[1], 'address': '172.31.255.3/32',
          'tcp_ports': [22], 'reporter': 'health-reporter'}
COLLECTOR = {'reporter': 'health-reporter', 'peers': [
    {'name': 'primary', 'public_key': KEYS[1], 'address': '172.31.255.3/32', 'endpoint': '203.0.113.3:51000', 'keepalive': 25},
    {'name': 'attestation', 'public_key': KEYS[2], 'address': '172.31.255.4/32', 'endpoint': '[2001:db8::4]:51000',
     'keepalive': 25}]}
UNLOCK = {'name': 'phone', 'public_key': KEYS[3], 'address': '172.31.255.6/32', 'account': 'state-unlock',
          'key_algorithm': 'ecdsa-sha2-nistp256', 'command': '/usr/local/sbin/state-unlock'}
UNLOCK_SSHD = '''Match Address 172.31.255.6
    AllowUsers state-unlock
Match all
# Require global PermitUserEnvironment=no and no broader environment override.
Match User state-unlock
    AuthenticationMethods publickey
    PubkeyAuthentication yes
    PubkeyAcceptedAlgorithms ecdsa-sha2-nistp256
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    PermitTTY yes
    DisableForwarding yes
    PermitUserRC no
    AcceptEnv LANG
    AllowAgentForwarding no
    X11Forwarding no
    MaxSessions 1
    ForceCommand /usr/local/sbin/state-unlock
    AuthorizedKeysFile /etc/diamaneos/state-unlock.authorized_keys

Match all
'''
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
        self.assertIsNone(self.host.health_collector(config, settings))
        self.assertIsNone(self.host.reporter_login(settings, None, None))
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
                         self.host.sshd_files('admin', self.host.reporter_login(settings, health, None)))
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
        with self.assertRaisesRegex(ValueError, 'health peers require'):
            self.host.management_rules(config)

    def test_collector_dials_its_peers_and_checks_itself(self):
        config = self.config(health_collector=COLLECTOR)
        settings = self.host.wireguard_settings(config)
        collector = self.host.health_collector(config, settings)
        # Only replies come back from the peers: no firewall rule for them.
        self.assertEqual(RULES, self.host.management_rules(config))
        self.assertEqual(TUNNEL + f'\n# Restricted host-health peer: primary\n[Peer]\nPublicKey = {KEYS[1]}\n'
                         'AllowedIPs = 172.31.255.3/32\nEndpoint = 203.0.113.3:51000\nPersistentKeepalive = 25\n'
                         f'\n# Restricted host-health peer: attestation\n[Peer]\nPublicKey = {KEYS[2]}\n'
                         'AllowedIPs = 172.31.255.4/32\nEndpoint = [2001:db8::4]:51000\nPersistentKeepalive = 25\n',
                         self.host.wireguard_text(settings, 'PRIVATE', None, collector))
        self.assertEqual({'/etc/ssh/sshd_config.d/00-diamaneos-admin.conf': 'AllowUsers admin health-reporter\n',
                          '/etc/ssh/sshd_config.d/01-diamaneos-health.conf':
                          REPORTER.replace('Match Address 172.31.255.3', 'Match Address 172.31.255.1')},
                         self.host.sshd_files('admin', self.host.reporter_login(settings, None, collector)))

    def test_invalid_collectors_are_refused(self):
        def peer(**change):
            return {**COLLECTOR['peers'][0], **change}
        changes = {'no peers': {'peers': []}, 'peers not a list': {'peers': peer()},
                   'extra field': {'reporter': 'health-reporter', 'peers': [peer()], 'ports': [22]},
                   'missing endpoint': {'peers': [{k: v for k, v in peer().items() if k != 'endpoint'}]},
                   'tcp ports': {'peers': [peer(tcp_ports=[22])]}, 'endpoint without port': {'peers': [peer(endpoint='203.0.113.3')]},
                   'loopback endpoint': {'peers': [peer(endpoint='127.0.0.1:51000')]},
                   'bare IPv6 endpoint': {'peers': [peer(endpoint='2001:db8::4:51000')]},
                   'keepalive zero': {'peers': [peer(keepalive=0)]}, 'keepalive text': {'peers': [peer(keepalive='25')]},
                   'same name': {'peers': [peer(), peer(public_key=KEYS[2], address='172.31.255.4/32')]},
                   'same address': {'peers': [peer(), peer(name='attestation', public_key=KEYS[2])]},
                   'same key': {'peers': [peer(), peer(name='attestation', address='172.31.255.4/32')]},
                   'own address': {'peers': [peer(address='172.31.255.1/32')]},
                   'admin peer key': {'peers': [peer(public_key=KEYS[0])]}, 'admin reporter': {'reporter': 'admin'}}
        for name, change in changes.items():
            config = self.config(health_collector={**COLLECTOR, **change})
            with self.subTest(name), self.assertRaises(ValueError):
                self.host.health_collector(config, self.host.wireguard_settings(config))
        config = self.config(health_collector=COLLECTOR, health_peer=HEALTH)
        with self.assertRaisesRegex(ValueError, 'not both'):
            self.host.health_collector(config, self.host.wireguard_settings(config))
        config = self.config(management_mode='key-only', health_collector=COLLECTOR)
        del config['wireguard']
        with self.assertRaisesRegex(ValueError, 'health peers require'):
            self.host.management_rules(config)

    def test_unlock_peer_gets_ssh_and_one_forced_command(self):
        config = self.config(health_peer=HEALTH, unlock_peer=UNLOCK)
        settings = self.host.wireguard_settings(config)
        health, unlock = self.host.health_peer(config, settings), self.host.unlock_peer(config, settings)
        self.assertEqual(RULES.replace('        iifname "wg-mgmt" drop\n',
                                       '        iifname "wg-mgmt" ip saddr 172.31.255.3 tcp dport 22 ct state new accept\n'
                                       '        iifname "wg-mgmt" ip saddr 172.31.255.6 tcp dport 22 ct state new accept\n'
                                       '        iifname "wg-mgmt" drop\n'), self.host.management_rules(config))
        self.assertTrue(self.host.wireguard_text(settings, 'PRIVATE', health, None, unlock).endswith(
            f'\n# Restricted unlock peer: phone\n[Peer]\nPublicKey = {KEYS[3]}\nAllowedIPs = 172.31.255.6/32\n'))
        files = self.host.sshd_files('admin', self.host.reporter_login(settings, health, None), unlock)
        self.assertEqual('AllowUsers admin health-reporter state-unlock\n', files['/etc/ssh/sshd_config.d/00-diamaneos-admin.conf'])
        self.assertEqual(UNLOCK_SSHD, files['/etc/ssh/sshd_config.d/02-diamaneos-unlock.conf'])
        self.assertEqual(REPORTER, files['/etc/ssh/sshd_config.d/01-diamaneos-health.conf'])

    def test_invalid_unlock_peers_are_refused(self):
        changes = {'missing field': {'command': None}, 'extra field': {'tcp_ports': [22]},
                   'name': {'name': 'My Phone'}, 'public address': {'address': '192.0.2.6/32'},
                   'own address': {'address': '172.31.255.1/32'}, 'peer address': {'address': '172.31.255.2/32'},
                   'health address': {'address': '172.31.255.3/32'}, 'health key': {'public_key': KEYS[1]},
                   'health name': {'name': 'monitor'}, 'peer key': {'public_key': KEYS[0]},
                   'root account': {'account': 'root'}, 'admin account': {'account': 'admin'},
                   'reporter account': {'account': 'health-reporter'}, 'rsa key': {'key_algorithm': 'ssh-rsa'},
                   'relative command': {'command': 'state-unlock'}, 'command elsewhere': {'command': '/bin/sh'},
                   'command with arguments': {'command': '/usr/local/sbin/state-unlock status'}}
        for name, change in changes.items():
            peer = {**UNLOCK, **change}
            if change.get('command', 0) is None:
                del peer['command']
            config = self.config(health_peer=HEALTH, unlock_peer=peer)
            with self.subTest(name), self.assertRaises(ValueError):
                self.host.management_rules(config)
        config = self.config(management_mode='key-only', unlock_peer=UNLOCK)
        del config['wireguard']
        with self.assertRaises(ValueError):
            self.host.management_rules(config)

    def test_downloads_moved_needs_download_addresses(self):
        self.assertTrue(self.host.downloads_moved({'downloads_moved': True}, ['203.0.113.7/32']))
        self.assertFalse(self.host.downloads_moved({'downloads_moved': False}, []))
        for config, downloads in (({'downloads_moved': True}, None), ({'downloads_moved': True}, []),
                                  ({'downloads_moved': 'yes'}, ['203.0.113.7/32'])):
            with self.subTest(config=config, downloads=downloads), self.assertRaises(ValueError):
                self.host.downloads_moved(config, downloads)

    def test_main_writes_the_reporter_files_only_with_a_health_peer_or_collector(self):
        for field, value in ((None, None), ('health_peer', HEALTH), ('health_collector', COLLECTOR)):
            with self.subTest(field), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                config = self.config(download_addresses=['203.0.113.7'], downloads_moved=True)
                if field:
                    config[field] = value
                _, tunnels = self.run_main(root, config)
                settings = self.host.wireguard_settings(config)
                health, collector = self.host.health_peer(config, settings), self.host.health_collector(config, settings)
                sshd = root / 'etc/ssh/sshd_config.d'
                self.assertEqual(self.host.sshd_files('admin', self.host.reporter_login(settings, health, collector)),
                                 {'/' + str(path.relative_to(root)): path.read_text()
                                  for path in sshd.iterdir() if path.name != '01-diamaneos-health.conf' or field})
                # Without either field a hand-made reporter file is left as it is.
                if not field:
                    self.assertEqual('kept\n', (sshd / '01-diamaneos-health.conf').read_text())
                self.assertEqual(self.host.management_rules(config), (root / 'etc/diamaneos/management.nft').read_text())
                self.assertEqual(0o600, (root / 'etc/diamaneos/management.nft').stat().st_mode & 0o777)
                self.assertEqual([(settings, health, collector, None)], tunnels)
                self.assertFalse((sshd / '02-diamaneos-unlock.conf').exists())
                self.assertEqual('[Address]\nAddress=203.0.113.7/32\n',
                                 (root / 'etc/systemd/network/10-eth0.network.d/60-diamaneos-addresses.conf').read_text())
        with tempfile.TemporaryDirectory() as temp, self.assertRaises(SystemExit):
            self.run_main(Path(temp), self.config(downloads_moved=True))
        for value in ('on', True):
            with tempfile.TemporaryDirectory() as temp, self.assertRaises(SystemExit):
                self.run_main(Path(temp), self.config(system_journal=value))

    def test_main_writes_and_removes_the_unlock_login(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config = self.config(unlock_peer=UNLOCK, system_journal='persistent')
            _, tunnels = self.run_main(root, config)
            sshd = root / 'etc/ssh/sshd_config.d'
            self.assertEqual(UNLOCK_SSHD, (sshd / '02-diamaneos-unlock.conf').read_text())
            self.assertEqual('AllowUsers admin state-unlock\n', (sshd / '00-diamaneos-admin.conf').read_text())
            self.assertEqual(UNLOCK['public_key'], tunnels[0][3]['public_key'])
            del config['unlock_peer']
            self.run_main(root, config)
            self.assertFalse((sshd / '02-diamaneos-unlock.conf').exists())
            self.assertEqual('AllowUsers admin\n', (sshd / '00-diamaneos-admin.conf').read_text())

    def run_main(self, root, config):
        """main() with every absolute path below root, commands recorded and the tunnel step recorded."""
        host_json = json.dumps(config)
        (root / 'sys/class/net/eth0').mkdir(parents=True, exist_ok=True)
        (root / 'etc/ssh/sshd_config.d').mkdir(parents=True, exist_ok=True)
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
                patch.object(self.host, 'remove', lambda name: path(name).unlink(missing_ok=True)), \
                patch.object(self.host, 'configure_wireguard', lambda *args: tunnels.append(args)), \
                patch.dict(os.environ, {'SUDO_USER': 'admin'}):
            self.host.main()
        return commands, tunnels


if __name__ == '__main__':
    unittest.main()
