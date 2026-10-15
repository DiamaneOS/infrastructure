# SPDX-License-Identifier: Apache-2.0
import importlib.machinery
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
loader = importlib.machinery.SourceFileLoader('activate_web_firewall', str(ROOT / 'debian/activate-web-firewall'))
spec = importlib.util.spec_from_loader(loader.name, loader)
firewall = importlib.util.module_from_spec(spec)
loader.exec_module(firewall)
TEMPLATE = (ROOT / 'debian/nftables-web.conf').read_text()


class WebFirewallTests(unittest.TestCase):
    def test_role_ports_tunnel_and_synproxy_rate_are_rendered(self):
        text = firewall.render(TEMPLATE, 'primary', 51820, 262144)
        self.assertNotIn('{{', text)
        self.assertIn('iifname != "wg-mgmt" tcp dport { 80, 443, 7275 } goto input-web', text)
        self.assertIn('limit rate over 4096/second burst 4096 packets', text)
        self.assertIn('udp dport 51820 notrack accept', text)
        self.assertIn('udp dport 51820 ct state untracked accept', text)
        for role in ('mirror', 'attestation'):
            self.assertIn('tcp dport { 80, 443 } goto', firewall.render(TEMPLATE, role, 51820, 65536))

    def test_both_counting_paths_cap_each_address_and_64(self):
        for chain in ('input-web-established', 'input-web-loopback'):
            body = TEMPLATE.split('chain ' + chain + ' {', 1)[1].split('}\n', 1)[0]
            self.assertIn('{ ip saddr ct count over 32 }', body)
            self.assertIn('{ ip6 saddr and ffff:ffff:ffff:ffff:: ct count over 32 }', body)

    def test_invalid_inputs_refuse(self):
        for arguments in (('staging', 51820, 65536), ('mirror', 22, 65536), ('mirror', 51820, 0)):
            with self.subTest(arguments=arguments), self.assertRaises(SystemExit):
                firewall.render(TEMPLATE, *arguments)


if __name__ == '__main__':
    unittest.main()
