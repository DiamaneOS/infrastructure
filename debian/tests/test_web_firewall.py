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
TCP = (1500, 1500, 6291456)  # Debian's interface MTU and tcp_rmem maximum


def chain(name):
    return TEMPLATE.split('chain ' + name + ' {', 1)[1].split('\n    }\n', 1)[0]


class WebFirewallTests(unittest.TestCase):
    def test_role_ports_tunnel_and_synproxy_rate_are_rendered(self):
        text = firewall.render(TEMPLATE, 'primary', 51820, 262144, *TCP)
        self.assertNotIn('{{', text)
        self.assertIn('iifname != "wg-mgmt" tcp dport { 80, 443, 7275 } goto input-web', text)
        self.assertIn('iif != lo tcp dport { 80, 443, 7275 } tcp flags syn jump prerouting-web-syn', text)
        self.assertIn('limit rate over 4096/second burst 4096 packets counter name "synproxy_syns"', text)
        self.assertEqual(text.count('size 262144'), 2)
        self.assertIn('udp dport 51820 notrack accept', text)
        self.assertIn('udp dport 51820 ct state untracked accept', text)
        for role in ('mirror', 'attestation'):
            self.assertIn('tcp dport { 80, 443 } goto', firewall.render(TEMPLATE, role, 51820, 65536, *TCP))

    def test_only_option_less_and_flood_syns_go_to_synproxy(self):
        body = chain('prerouting-web-syn')
        # The flood counter is on the rate rule alone, so an option-less SYN below the rate does
        # not raise synproxy_syns and the alert still means a flood.
        rate = next(l for l in body.splitlines() if 'limit rate over' in l)
        self.assertIn('counter name "synproxy_syns" notrack accept', rate)
        option_less = next(l for l in body.splitlines() if 'maxseg missing' in l)
        self.assertIn('tcp option maxseg missing notrack accept', option_less)
        self.assertNotIn('synproxy_syns', option_less)
        # Exactly one rule names the counter, so it only ever counts the flood.
        self.assertEqual(sum('name "synproxy_syns"' in l for l in TEMPLATE.splitlines()), 1)

    def test_real_client_keeps_the_tracked_path(self):
        self.assertIn('new : goto input-web-new', chain('input-web'))
        self.assertNotIn('ct mark', TEMPLATE)
        self.assertNotIn('input-web-established', TEMPLATE)

    def test_synproxy_options_follow_the_host(self):
        for tcp, options in (((1500, 1500, 6291456), ('mss 1460 wscale 7', 'mss 1440 wscale 7')),
                             ((1450, 1400, 67108864), ('mss 1410 wscale 11', 'mss 1340 wscale 11'))):
            text = firewall.render(TEMPLATE, 'mirror', 51820, 65536, *tcp)
            self.assertIn('meta nfproto ipv4 synproxy ' + options[0] + ' timestamp sack-perm', text)
            self.assertIn('meta nfproto ipv6 synproxy ' + options[1] + ' timestamp sack-perm', text)

    def test_both_counting_paths_cap_each_address_and_64(self):
        # Tracked new connections count at the SYN with a direct reset, synproxy connections at
        # the loopback handover through the over-cap sets.
        for c, over in (('input-web-new', 'counter name "per_source_rejects" reject with tcp reset'),
                        ('input-web-loopback', 'goto input-web-over-cap')):
            body = chain(c)
            self.assertIn('add @ip-connlimit-main { ip saddr ct count over 32 } ' + over, body)
            self.assertIn('add @ip6-connlimit-main { ip6 saddr and ffff:ffff:ffff:ffff:: ct count over 32 } ' + over, body)
        # Only the two counting paths evaluate ct count. The over-cap sets carry none.
        self.assertEqual(TEMPLATE.count('ct count'), 4)
        for name in ('ip-over-cap', 'ip6-over-cap'):
            body = TEMPLATE.split('set ' + name + ' {', 1)[1].split('}', 1)[0]
            self.assertIn('flags dynamic, timeout', body)
            self.assertIn('timeout 10s', body)
        self.assertIn('reject with tcp reset', chain('input-web-over-cap'))

    def test_invalid_inputs_refuse(self):
        for arguments in (('staging', 51820, 65536, *TCP), ('mirror', 22, 65536, *TCP), ('mirror', 51820, 0, *TCP),
                          ('mirror', 51820, 65536, 1000, 1500, 6291456), ('mirror', 51820, 65536, 1500, 1500, 4096)):
            with self.subTest(arguments=arguments), self.assertRaises(SystemExit):
                firewall.render(TEMPLATE, *arguments)


if __name__ == '__main__':
    unittest.main()
