# SPDX-License-Identifier: Apache-2.0
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('egress_config', ROOT / 'debian/egress_config.py')
api = importlib.util.module_from_spec(spec)
spec.loader.exec_module(api)


class EgressConfigurationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / 'destinations.json'

    def load(self):
        return api.load_destinations(self.path, uid=os.getuid())

    def test_missing_config_has_no_destinations(self):
        self.assertEqual({}, self.load())

    def test_external_provider_and_monitor_destinations_are_preserved(self):
        self.path.write_text(json.dumps({'smtp': {'port': 465, 'hostnames': ['smtp.example.net']},
                                        'monitor': {'port': 443, 'hostnames': ['health.example.net']}}))
        self.path.chmod(0o600)
        self.assertEqual({'smtp': (465, ['smtp.example.net']), 'monitor': (443, ['health.example.net'])}, self.load())

    def test_unprotected_symlink_and_wrong_owner_refuse(self):
        self.path.write_text('{}'); self.path.chmod(0o666)
        with self.assertRaises(ValueError): self.load()
        self.path.chmod(0o600)
        with self.assertRaises(ValueError): api.load_destinations(self.path, uid=os.getuid() + 1)
        link = self.path.with_name('link'); link.symlink_to(self.path)
        with self.assertRaises(OSError): api.load_destinations(link, uid=os.getuid())

    def test_unknown_groups_ports_duplicates_and_bad_hostnames_refuse(self):
        values = [{'root': {'port': 443, 'hostnames': ['example.net']}},
                  {'smtp': {'port': 80, 'hostnames': ['smtp.example.net']}},
                  {'monitor': {'port': 465, 'hostnames': ['example.net']}},
                  {'smtp': {'port': 465, 'hostnames': ['127.0.0.1']}},
                  {'smtp': {'port': 465, 'hostnames': ['example.net', 'example.net']}},
                  {'smtp': {'port': 465, 'hostnames': [{}]}},
                  {'smtp': {'port': 465, 'hostnames': []}}]
        for value in values:
            with self.subTest(value=value):
                self.path.write_text(json.dumps(value)); self.path.chmod(0o600)
                with self.assertRaises(ValueError): self.load()
        self.path.write_text('{"smtp":{},"smtp":{}}')
        with self.assertRaises(ValueError): self.load()

    def test_monitor_lists_up_to_the_host_name_cap(self):
        names = ['host%d.example.net' % i for i in range(api.MAX_HOSTNAMES + 1)]
        self.path.write_text(json.dumps({'monitor': {'port': 443, 'hostnames': names[:-1]}})); self.path.chmod(0o600)
        self.assertEqual((443, names[:-1]), self.load()['monitor'])
        self.path.write_text(json.dumps({'monitor': {'port': 443, 'hostnames': names}}))
        with self.assertRaises(ValueError): self.load()


if __name__ == '__main__':
    unittest.main()


class SeenAddressTests(unittest.TestCase):
    def test_addresses_are_kept_for_an_hour_after_their_last_answer(self):
        seen = api.merge_seen({}, {'https4': {'17.1.1.1'}}, now=1000.0)
        seen = api.merge_seen(seen, {'https4': {'17.2.2.2'}}, now=2000.0)
        self.assertEqual({'17.1.1.1': 1000.0, '17.2.2.2': 2000.0}, seen['https4'])
        seen = api.merge_seen(seen, {'https4': set()}, now=4700.0)
        self.assertEqual({'17.2.2.2': 2000.0}, seen['https4'])

    def test_saved_entries_that_are_not_public_or_from_the_future_are_dropped(self):
        previous = {'https4': {'10.0.0.1': 900.0, 'not-an-address': 900.0, '17.1.1.1': 5000.0},
                    'https6': 'broken'}
        self.assertEqual({}, api.merge_seen(previous, {}, now=1000.0))

    def test_unreadable_state_starts_empty_and_saving_replaces_it(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'seen.json'
            self.assertEqual({}, api.load_seen(path))
            path.write_text('{broken')
            self.assertEqual({}, api.load_seen(path))
            api.save_seen({'https4': {'17.1.1.1': 1.0}}, path)
            self.assertEqual({'https4': {'17.1.1.1': 1.0}}, api.load_seen(path))
