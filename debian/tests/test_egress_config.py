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


if __name__ == '__main__':
    unittest.main()
