# SPDX-License-Identifier: Apache-2.0
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]


class DeploymentInputsTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.source = self.base / 'source'
        for name in ['network', 'releases', 'attestation']:
            directory = self.source / name / 'nginx'
            directory.mkdir(parents=True)
            (directory / 'mime.types').write_text('types {}\n')
            (directory / 'root_grapheneos.org.conf').write_text('root /srv/grapheneos.org;\n')
        (self.source / 'network/nginx/nginx.conf').write_text(
            'include mime.types;\ninclude releases[.]conf;\n')
        (self.source / 'releases/nginx/nginx.conf').write_text(
            'include mime.types;\ninclude releases.conf;\n')
        (self.source / 'releases/nginx/releases.conf').write_text(
            'server {\n server_name releases.diamaneos.de apps.diamaneos.de;\n'
            ' include headers.conf;\n}\n')
        (self.source / 'releases/nginx/headers.conf').write_text('add_header X-Test value;\n')
        (self.source / 'attestation/nginx/nginx.conf').write_text(
            'include mime.types;\nserver {\n server_name attestation.diamaneos.de;\n'
            ' include service-state.conf;\n}\n')
        (self.source / 'attestation/nginx/service-state.conf').write_text('return 503;\n')

    def assemble(self, role, destination):
        return subprocess.run([sys.executable, str(ROOT / 'debian/assemble-nginx'),
                               role, str(self.source), str(destination)],
                              capture_output=True, text=True, timeout=10)

    def test_only_active_vhost_dependencies_are_copied(self):
        expected = {
            'primary': {'nginx.conf', 'mime.types', 'releases.conf', 'headers.conf', 'ads.conf'},
            'mirror': {'nginx.conf', 'mime.types', 'releases.conf', 'headers.conf', 'mirror.conf', 'ads.conf'},
            'attestation': {'nginx.conf', 'mime.types', 'service-state.conf', 'ads.conf'},
        }
        for role, names in expected.items():
            with self.subTest(role=role):
                destination = self.base / role
                result = self.assemble(role, destination)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual({path.name for path in destination.iterdir()}, names)
                if role == 'mirror':
                    self.assertIn('server_name releases-na.diamaneos.de apps-na.diamaneos.de;',
                                  (destination / 'releases.conf').read_text())

    def test_missing_or_external_includes_reject_without_output(self):
        entry = self.source / 'attestation/nginx/nginx.conf'
        for expression in ['missing.conf', '../outside.conf', '/etc/secret.conf']:
            with self.subTest(expression=expression):
                entry.write_text('include ' + expression + ';\n')
                destination = self.base / 'rejected'
                result = self.assemble('attestation', destination)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(destination.exists())

    def test_committed_source_staging_excludes_website_and_identity_assets(self):
        clones = self.base / 'clones'
        for name in ['infrastructure', 'network-services', 'releases.diamaneos.de', 'AttestationServer']:
            repo = clones / name
            (repo / 'nginx').mkdir(parents=True)
            (repo / 'nginx/nginx.conf').write_text('events {}\n')
            (repo / 'static/.well-known').mkdir(parents=True)
            (repo / 'static/.well-known/security.txt').write_text('Contact: upstream@example.invalid\n')
            (repo / 'static/donate-bitcoin.png').write_bytes(b'not an image')
            (repo / 'allowed_signers').write_text('upstream signing identity\n')
            if name == 'infrastructure':
                (repo / 'debian').mkdir()
                (repo / 'debian/adapter').write_text('configuration\n')
                for filename in ['session-ticket-keys-create', 'session-ticket-keys-rotate']:
                    (repo / filename).write_text('script\n')
                directory = repo / 'etc/systemd/system'
                directory.mkdir(parents=True)
                for filename in ['session-ticket-keys-create.service', 'session-ticket-keys-rotate.service', 'session-ticket-keys-rotate.timer']:
                    (directory / filename).write_text('[Unit]\n')
            if name == 'AttestationServer':
                directory = repo / 'systemd/system'
                directory.mkdir(parents=True)
                (directory / 'attestation.service').write_text('[Unit]\n')
            subprocess.run(['git', 'init', '-q', str(repo)], check=True)
            subprocess.run(['git', '-C', str(repo), 'add', '.'], check=True)
            subprocess.run(['git', '-C', str(repo), '-c', 'user.name=Fixture',
                            '-c', 'user.email=fixture@example.invalid', '-c', 'commit.gpgsign=false',
                            'commit', '-qm', 'Fixture'], check=True)
        destination = self.base / 'staged'
        result = subprocess.run([sys.executable, str(ROOT / 'debian/stage-web-sources'),
                                 str(clones), str(destination)],
                                capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((destination / 'attestation/attestation.service').is_file())
        self.assertEqual(len(json.loads((destination / 'source-pins.json').read_text())), 4)
        self.assertFalse(any(path.name in {'static', 'allowed_signers', 'security.txt',
                                          'donate-bitcoin.png'} for path in destination.rglob('*')))
