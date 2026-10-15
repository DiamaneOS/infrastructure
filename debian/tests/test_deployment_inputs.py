# SPDX-License-Identifier: Apache-2.0
import importlib.machinery
import importlib.util
import json
from pathlib import Path
import re
import runpy
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


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

    def assemble(self, role, destination, *options):
        return subprocess.run([sys.executable, str(ROOT / 'debian/assemble-nginx'),
                               role, str(self.source), str(destination), *options],
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
                if role == 'primary':
                    self.assertIn('include website[.]conf;', (destination / 'nginx.conf').read_text())
                    self.assertFalse((destination / 'website.conf').exists())
                else:
                    self.assertNotIn('include website[.]conf;', (destination / 'nginx.conf').read_text())

    def test_mirror_status_page_is_unlisted_and_staged_for_its_first_certificate(self):
        def servers(destination, *options):
            self.assertEqual(self.assemble('mirror', destination, *options).returncode, 0)
            text = (destination / 'mirror.conf').read_text()
            return [block for block in text.split('server {') if 'status.diamaneos.de' in block]
        http, https = servers(self.base / 'full')
        self.assertEqual([http], servers(self.base / 'pending', '--before-status-certificate'))
        self.assertIn('location /.well-known/acme-challenge/ { root /var/lib/letsencrypt/webroot; }', http)
        self.assertIn('location / { return 301 https://$host$request_uri; }', http)
        self.assertIn('ssl_certificate /etc/letsencrypt/live/diamaneos-status/fullchain.pem;', https)
        self.assertIn('root /var/lib/diamaneos-status-page;', https)
        self.assertIn('disable_symlinks on from=$document_root;', https)
        # Only the page and robots.txt. A location with add_header would drop the server's headers.
        self.assertEqual(['location = / { try_files /index.html =404; }',
                          'location = /robots.txt { default_type text/plain; return 200 "User-agent: *\\nDisallow: /\\n"; }',
                          'location / { return 404; }'], re.findall(r'location [^\n]+', https))
        self.assertNotIn('include', http + https)
        headers = dict(re.findall(r'add_header (\S+) "([^"]+)" always;', https))
        # private-scripts monitoring/status_page.py STYLE_HASH is the page's only style.
        self.assertEqual("default-src 'none'; style-src 'sha256-7yC9xC/iI2tfRx8ChmbZOZ2Q+6s4bRpnah8Zp3SnLgc='; "
                         "frame-ancestors 'none'; base-uri 'none'; form-action 'none'", headers.pop('Content-Security-Policy'))
        self.assertEqual({'X-Robots-Tag': 'noindex, nofollow, noarchive', 'Cache-Control': 'no-cache',
                          'Strict-Transport-Security': 'max-age=31536000', 'X-Content-Type-Options': 'nosniff',
                          'Referrer-Policy': 'no-referrer'}, headers)
        self.assertIn(' diamaneos-status ', (ROOT / 'debian/nginx-cert-access').read_text())
        refused = self.assemble('primary', self.base / 'refused', '--before-status-certificate')
        self.assertNotEqual(refused.returncode, 0)
        self.assertFalse((self.base / 'refused').exists())

    def test_download_addresses_serve_only_the_download_names(self):
        (self.source / 'network/nginx/nginx.conf').write_text(
            'http {\n    include releases[.]conf;\n}\n\nstream {\n    server {\n        listen 7275 default_server ssl;\n'
            '        proxy_pass supl.google.com;\n    }\n}\n')
        (self.source / 'releases/nginx/releases.conf').write_text(
            'server {\n    listen 80;\n    listen [::]:80;\n    server_name releases.diamaneos.de apps.diamaneos.de;\n}\n\n'
            'server {\n    listen 443 ssl;\n    listen [::]:443 ssl;\n    server_name apps.diamaneos.de;\n}\n\n'
            'server {\n    listen 443 ssl;\n    server_name diamaneos.de;\n}\n')
        v4, v6 = '203.0.113.7', '2001:db8::7'

        def servers(destination, *options):
            result = self.assemble('primary', destination, *options)
            self.assertEqual(result.returncode, 0, result.stderr)
            text = (destination / 'releases.conf').read_text()
            return text, [block for block in text.split('server {')[1:]], (destination / 'nginx.conf').read_text()

        text, blocks, main = servers(self.base / 'both', '--download-address', v4, '--download-address', v6)
        self.assertEqual(blocks[:4], [f'\n    listen {v4}:80 default_server;\n    return 444;\n}}\n\n',
                                      f'\n    listen {v4}:443 default_server ssl;\n    ssl_reject_handshake on;\n}}\n\n',
                                      f'\n    listen [{v6}]:80 default_server;\n    return 444;\n}}\n\n',
                                      f'\n    listen [{v6}]:443 default_server ssl;\n    ssl_reject_handshake on;\n}}\n\n'])
        self.assertIn(f'    listen 80;\n    listen {v4}:80;\n    listen [::]:80;\n    listen [{v6}]:80;\n', blocks[4])
        self.assertIn(f'    listen 443 ssl;\n    listen {v4}:443 ssl;\n    listen [::]:443 ssl;\n    listen [{v6}]:443 ssl;\n', blocks[5])
        self.assertEqual(['listen 443 ssl;'], re.findall(r'listen [^\n]+', blocks[6]))
        self.assertIn('include ads.conf;', blocks[5])
        self.assertTrue(main.endswith(f'    server {{\n        listen {v4}:7275;\n        return "";\n    }}\n\n'
                                      f'    server {{\n        listen [{v6}]:7275;\n        return "";\n    }}\n}}\n'))
        self.assertIn('include website[.]conf;', main)

        # Moved: IPv4 answers only on its own address, IPv6 keeps the shared one.
        _, blocks, _ = servers(self.base / 'moved', '--download-address', v4, '--downloads-moved')
        self.assertEqual([f'listen {v4}:80;', 'listen [::]:80;'], re.findall(r'listen [^\n]+', blocks[2]))
        self.assertEqual([f'listen {v4}:443 ssl;', 'listen [::]:443 ssl;'], re.findall(r'listen [^\n]+', blocks[3]))
        self.assertEqual(['listen 443 ssl;'], re.findall(r'listen [^\n]+', blocks[4]))

        refusals = {'mirror role': ('mirror', '--download-address', v4), 'two IPv4': ('primary', '--download-address', v4,
                    '--download-address', '198.51.100.1'), 'loopback': ('primary', '--download-address', '127.0.0.1'),
                    'not an address': ('primary', '--download-address', 'releases'), 'moved alone': ('primary', '--downloads-moved'),
                    'missing value': ('primary', '--download-address')}
        for name, (role, *options) in refusals.items():
            with self.subTest(name):
                self.assertNotEqual(self.assemble(role, self.base / 'refused', *options).returncode, 0)
                self.assertFalse((self.base / 'refused').exists())
        # Without a wildcard listen to extend the assembly refuses.
        (self.source / 'releases/nginx/releases.conf').write_text('server {\n server_name releases.diamaneos.de;\n}\n')
        self.assertNotEqual(self.assemble('primary', self.base / 'refused', '--download-address', v4).returncode, 0)
        self.assertFalse((self.base / 'refused').exists())

    def test_host_download_addresses(self):
        loader = importlib.machinery.SourceFileLoader('configure_host', str(ROOT / 'debian/host/configure-host'))
        host = importlib.util.module_from_spec(importlib.util.spec_from_loader(loader.name, loader))
        loader.exec_module(host)
        self.assertIsNone(host.download_addresses({}))
        self.assertEqual([], host.download_addresses({'download_addresses': []}))
        self.assertEqual(['203.0.113.7/32', '2001:db8::7/128'],
                         host.download_addresses({'download_addresses': ['203.0.113.7', '2001:db8::7']}))
        for values in (['203.0.113.7', '198.51.100.1'], ['127.0.0.1'], ['fe80::1'], ['203.0.113.7/32'], [7], '203.0.113.7'):
            with self.subTest(values=values), self.assertRaises(ValueError):
                host.download_addresses({'download_addresses': values})

    def test_mirror_serves_only_its_health_reply_and_the_monitor_heartbeat(self):
        self.assertEqual(self.assemble('mirror', self.base / 'mirror').returncode, 0)
        text = (self.base / 'mirror' / 'mirror.conf').read_text()
        https = next(block for block in text.split('server {') if 'mirror.diamaneos.de' in block and '443' in block)
        self.assertEqual(['location = /healthz { default_type text/plain; return 200 "ready\\n"; }',
                          'location = /monitor-heartbeat { default_type text/plain; disable_symlinks on; '
                          'alias /var/lib/diamaneos-status-page/heartbeat; }',
                          'location / { return 404; }'], re.findall(r'location [^\n]+', https))

    def test_missing_or_external_includes_reject_without_output(self):
        entry = self.source / 'attestation/nginx/nginx.conf'
        for expression in ['missing.conf', '../outside.conf', '/etc/secret.conf']:
            with self.subTest(expression=expression):
                entry.write_text('include ' + expression + ';\n')
                destination = self.base / 'rejected'
                result = self.assemble('attestation', destination)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(destination.exists())

    def test_runtime_dropins_have_declared_modes_independent_of_caller_umask(self):
        runtime = (ROOT / 'debian/install-web-runtime').read_text()
        expected = {
            'nginx-clock-readiness.conf': b'[Unit]\nWants=diamaneos-clock.service\nAfter=diamaneos-clock.service\n',
            'egress-network-admin.conf': b'[Service]\nCapabilityBoundingSet=CAP_NET_ADMIN\n',
        }
        for name, body in expected.items():
            self.assertEqual(body, (ROOT / 'debian' / name).read_bytes())
            self.assertIn('install -o root -g root -m 0644 "$here/' + name + '"', runtime)
        self.assertIn('generated_file "/etc/systemd/system/$mount_unit"', runtime)
        self.assertIn('generated_file /etc/diamaneos/web-role --role "$role"', runtime)
        self.assertIn('os.O_WRONLY|os.O_NOFOLLOW|os.O_NONBLOCK', runtime)
        self.assertIn('info.st_nlink==1', runtime)

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
                (repo / 'static/privacy-policy.html').write_text('<!doctype html><title>DiamaneOS privacy</title>\n')
                (repo / 'static/privacy.css').write_text('body { color: black; }\n')
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
        self.assertEqual({path.name for path in (destination / 'attestation/static').iterdir()},
                         {'privacy-policy.html', 'privacy.css'})
        self.assertFalse(any(path.name in {'allowed_signers', 'security.txt',
                                          'donate-bitcoin.png'} for path in destination.rglob('*')))
        self.assertFalse((destination / 'network/static').exists())
        self.assertFalse((destination / 'releases/static').exists())
        original = json.loads((destination / 'source-pins.json').read_text())['AttestationServer']
        # A committed symbolic link is not a public-file authorization.
        asset = clones / 'AttestationServer/static/privacy.css'
        asset.unlink()
        asset.symlink_to('/etc/passwd')
        subprocess.run(['git', '-C', str(clones / 'AttestationServer'), 'add', str(asset)], check=True)
        subprocess.run(['git', '-C', str(clones / 'AttestationServer'), '-c', 'user.name=Fixture',
                        '-c', 'user.email=fixture@example.invalid', '-c', 'commit.gpgsign=false',
                        'commit', '-qm', 'Unsafe fixture'], check=True)
        unsafe = subprocess.check_output(['git', '-C', str(clones / 'AttestationServer'),
                                          'rev-parse', 'HEAD'], text=True).strip()
        refused = subprocess.run([sys.executable, str(ROOT / 'debian/stage-web-sources'),
                                  str(clones), str(self.base / 'refused')],
                                 capture_output=True, text=True, timeout=15)
        self.assertNotEqual(refused.returncode, 0)
        self.assertFalse((self.base / 'refused/source-pins.json').exists())
        # Move HEAD after cleanliness succeeds, without changing its index or
        # working files. Only an exporter bound to the checked commit is safe.
        subprocess.run(['git', '-C', str(clones / 'AttestationServer'), 'reset',
                        '--hard', original], check=True, stdout=subprocess.DEVNULL)
        moving = self.base / 'moving'
        native_run = subprocess.run
        changed = []

        def move_head(argv, **kwargs):
            result = native_run(argv, **kwargs)
            if (argv[:3] == ['git', '-C', str(clones / 'AttestationServer')]
                    and argv[3] == 'diff' and not changed):
                native_run(['git', '-C', str(clones / 'AttestationServer'),
                            'update-ref', 'HEAD', unsafe], check=True)
                changed.append(True)
            return result

        with patch.object(sys, 'argv', ['stage-web-sources', str(clones), str(moving)]), \
                patch.object(subprocess, 'run', side_effect=move_head):
            runpy.run_path(str(ROOT / 'debian/stage-web-sources'), run_name='__main__')
        self.assertEqual(changed, [True])
        self.assertEqual(json.loads((moving / 'source-pins.json').read_text())['AttestationServer'], original)
        exported = moving / 'attestation/static/privacy.css'
        self.assertFalse(exported.is_symlink())
        self.assertEqual(exported.read_text(), 'body { color: black; }\n')
