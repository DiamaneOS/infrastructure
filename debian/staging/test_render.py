# SPDX-License-Identifier: Apache-2.0
import importlib.util
from pathlib import Path
import shutil
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('staging_render', HERE / 'render.py')
renderer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(renderer)


class RenderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.source = self.root / 'source'
        for role in ('releases', 'attestation'):
            directory = self.source / role / 'nginx'
            directory.mkdir(parents=True)
            (directory / 'mime.types').write_text('types {}\n')
            (directory / 'headers.conf').write_text('add_header X-Content-Type-Options nosniff;\n')
        release = self.source / 'releases/nginx'
        (release / 'nginx.conf').write_text('events {}\nhttp {\n include mime.types;\n include releases.conf;\n}\n')
        (release / 'releases.conf').write_text('server {\n server_name releases.diamaneos.de apps.diamaneos.de;\n include headers.conf;\n ssl_certificate /etc/letsencrypt/live/diamaneos-artifacts/fullchain.pem;\n ssl_certificate_key /etc/letsencrypt/live/diamaneos-artifacts/privkey.pem;\n include root_apps.diamaneos.de.conf;\n}\n')
        (release / 'root_apps.diamaneos.de.conf').write_text('root /srv/apps.diamaneos.de_a;\n')
        attestation = self.source / 'attestation/nginx'
        (attestation / 'nginx.conf').write_text('events {}\nhttp {\n upstream backend { server [::1]:8080; }\n server {\n server_name attestation.diamaneos.de;\n ssl_certificate /etc/letsencrypt/live/diamaneos-attestation/fullchain.pem;\n ssl_certificate_key /etc/letsencrypt/live/diamaneos-attestation/privkey.pem;\n include service-state.conf;\n include root_attestation.diamaneos.de.conf;\n }\n}\n')
        (attestation / 'service-state.conf').write_text('return 503 "DiamaneOS attestation enrollment is closed.\\n";\n')
        (attestation / 'root_attestation.diamaneos.de.conf').write_text('root /srv/attestation.diamaneos.de_a;\n')
        self.headers = self.root / 'website-headers.conf'
        self.headers.write_text('add_header Content-Security-Policy "default-src none";\nadd_header X-Content-Type-Options nosniff;\n')
        self.output = self.root / 'output'

    def render(self, role='web'):
        renderer.render(role, self.source, self.output, self.headers)

    def test_web_reuses_artifact_handlers_and_adds_only_static_website(self):
        self.render()
        config = '\n'.join(p.read_text() for p in self.output.glob('*.conf'))
        for name in ('staging.diamaneos.de', 'releases.staging.diamaneos.de', 'apps.staging.diamaneos.de'):
            self.assertIn(name, config)
        self.assertIn('return 503;', (self.output / 'mirror.conf').read_text())
        self.assertIn('default-src none', config)
        self.assertNotIn('proxy_pass', config)
        self.assertNotIn('/srv/apps.diamaneos.de_a', config)
        self.assertIn('/srv/diamaneos-staging/apps/current', config)
        self.assertIn('/etc/letsencrypt/live/diamaneos-staging/', config)
        self.assertIn('attestation.staging.diamaneos.de', config)
        self.assertIn('Disallow: /', config)
        self.assertIn('X-Robots-Tag', (self.output / 'noindex.conf').read_text())
        self.assertIn('include noindex.conf;', (self.output / 'nginx.conf').read_text())
        website = (self.output / 'mirror.conf').read_text().split('server_name staging.diamaneos.de;')[2]
        self.assertIn('keepalive_requests 64;\n    keepalive_timeout 15s;', website.split('server {')[0])

    def test_staging_crawler_policy_merges_into_locations_without_duplicates(self):
        self.render()
        text='\n'.join(p.read_text() for p in self.output.glob('*.conf'))
        # noindex.conf, and each location that does not merge repeats it.
        self.assertEqual(1+text.count('add_header_inherit on;'),text.count('add_header X-Robots-Tag'))
        self.assertNotIn('NOINDEX_HEADER',text)
        self.assertIn('add_header_inherit merge;',text)
        self.assertIn('include noindex.conf;',text)
        self.assertIn('Disallow: /',text)
        self.assertIn('attestation.staging.diamaneos.de',text)
        self.assertNotIn('proxy_pass',text)

    def test_security_contact_files_as_on_the_production_website(self):
        self.render()
        website = (self.output / 'mirror.conf').read_text().split('server_name staging.diamaneos.de;')[2]
        blocks = {}
        for location, kind in (('= /.well-known/security.txt', 'text/plain'), ('= /security-public.asc', 'application/pgp-keys'),
                               ('= /security-public.pgp', 'application/pgp-keys'),
                               ('^~ /.well-known/openpgpkey/', 'application/octet-stream')):
            block = blocks[location] = website.split('location ' + location + ' {\n')[1].split('\n    }\n')[0]
            self.assertTrue(block.lstrip().startswith('if ($request_method !~ ^(?:GET|HEAD)$) { return 405; }'))
            self.assertIn('types { }\n        default_type ' + kind + ';', block)
            self.assertTrue(block.endswith('try_files $uri =404;'))
        self.assertIn('charset utf-8;', blocks['= /.well-known/security.txt'])
        keys = blocks['^~ /.well-known/openpgpkey/']
        self.assertIn('(?:policy|hu/t5s8ztdbon8yzntexy6oz5y48etqsnbb)$) { return 404; }', keys)
        self.assertIn('add_header_inherit on;', keys)
        self.assertEqual(11, keys.count('add_header '))
        for header in ('Cross-Origin-Resource-Policy "cross-origin"', 'Access-Control-Allow-Origin "*"',
                       'Strict-Transport-Security "max-age=31536000; includeSubDomains"',
                       'X-Robots-Tag "noindex, nofollow, noarchive"'):
            self.assertIn('add_header ' + header + ' always;', keys)

    def test_installer_site_uses_staging_names_and_its_own_lineage(self):
        self.render()
        text = (self.output / 'installer.conf').read_text()
        for line in ('server_name install.staging.diamaneos.de;', 'root /srv/diamaneos-staging/acme;',
                     'ssl_certificate_key /etc/letsencrypt/live/diamaneos-staging-installer/privkey.pem;',
                     'root /srv/diamaneos-staging/installer/current;', 'include installer-page.conf;',
                     'keepalive_timeout 15s;'):
            self.assertIn(line, text)
        self.assertIn('connect-src https://releases.diamaneos.de;', (self.output / 'installer-page.conf').read_text())
        for name, policy in (('installer-page.conf', 'connect-src https://releases.diamaneos.de; img-src https://diamaneos.de;'),
                             ('installer-general.conf', 'connect-src https://releases.diamaneos.de;')):
            with self.assertRaises(ValueError): renderer.validate({name: policy}, 'web')
        self.assertIn('include mirror.conf;\n    include installer.conf;', (self.output / 'nginx.conf').read_text())
        shutil.rmtree(self.output)
        renderer.render('web', self.source, self.output, self.headers, installer_pending=True)
        text = (self.output / 'installer.conf').read_text()
        self.assertIn('location /.well-known/acme-challenge/', text)
        self.assertNotIn('443', text)
        self.assertFalse((self.output / 'installer-page.conf').exists())

    def test_attestation_is_separate_loopback_and_closed(self):
        self.render('attestation-disabled')
        self.assertEqual('return 503;\n', (self.output / 'service-state.conf').read_text())
        text = (self.output / 'nginx.conf').read_text()
        self.assertIn('server [::1]:8080', text)
        self.assertIn('attestation.staging.diamaneos.de', text)
        self.assertNotIn('releases.staging', text)

    def test_unknown_hostname_and_unmapped_directives_refuse_without_output(self):
        entry = self.source / 'releases/nginx/releases.conf'
        for text in ('server {\n server_name unexpected.diamaneos.de;\n}\n',
                     'server { server_name releases.diamaneos.de; }\n',
                     'server {\n server_name releases.diamaneos.de;\n alias /srv/private;\n}\n'):
            entry.write_text(text)
            with self.assertRaises(ValueError): self.render()
            self.assertFalse(self.output.exists())

    def test_no_clobber_or_symlink_output(self):
        self.output.mkdir()
        marker = self.output / 'preserve'
        marker.write_text('existing')
        with self.assertRaises(ValueError): self.render()
        self.assertEqual('existing', marker.read_text())
        shutil.rmtree(self.output)
        self.output.symlink_to(self.root / 'missing')
        with self.assertRaises(ValueError): self.render()

    def test_header_includes_and_production_urls_refuse(self):
        for text in ('include /etc/private.conf;\n',
                     'add_header Content-Security-Policy "https://diamaneos.de";\nadd_header X-Content-Type-Options nosniff;\n'):
            self.headers.write_text(text)
            with self.assertRaises(ValueError): self.render()
            self.assertFalse(self.output.exists())

    def test_external_attestation_backend_is_refused(self):
        entry = self.source / 'attestation/nginx/nginx.conf'
        entry.write_text(entry.read_text().replace('[::1]:8080', '192.0.2.1:8080'))
        with self.assertRaises(ValueError): self.render('attestation-disabled')

    def test_input_files_are_unchanged_and_source_symlink_refuses(self):
        before = {str(p): p.read_bytes() for p in self.source.rglob('*') if p.is_file()}
        self.render()
        self.assertEqual(before, {str(p): p.read_bytes() for p in self.source.rglob('*') if p.is_file()})
        shutil.rmtree(self.output)
        self.headers.unlink(); self.headers.symlink_to(self.source / 'releases/nginx/headers.conf')
        with self.assertRaises(ValueError): self.render()


if __name__ == '__main__':
    unittest.main()
