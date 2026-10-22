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
        (release / 'releases.conf').write_text('server {\n server_name releases.diamaneos.de apps.diamaneos.de;\n include headers.conf;\n ssl_certificate /etc/letsencrypt/live/diamaneos-artifacts/fullchain.pem;\n ssl_certificate_key /etc/letsencrypt/live/diamaneos-artifacts/privkey.pem;\n include root_apps.diamaneos.de.conf;\n location ^~ /grapheneos/ {\n  root /srv/apps.diamaneos.de-grapheneos;\n }\n}\n')
        (release / 'root_apps.diamaneos.de.conf').write_text('root /srv/apps.diamaneos.de_a;\n')
        attestation = self.source / 'attestation/nginx'
        (attestation / 'nginx.conf').write_text('events {}\nhttp {\n upstream backend { server [::1]:8080; }\n server {\n server_name attestation.diamaneos.de;\n ssl_certificate /etc/letsencrypt/live/diamaneos-attestation/fullchain.pem;\n ssl_certificate_key /etc/letsencrypt/live/diamaneos-attestation/privkey.pem;\n include service-state.conf;\n include root_attestation.diamaneos.de.conf;\n }\n}\n')
        (attestation / 'service-state.conf').write_text('return 503 "DiamaneOS attestation enrollment is closed.\\n";\n')
        (attestation / 'root_attestation.diamaneos.de.conf').write_text('root /srv/attestation.diamaneos.de_a;\n')
        self.headers = self.root / 'website-headers.conf'
        self.headers.write_text('add_header Content-Security-Policy "default-src none";\nadd_header X-Content-Type-Options nosniff;\n')
        self.installer = self.root / 'installer-headers'
        self.installer.mkdir()
        (self.installer / 'website-installer-base.conf').write_text('# Every response.\nadd_header X-Content-Type-Options "nosniff" always;\n')
        (self.installer / 'website-installer-page.conf').write_text(
            'add_header Content-Security-Policy "default-src \'none\'; connect-src https://releases.diamaneos.de; script-src \'self\'" always;\n')
        (self.installer / 'website-installer-general.conf').write_text('add_header Content-Security-Policy "default-src \'none\'" always;\n')
        self.output = self.root / 'output'

    def render(self, role='web'):
        renderer.render(role, self.source, self.output, self.headers, installer_headers=self.installer)

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
        self.assertNotIn('/srv/apps.diamaneos.de-grapheneos', config)
        self.assertIn('root /srv/diamaneos-staging/apps-grapheneos;', config)
        self.assertIn('/etc/letsencrypt/live/diamaneos-staging/', config)
        self.assertIn('attestation.staging.diamaneos.de', config)
        self.assertIn('Disallow: /', config)
        self.assertIn('X-Robots-Tag', (self.output / 'noindex.conf').read_text())
        self.assertIn('include noindex.conf;', (self.output / 'nginx.conf').read_text())
        website = (self.output / 'mirror.conf').read_text().split('server_name staging.diamaneos.de;')[2]
        self.assertIn('keepalive_requests 64;\n    keepalive_timeout 15s;', website.split('server {')[0])

    def test_update_tests_add_second_release_name_fault_files_and_no_file_cache(self):
        release = self.source / 'releases/nginx/releases.conf'
        release.write_text(
            'server {\n listen 80;\n server_name releases.diamaneos.de apps.diamaneos.de;\n location / { return 404; }\n}\n'
            'server {\n listen 443 ssl;\n server_name releases.diamaneos.de;\n'
            ' ssl_certificate /etc/letsencrypt/live/diamaneos-artifacts/fullchain.pem;\n'
            ' ssl_certificate_key /etc/letsencrypt/live/diamaneos-artifacts/privkey.pem;\n'
            ' open_file_cache max=2048 inactive=1d;\n open_file_cache_valid 1d;\n'
            ' location /metadata { open_file_cache max=1 inactive=1d;\n  open_file_cache_valid 5s; }\n}\n'
            'server {\n listen 443 ssl;\n server_name apps.diamaneos.de;\n'
            ' ssl_certificate /etc/letsencrypt/live/diamaneos-artifacts/fullchain.pem;\n'
            ' ssl_certificate_key /etc/letsencrypt/live/diamaneos-artifacts/privkey.pem;\n'
            ' open_file_cache max=2048 inactive=1d;\n include root_apps.diamaneos.de.conf;\n}\n')
        self.render()
        plain = (self.output / 'releases.conf').read_text()
        self.assertNotIn('releases-na.staging', plain)
        self.assertNotIn('/releases/fault', plain)
        shutil.rmtree(self.output)
        renderer.render('web', self.source, self.output, self.headers, self.installer, update_tests=True)
        text = (self.output / 'releases.conf').read_text()
        http, https, apps = text.split('server {')[1:]
        self.assertIn('server_name releases.staging.diamaneos.de apps.staging.diamaneos.de releases-na.staging.diamaneos.de;', http)
        self.assertNotIn('/releases/fault', http)
        self.assertIn('server_name releases.staging.diamaneos.de releases-na.staging.diamaneos.de;\n'
                      ' if (-f /srv/diamaneos-staging/releases/fault/$host) { return 503; }', https)
        self.assertEqual(2, https.count('open_file_cache off;'))
        self.assertNotIn('open_file_cache_valid', https)
        self.assertNotIn('releases-na', apps)
        self.assertIn('open_file_cache max=2048', apps)
        with self.assertRaises(ValueError):
            renderer.render('attestation-disabled', self.source, self.root / 'other', update_tests=True)

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

    def test_releases_feed_as_on_the_production_website(self):
        self.render()
        website = (self.output / 'mirror.conf').read_text().split('server_name staging.diamaneos.de;')[2]
        feed = website.split('location = /releases.atom {\n')[1].split('\n    }\n')[0]
        self.assertTrue(feed.lstrip().startswith('if ($request_method !~ ^(?:GET|HEAD)$) { return 405; }'))
        self.assertIn('types { }\n        default_type application/atom+xml;\n        charset utf-8;\n'
                      '        charset_types application/atom+xml;\n        add_header_inherit on;', feed)
        self.assertEqual(10, feed.count('add_header '))
        self.assertIn('add_header Cross-Origin-Resource-Policy "cross-origin" always;', feed)
        self.assertIn('add_header X-Robots-Tag "noindex, nofollow, noarchive" always;', feed)
        self.assertNotIn('Access-Control-Allow-Origin', feed)
        self.assertTrue(feed.endswith('try_files $uri =404;'))

    def test_website_answers_missing_pages_with_its_404_page(self):
        self.render()
        text = (self.output / 'mirror.conf').read_text()
        self.assertEqual(1, text.count('error_page 404 /404.html;'))
        website = text.split('server_name staging.diamaneos.de;')[2].split('\n}\n')[0]
        self.assertIn('error_page 404 /404.html;', website)

    def test_public_keys_as_on_the_production_website(self):
        self.render()
        website = (self.output / 'mirror.conf').read_text().split('server_name staging.diamaneos.de;')[2]
        self.assertLess(website.index('location ^~ /keys/ {'), website.index('|pem|key|'))
        for location in ('/keys', '/keys/'):
            self.assertIn('location = ' + location + ' { return 301 /documentation/keys/; }', website)
        block = website.split('location ^~ /keys/ {\n')[1].split('\n    }\n')[0]
        self.assertIn(r'if ($uri !~ ^/keys/(?:avb_pkmd\.bin|avb\.pub\.pem|factory\.allowed_signers|apps\.0\.pub|'
                      r'release-list\.pub\.pem)$) { return 404; }', block)
        self.assertIn('types { application/octet-stream bin; }\n        default_type text/plain;', block)
        self.assertNotIn('add_header', block)
        self.assertTrue(block.endswith('try_files $uri =404;'))

    def test_website_serves_the_installer_with_its_own_headers(self):
        self.render()
        self.assertNotIn('install.staging', '\n'.join(p.read_text() for p in self.output.glob('*.conf')))
        website = (self.output / 'mirror.conf').read_text().split('server_name staging.diamaneos.de;')[2]
        self.assertIn('location = /install/web { return 301 /install/web/; }', website)
        block = website.split('location ^~ /install/web/ {\n')[1].split('\n    }\n')[0]
        self.assertEqual(4, block.count('add_header_inherit on;'))
        self.assertEqual(4, block.count('add_header X-Robots-Tag "noindex, nofollow, noarchive" always;'))
        self.assertEqual(4, block.count('include website-installer-base.conf;'))
        self.assertEqual(2, block.count('include website-installer-page.conf;'))
        self.assertIn('try_files /install/web/index.html =404;', block)
        self.assertIn('text/javascript js mjs;', block)
        self.assertNotIn('website-headers.conf', block)
        self.assertEqual('add_header X-Content-Type-Options "nosniff" always;\n',
                         (self.output / 'website-installer-base.conf').read_text())
        self.assertIn('connect-src https://releases.diamaneos.de;', (self.output / 'website-installer-page.conf').read_text())
        with self.assertRaises(ValueError):
            renderer.validate({'website-installer-general.conf': 'connect-src https://releases.diamaneos.de;'}, 'web')
        shutil.rmtree(self.output)
        with self.assertRaises(ValueError): renderer.render('web', self.source, self.output, self.headers)

    def test_html_is_revalidated(self):
        self.render()
        text = (self.output / 'mirror.conf').read_text()
        self.assertIn('map $sent_http_content_type $website_cache_control {\n    ~^text/html "no-cache";\n    default "";\n}', text)
        server = text.split('server_name staging.diamaneos.de;')[2].split('location ')[0]
        self.assertIn('include website-headers.conf;\n    add_header Cache-Control $website_cache_control always;', server)

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
