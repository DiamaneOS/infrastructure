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

    def render(self, role='web', attestation=False):
        renderer.render(role, self.source, self.output, self.headers, attestation)

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
        self.assertNotIn('attestation', (self.output / 'mirror.conf').read_text())
        self.assertNotIn('attestation.staging.diamaneos.de', config)
        self.assertIn('Disallow: /', config)
        self.assertIn('X-Robots-Tag', (self.output / 'noindex.conf').read_text())
        self.assertIn('include noindex.conf;', (self.output / 'nginx.conf').read_text())

    def test_staging_crawler_policy_merges_into_locations_without_duplicates(self):
        self.render()
        text='\n'.join(p.read_text() for p in self.output.glob('*.conf'))
        self.assertEqual(1,text.count('add_header X-Robots-Tag'))
        self.assertIn('add_header_inherit merge;',text)
        self.assertIn('include noindex.conf;',text)
        self.assertIn('Disallow: /',text)
        self.assertNotIn('proxy_pass',text)

    def test_closed_attestation_frontend_only_on_request(self):
        self.render(attestation=True)
        text = (self.output / 'mirror.conf').read_text()
        self.assertEqual(2, text.count('server_name attestation.staging.diamaneos.de;'))
        self.assertEqual(2, text.count('return 503 "DiamaneOS attestation enrollment is closed.\\n";'))
        shutil.rmtree(self.output)
        with self.assertRaises(ValueError): self.render('attestation-disabled', attestation=True)

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
