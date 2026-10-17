#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
"""Render bounded, separate staging web or disabled-attestation configurations."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
HERE = Path(__file__).resolve().parent
BASE = '/srv/diamaneos-staging'
HOSTS = {
    'mirror.diamaneos.de': 'staging.diamaneos.de',
    'releases-na.diamaneos.de': 'releases.staging.diamaneos.de',
    'apps-na.diamaneos.de': 'apps.staging.diamaneos.de',
    'attestation.diamaneos.de': 'attestation.staging.diamaneos.de',
}
FILES = {
    'root_releases.diamaneos.de.conf': 'root_releases.staging.diamaneos.de.conf',
    'root_apps.diamaneos.de.conf': 'root_apps.staging.diamaneos.de.conf',
    'root_attestation.diamaneos.de.conf': 'root_attestation.staging.diamaneos.de.conf',
}
ROOTS = {
    '/srv/releases.diamaneos.de_a': BASE + '/releases/current',
    '/srv/apps.diamaneos.de_a': BASE + '/apps/current',
    '/srv/releases': BASE + '/releases/metadata',
    '/srv/attestation.diamaneos.de_a': BASE + '/attestation/public',
    '/var/lib/letsencrypt/webroot': BASE + '/acme',
    '/var/empty': '/var/empty',
}
LINEAGES = {
    'diamaneos-primary': 'diamaneos-staging',
    'diamaneos-mirror': 'diamaneos-staging',
    'diamaneos-mirror-artifacts': 'diamaneos-staging',
    'diamaneos-attestation': 'diamaneos-staging',
}
DIRECTIVE = re.compile(r'(?m)^(\s*)(server_name|ssl_certificate_key|ssl_certificate|root|alias|include|return)\s+([^;\n]+);')
DOMAIN = re.compile(r'(?<![\w.-])(?:[a-z0-9-]+\.)*diamaneos\.de(?![\w.-])')
# The installer page downloads releases from production. This one source may name it.
RELEASE_SOURCE = ({'website-installer-page.conf'}, 'connect-src https://releases.diamaneos.de;')
# The website's copy of the installer's headers, for /install/web/.
INSTALLER_HEADERS = ('website-installer-base.conf', 'website-installer-page.conf', 'website-installer-general.conf')
def require(value, message):
    if not value:
        raise ValueError(message)
def read(path, limit=1024 * 1024):
    path = Path(path)
    require(path.resolve() == path, 'Symlinked source is unsupported')
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= limit,
            'Source must be a bounded regular file')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        data = stream.read(limit + 1)
        signature = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        require(len(data) == info.st_size and signature(info) == signature(os.fstat(stream.fileno()))
                == signature(path.lstat()), 'Source changed during rendering')
    return data.decode('utf-8')
def rewrite(text):
    text = '\n'.join(line for line in text.splitlines() if not line.lstrip().startswith('#')) + '\n'
    def directive(match):
        indent, kind, value = match.groups()
        if kind == 'server_name':
            names = value.split()
            require(names and all(name in HOSTS for name in names), 'Unsupported serving hostname')
            value = ' '.join(HOSTS[name] for name in names)
        elif kind in ('ssl_certificate', 'ssl_certificate_key'):
            found = re.fullmatch(r'/etc/letsencrypt/live/([^/]+)/(fullchain\.pem|privkey\.pem)', value)
            require(found and found[1] in LINEAGES, 'Unsupported certificate path')
            leaf = 'privkey.pem' if kind == 'ssl_certificate_key' else 'fullchain.pem'
            require(found[2] == leaf, 'Unexpected certificate directive')
            value = '/etc/letsencrypt/live/' + LINEAGES[found[1]] + '/' + leaf
        elif kind in ('root', 'alias'):
            require(value in ROOTS, 'Unsupported serving root')
            value = ROOTS[value]
        elif kind == 'include':
            require(re.fullmatch(r'[A-Za-z0-9_.?*\[\]-]+', value), 'External include is unsupported')
            value = FILES.get(value, value)
        elif kind == 'return' and value.startswith('301 https://diamaneos.de/'):
            require(value == '301 https://diamaneos.de/releases', 'Unsupported redirect')
            value = '301 https://staging.diamaneos.de/releases'
        return indent + kind + ' ' + value + ';'
    return DIRECTIVE.sub(directive, text)
def validate(files, role):
    allowed = ({'staging.diamaneos.de', 'releases.staging.diamaneos.de', 'apps.staging.diamaneos.de',
                'attestation.staging.diamaneos.de'} if role == 'web'
               else {'attestation.staging.diamaneos.de'})
    for name, text in files.items():
        if not name.endswith('.conf'):
            continue
        checked = text.replace(RELEASE_SOURCE[1], '', 1) if name in RELEASE_SOURCE[0] else text
        # Filenames and arbitrary strings are checked too: missed directives fail closed.
        require(all(host in allowed for host in DOMAIN.findall(name + '\n' + checked)),
                'Production or unexpected hostname remains')
        require(not re.search(r'/srv/(?!diamaneos-staging(?:/|\b))', text)
                and not re.search(r'/etc/letsencrypt/live/(?!diamaneos-staging/)', text)
                and '/run/diamaneos-contact' not in text and '/var/lib/attestation' not in text,
                'Production path remains')
        require('proxy_pass' not in text if role == 'web' else True, 'Static web cannot proxy to a backend')
        for value in re.findall(r'(?m)^\s*include\s+([^;]+);', text):
            require(value in files, 'Unresolved include remains')
WEBSITE = '''# Browsers revalidate HTML on every visit, as on the production website.
map $sent_http_content_type $website_cache_control {
    ~^text/html "no-cache";
    default "";
}
server {
    listen 80; listen [::]:80;
    server_name staging.diamaneos.de;
    location /.well-known/acme-challenge/ { root /srv/diamaneos-staging/acme; }
    location / { return 301 https://staging.diamaneos.de$request_uri; }
}
server {
    listen 443 ssl; listen [::]:443 ssl;
    http2 on;
    server_name staging.diamaneos.de;
    ssl_certificate /etc/letsencrypt/live/diamaneos-staging/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/diamaneos-staging/privkey.pem;
    root /srv/diamaneos-staging/website/current;
    index index.html;
    absolute_redirect off; autoindex off;
    disable_symlinks on from=$document_root;
    access_log off;
    # As on the production website: one HTTP/2 connection for a page and its files.
    keepalive_requests 64;
    keepalive_timeout 15s;
    include website-headers.conf;
    add_header Cache-Control $website_cache_control always;
    location = /contact/submit { return 503; }
    location = /robots.txt { default_type text/plain; return 200 "User-agent: *\\nDisallow: /\\n"; }
    location = /healthz { default_type text/plain; return 200 "ready\\n"; }
    # The security contact files, as on the production website.
    location = /.well-known/security.txt {
        if ($request_method !~ ^(?:GET|HEAD)$) { return 405; }
        types { }
        default_type text/plain;
        charset utf-8;
        try_files $uri =404;
    }
    location = /security-public.asc {
        if ($request_method !~ ^(?:GET|HEAD)$) { return 405; }
        types { }
        default_type application/pgp-keys;
        try_files $uri =404;
    }
    location = /security-public.pgp {
        if ($request_method !~ ^(?:GET|HEAD)$) { return 405; }
        types { }
        default_type application/pgp-keys;
        try_files $uri =404;
    }
    # Production's header set for this location replaces the server's instead of merging.
    location ^~ /.well-known/openpgpkey/ {
        if ($request_method !~ ^(?:GET|HEAD)$) { return 405; }
        if ($uri !~ ^/\\.well-known/openpgpkey/(?:policy|hu/t5s8ztdbon8yzntexy6oz5y48etqsnbb)$) { return 404; }
        types { }
        default_type application/octet-stream;
        add_header_inherit on;
        add_header Content-Security-Policy "default-src 'none'; style-src 'self'; img-src 'self'; font-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header Referrer-Policy "same-origin" always;
        add_header Permissions-Policy "accelerometer=(), camera=(), geolocation=(), gyroscope=(), hid=(), magnetometer=(), microphone=(), payment=(), serial=(), usb=()" always;
        add_header Cross-Origin-Opener-Policy "same-origin" always;
        add_header Cross-Origin-Resource-Policy "cross-origin" always;
        add_header Cross-Origin-Embedder-Policy "require-corp" always;
        add_header X-Frame-Options "DENY" always;
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
        add_header Access-Control-Allow-Origin "*" always;
        NOINDEX_HEADER
        try_files $uri =404;
    }
    # The web installer with its own headers instead of the website's, as on the production website.
    location = /install/web { return 301 /install/web/; }
    location ^~ /install/web/ {
        if ($request_method !~ ^(?:GET|HEAD)$) { return 405; }
        types {
            text/html html;
            text/css css;
            text/javascript js mjs;
            application/json map;
            font/woff2 woff2;
        }
        default_type text/plain;
        charset utf-8;
        add_header_inherit on;
        include website-installer-base.conf;
        include website-installer-general.conf;
        add_header Cache-Control "no-cache" always;
        NOINDEX_HEADER
        try_files $uri =404;
        location = /install/web/ {
            add_header_inherit on;
            include website-installer-base.conf;
            include website-installer-page.conf;
            add_header Cache-Control "no-cache" always;
            NOINDEX_HEADER
            try_files /install/web/index.html =404;
        }
        location = /install/web/index.html {
            add_header_inherit on;
            include website-installer-base.conf;
            include website-installer-page.conf;
            add_header Cache-Control "no-cache" always;
            NOINDEX_HEADER
        }
        location ^~ /install/web/js/fastboot/ {
            add_header_inherit on;
            include website-installer-base.conf;
            include website-installer-general.conf;
            add_header Cache-Control "public, max-age=31536000, immutable" always;
            NOINDEX_HEADER
        }
    }
    # The short link the setup wizard shows, as on the production website.
    location ~* ^/ubl/?$ { return 301 /faq/#bootloader-locking-setup; }
    location ~ (^|/)\\. { return 404; }
    location ~* \\.(?:py|conf|toml|json|pem|key|cred|sqlite|db|sh)$ { return 404; }
    location / {
        if ($request_method !~ ^(?:GET|HEAD)$) { return 405; }
        try_files $uri $uri/ =404;
    }
}
'''
CLOSED = '''server {
    listen 80; listen [::]:80;
    server_name attestation.staging.diamaneos.de;
    location /.well-known/acme-challenge/ { root /srv/diamaneos-staging/acme; }
    location / { CLOSED_RESPONSE }
}
server {
    listen 443 ssl; listen [::]:443 ssl;
    server_name attestation.staging.diamaneos.de;
    ssl_certificate /etc/letsencrypt/live/diamaneos-staging/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/diamaneos-staging/privkey.pem;
    CLOSED_RESPONSE
}
'''
def header_file(path, limit=16384):
    text = read(path, limit)
    require(all(not line.strip() or line.lstrip().startswith('#') or line.lstrip().startswith('add_header ')
                for line in text.splitlines()), 'Unsupported website header directives')
    return text
def render(role, source, output, website_headers=None, installer_headers=None):
    source, output = Path(source), Path(output)
    require(source.resolve() == source, 'Symlinked source root is unsupported')
    require(role in ('web', 'attestation-disabled'), 'Unsupported staging role')
    require(not output.exists() and not output.is_symlink() and output.parent.resolve() == output.parent,
            'Output must be a fresh path without symlink ancestors')
    base_role = 'mirror' if role == 'web' else 'attestation'
    with tempfile.TemporaryDirectory(prefix='diamaneos-staging-') as directory:
        assembled = Path(directory).resolve() / 'assembled'
        subprocess.run([sys.executable, '-B', str(HERE.parent / 'assemble-nginx'), base_role,
                        str(source), str(assembled)], check=True, timeout=30)
        files = {path.name: read(path) for path in assembled.iterdir()}
    inputs = {name: hashlib.sha256(text.encode()).hexdigest() for name, text in files.items()}
    if role == 'web':
        # Replaced below. The production status page has no staging counterpart.
        del files['mirror.conf']
    files = {FILES.get(name, name): rewrite(text) if name.endswith('.conf') else text
             for name, text in files.items()}
    if role == 'web':
        require(website_headers is not None, 'Reviewed website headers are required')
        headers = header_file(Path(website_headers))
        require('Content-Security-Policy' in headers and 'X-Content-Type-Options' in headers,
                'Website security headers are missing')
        require(installer_headers is not None, 'The website\'s installer headers are required')
        for name in INSTALLER_HEADERS:
            text = header_file(Path(installer_headers) / name)
            require(name == 'website-installer-base.conf' or 'Content-Security-Policy' in text,
                    'Installer security headers are missing')
            files[name] = rewrite(text)
            inputs[name] = hashlib.sha256(text.encode()).hexdigest()
        state = read(source / 'attestation/nginx/service-state.conf', 16384)
        closed = re.findall(r'(?m)^\s*(return 503 "[^"\n]+";)', state)
        require(len(closed) == 1, 'Explicit closed attestation response is required')
        files['mirror.conf'] = WEBSITE + CLOSED.replace('CLOSED_RESPONSE', closed[0])
        inputs['closed-attestation-state'] = hashlib.sha256(state.encode()).hexdigest()
        files['website-headers.conf'] = headers
        inputs['website-headers.conf'] = hashlib.sha256(headers.encode()).hexdigest()
        require(files['nginx.conf'].count('include mirror.conf;') == 1, 'Website include is required')
    else:
        require('service-state.conf' in files, 'Attestation enrollment fence missing')
        files['service-state.conf'] = 'return 503;\n'
        require('server [::1]:8080' in files['nginx.conf'] or 'server 127.0.0.1:8080' in files['nginx.conf'],
                'Attestation backend must remain loopback-only')
    # The required nginx version merges inherited headers into nested locations.
    # Remove inherited crawler directives so the staging policy is unambiguous.
    for name, text in list(files.items()):
        if name.endswith('.conf'):
            files[name] = re.sub(r'(?m)^\s*add_header X-Robots-Tag [^\n]+;\n?', '', text)
    noindex = 'add_header X-Robots-Tag "noindex, nofollow, noarchive" always;'
    files['noindex.conf'] = 'add_header_inherit merge;\n' + noindex + '\n'
    if role == 'web':
        # A location that does not merge repeats the noindex header.
        files['mirror.conf'] = files['mirror.conf'].replace('NOINDEX_HEADER', noindex)
    require(files['nginx.conf'].count('http {') == 1, 'Explicit HTTP context is required')
    files['nginx.conf'] = files['nginx.conf'].replace('http {', 'http {\n    include noindex.conf;')
    validate(files, role)
    output.mkdir(mode=0o755)
    for name, text in sorted(files.items()):
        with (output / name).open('x') as stream:
            os.fchmod(stream.fileno(), 0o644)
            stream.write(text)
    manifest = {'schema_version': 1, 'role': role, 'input_sha256': inputs, 'output_sha256': {name: hashlib.sha256(text.encode()).hexdigest() for name, text in files.items()}}
    with (output / 'rendered.json').open('x') as stream:
        os.fchmod(stream.fileno(), 0o644)
        json.dump(manifest, stream, sort_keys=True, indent=2)
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('role', choices=('web', 'attestation-disabled'))
    parser.add_argument('source', type=Path); parser.add_argument('output', type=Path)
    parser.add_argument('--website-headers', type=Path)
    parser.add_argument('--installer-headers', type=Path, help="the website's server/nginx folder")
    args = parser.parse_args()
    render(args.role, args.source, args.output, args.website_headers, args.installer_headers)
if __name__ == '__main__':
    main()
