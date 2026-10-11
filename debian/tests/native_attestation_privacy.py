#!/usr/bin/python3
"""Check the actual privacy handlers with native nginx in an isolated network."""
from pathlib import Path
import hashlib
import http.client
import json
import os
import signal
import stat
import subprocess
import sys
import tempfile
import time


def location(text, name):
    start = text.index('        location = ' + name + ' {')
    opened = text.index('{', start)
    depth = 1
    cursor = opened + 1
    while depth and cursor < len(text):
        depth += (text[cursor] == '{') - (text[cursor] == '}')
        cursor += 1
    if depth:
        raise ValueError('location_boundary')
    return text[start:cursor]


def check(source):
    if (sys.platform != 'linux' or os.getuid() != 0 or os.geteuid() != 0
            or os.stat('/proc/self/ns/net').st_ino == os.stat('/proc/1/ns/net').st_ino):
        raise ValueError('isolated_namespace_required')
    binary = Path('/usr/sbin/nginx')
    info = binary.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError('native_binary_refused')
    names = ['nginx/nginx.conf', 'nginx/service-state.conf', 'nginx/security-headers.conf',
             'static/privacy-policy.html', 'static/privacy.css']
    bodies = {name: (source / name).read_bytes() for name in names}
    if any(not body or len(body) > 128 * 1024 for body in bodies.values()):
        raise ValueError('source_bounds')
    # This changes loopback only in the independently verified namespace.
    subprocess.run(['/usr/bin/ip', 'link', 'set', 'lo', 'up'], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
    facts = {}
    with tempfile.TemporaryDirectory(prefix='privacy-nginx-') as tmp:
        root = Path(tmp)
        web = root / 'web'
        web.mkdir()
        for name in ('privacy-policy.html', 'privacy.css'):
            (web / name).write_bytes(bodies['static/' + name])
        (root / 'service-state.conf').write_bytes(bodies['nginx/service-state.conf'])
        (root / 'security-headers.conf').write_bytes(bodies['nginx/security-headers.conf'])
        handlers = '\n'.join(location(bodies['nginx/nginx.conf'].decode(), name)
                             for name in ('/privacy-policy', '/privacy.css'))
        config = ('pid ' + str(root / 'nginx.pid') + ';\nerror_log /dev/null crit;\n'
            'events {}\nhttp { access_log off; default_type text/plain; charset utf-8;\n'
            'types { text/html html; text/css css; }\nserver { listen 127.0.0.1:18374;\n'
            'server_name attestation.diamaneos.de; root ' + str(web) + ';\n'
            'include service-state.conf;\n' + handlers + '\n}\n}\n')
        (root / 'nginx.conf').write_text(config)
        subprocess.run([str(binary), '-t', '-p', str(root) + '/', '-c', 'nginx.conf'],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
        child = subprocess.Popen([str(binary), '-p', str(root) + '/', '-c', 'nginx.conf',
            '-g', 'daemon off; master_process off;'], start_new_session=True,
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        def request(method, path):
            connection = http.client.HTTPConnection('127.0.0.1', 18374, timeout=2)
            try:
                connection.request(method, path, headers={'Host': 'attestation.diamaneos.de'})
                reply = connection.getresponse()
                return reply.status, dict(reply.getheaders()), reply.read(128 * 1024)
            finally:
                connection.close()

        try:
            end = time.monotonic() + 5
            while True:
                if child.poll() is not None:
                    raise ValueError('native_startup_failed')
                try:
                    request('GET', '/')
                    break
                except OSError:
                    if time.monotonic() >= end:
                        raise ValueError('native_startup_timeout')
                    time.sleep(.05)
            for method in ('GET', 'HEAD'):
                for path in ('/', '/api/create-account', '/api/login', '/auditor/challenge',
                             '/auditor/verify', '/privacy-policy.html', '/privacyXcss', '/donate'):
                    status, _, body = request(method, path)
                    if status != 503 or (method == 'GET' and body !=
                            b'DiamaneOS attestation enrollment is closed.\n'):
                        raise ValueError('closed_fence_changed')
            facts['closed_fence'] = True
            for path, name, mime in [('/privacy-policy', 'privacy-policy.html', 'text/html'),
                                     ('/privacy.css', 'privacy.css', 'text/css')]:
                status, headers, body = request('GET', path)
                if status != 200 or body != bodies['static/' + name] or not headers['Content-Type'].startswith(mime):
                    raise ValueError('public_policy_failed')
                if "frame-ancestors 'none'" not in headers.get('Content-Security-Policy', ''):
                    raise ValueError('security_headers_missing')
                if 'Set-Cookie' in headers:
                    raise ValueError('unexpected_cookie')
                status, _, body = request('HEAD', path)
                if status != 200 or body:
                    raise ValueError('policy_head_failed')
                status, _, _ = request('POST', path)
                if status != 405:
                    raise ValueError('policy_method_failed')
            facts['public_policy'] = facts['head'] = facts['method_refusal'] = True
        finally:
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait(timeout=5)
            if child.poll() is None:
                raise ValueError('owned_process_cleanup_failed')
        facts['owned_cleanup'] = True
    return {'schema_version': 1, 'status': 'PASS', 'isolated_network': True, 'checks': facts,
            'source_sha256': {name: hashlib.sha256(body).hexdigest() for name, body in bodies.items()},
            'native_sha256': hashlib.sha256(binary.read_bytes()).hexdigest()}


if __name__ == '__main__':
    try:
        print(json.dumps(check(Path(sys.argv[1])), sort_keys=True))
    except (OSError, ValueError, IndexError, KeyError, subprocess.SubprocessError):
        print(json.dumps({'schema_version': 1, 'status': 'FAIL', 'qualified': False}))
        raise SystemExit(2)
