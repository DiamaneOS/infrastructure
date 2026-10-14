# SPDX-License-Identifier: Apache-2.0
"""Read fixed service destinations from a root-controlled external configuration."""
import ipaddress
import json
import os
from pathlib import Path
import re
import stat

HOSTNAME = re.compile(r'^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$')
DEFAULT_CONFIG = Path('/etc/diamaneos/egress-services.json')
MAX_CONFIG_BYTES = 16 * 1024


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate service destination')
        result[key] = value
    return result


def load_destinations(path=DEFAULT_CONFIG, *, uid=0):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return {}
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_mode & 0o022:
            raise ValueError('service destination configuration is not protected')
        raw = stream.read(MAX_CONFIG_BYTES + 1)
    if len(raw) > MAX_CONFIG_BYTES:
        raise ValueError('service destination configuration exceeds its limit')
    result = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(result, dict) or not set(result) <= {'smtp', 'monitor'}:
        raise ValueError('unsupported service destination group')
    for name, entry in result.items():
        if not isinstance(entry, dict) or set(entry) != {'port', 'hostnames'}:
            raise ValueError('unsupported service destination fields')
        port = entry['port']
        if type(port) is not int or port not in ({465, 587} if name == 'smtp' else {443}):
            raise ValueError('unsupported service destination port')
        hosts = entry['hostnames']
        if not isinstance(hosts, list) or not 1 <= len(hosts) <= 16 or not all(isinstance(host, str) for host in hosts):
            raise ValueError('invalid service destination count')
        if len(set(hosts)) != len(hosts) or not all(HOSTNAME.fullmatch(host) for host in hosts):
            raise ValueError('invalid service destination hostname')
    return {name: (entry['port'], entry['hostnames']) for name, entry in result.items()}


SEEN_STATE = Path('/var/lib/diamaneos-egress/seen.json')
# Rotating DNS answers (CDN pools) differ between nginx's own lookups and this refresh, so a set
# holding only the latest answer refuses addresses nginx still uses. Keep each address for an hour
# after it was last resolved.
SEEN_SECONDS = 3600


def merge_seen(previous, current, now, keep=SEEN_SECONDS):
    """Per group: the addresses resolved now, plus those resolved within the last keep seconds."""
    merged = {}
    for group, addresses in previous.items():
        if not isinstance(addresses, dict):
            continue
        kept = {}
        for address, seen in addresses.items():
            try:
                public = ipaddress.ip_address(address).is_global
            except ValueError:
                continue
            if public and type(seen) in (int, float) and now - keep < seen <= now:
                kept[address] = seen
        if kept:
            merged[group] = kept
    for group, addresses in current.items():
        merged.setdefault(group, {}).update({address: now for address in addresses})
    return merged


def load_seen(path=SEEN_STATE):
    """The saved addresses, or none when the file is missing or unreadable."""
    try:
        result = json.loads(Path(path).read_bytes())
    except (OSError, ValueError):
        return {}
    return result if isinstance(result, dict) else {}


def save_seen(seen, path=SEEN_STATE):
    path = Path(path)
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(seen, sort_keys=True))
    os.replace(temporary, path)
