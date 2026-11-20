"""Offline PSL matching, including PRIVATE domains, wildcards and exceptions.

Algorithm: https://github.com/publicsuffix/list/wiki/Format
The vendored list is loaded once; no network or optional dependency at runtime.
"""

import ipaddress
from functools import lru_cache
from pathlib import Path


def normalize(host):
    host = (host or '').lower().strip('[]').rstrip('.')
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        return host.encode('idna').decode('ascii')


@lru_cache(maxsize=1)
def _rules():
    exact, wildcard, exceptions = set(), set(), set()
    for line in Path(__file__).with_name('public_suffix_list.dat').read_text().splitlines():
        line = line.strip()
        if not line or line.startswith('//'):
            continue
        target = exceptions if line.startswith('!') else wildcard if line.startswith('*.') else exact
        target.add(normalize(line.removeprefix('!').removeprefix('*.')))
    return exact, wildcard, exceptions


@lru_cache(maxsize=8192)
def registrable(host: str) -> str:
    host = normalize(host)
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    parts = host.split('.')
    exact, wildcard, exceptions = _rules()
    suffix_size = 1  # PSL's implicit * for unknown/private TLDs
    for i in range(len(parts)):
        suffix = '.'.join(parts[i:])
        size = len(parts) - i
        if suffix in exceptions:
            suffix_size = size - 1
            break
        if suffix in exact or (i + 1 < len(parts) and '.'.join(parts[i + 1:]) in wildcard):
            suffix_size = max(suffix_size, size)
    return '.'.join(parts[-(suffix_size + 1):])


def ancestors(host: str) -> list[str]:
    """Most specific first, stopping at the registrable tenant boundary."""
    host = normalize(host)
    base = registrable(host)
    names = [host]
    while host != base and '.' in host:
        host = host.split('.', 1)[1]
        names.append(host)
    return names
