"""Opt-in integrations and local network listeners for a public installation."""

import ipaddress
import os
import shutil
from pathlib import Path

from aifilter import config

LAN = tuple(ipaddress.ip_network(value) for value in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7",
))


def listen_ip(value: str, version: int) -> str:
    if not isinstance(value, str):
        raise ValueError("listener must be configured as an IP address string")
    address = ipaddress.ip_address(value)
    if address.version != version or not (address.is_loopback or any(address in net for net in LAN)):
        raise ValueError("listener must use a loopback or private LAN address")
    return str(address)


def listen_ipv4(section: str) -> str:
    return listen_ip(config.load().get(section, "listen_host", "127.0.0.1"), 4)


def optional_path(setting: str, filename: str | None = None, *, directory: bool = False) -> Path | None:
    if not (value := os.environ.get(setting)):
        return None
    path = Path(value).expanduser()
    if filename:
        path = path / filename
    exists = path.is_dir() if directory else path.is_file()
    return path if exists else None


def bridge_executable() -> str | None:
    command = os.environ.get("AIFILTER_NOTIFICATION_COMMAND")
    return shutil.which(command) if command else None
