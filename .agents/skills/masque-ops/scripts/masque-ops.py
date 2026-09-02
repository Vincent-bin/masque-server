#!/usr/bin/env python3
"""Safe, deterministic fleet operations for masque-server.

The script deliberately keeps inventory and credentials outside its own files.
Mutating commands require both an exact release tag and an explicit --apply.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import dataclasses
import datetime as dt
import ipaddress
import json
import os
import posixpath
import re
import secrets
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import tomllib

SCHEMA_VERSION = 1
SCRIPT_PATH = Path(__file__).resolve()
SKILL_ROOT = SCRIPT_PATH.parent.parent
INSTALLER_PATH = SKILL_ROOT / "scripts" / "install-latest.sh"


def protected_source_root() -> Path:
    """Return the checkout root, or the installed Skill root outside a checkout."""
    for candidate in SCRIPT_PATH.parents:
        checkout_skill = candidate / ".agents" / "skills" / "masque-ops"
        if (
            (candidate / ".git").exists()
            and (candidate / "Cargo.toml").is_file()
            and checkout_skill.resolve() == SKILL_ROOT
        ):
            return candidate
    return SKILL_ROOT


PROTECTED_SOURCE_ROOT = protected_source_root()
DEFAULT_INVENTORY = Path(
    os.environ.get(
        "MASQUE_OPS_INVENTORY",
        str(Path.home() / ".config" / "masque-server" / "fleet.toml"),
    )
).expanduser()
DEFAULT_STATE = Path.home() / ".local" / "state" / "masque-server" / "ops-state.json"
DEFAULT_REPOSITORY = "Vincent-bin/masque-server"
VERSION_RE = re.compile(
    r"^v(?P<major>0|[1-9][0-9]*)\."
    r"(?P<minor>0|[1-9][0-9]*)\."
    r"(?P<patch>0|[1-9][0-9]*)"
    r"(?P<prerelease>-(?:"
    r"0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*"
    r")(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?$"
)
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
USER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,63}$")
AUTH_USER_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$")
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
REMOTE_SERVICE = "masque.service"
REMOTE_CONFIG = "/etc/masque/masque.toml"
REMOTE_BINARY = "/usr/local/bin/masque-server"
REMOTE_CERT = "/etc/masque/certs/server.crt"
REMOTE_MAINTENANCE = "/usr/local/sbin/masque-maintain"


class OpsError(RuntimeError):
    """A user-facing operational failure."""


def load_ops_version() -> str:
    version_path = SKILL_ROOT / "VERSION"
    try:
        version = version_path.read_text(encoding="ascii").strip()
    except OSError as error:
        raise OpsError(f"bundled operations version is missing: {version_path}") from error
    if VERSION_RE.fullmatch(f"v{version}") is None:
        raise OpsError(f"bundled operations version is invalid: {version_path}")
    return version


def bundled_installer_text() -> str:
    """Load the generic server installer shipped inside this Skill."""
    if not INSTALLER_PATH.is_file():
        raise OpsError(f"bundled bootstrap installer is missing: {INSTALLER_PATH}")
    try:
        return INSTALLER_PATH.read_text(encoding="utf-8")
    except OSError as error:
        raise OpsError(
            f"bundled bootstrap installer could not be read: {INSTALLER_PATH}"
        ) from error


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def require_mapping(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise OpsError(f"{label} must be a TOML table")
    return value


def reject_unknown(mapping: dict[str, Any], allowed: set[str], label: str) -> None:
    unknown = sorted(set(mapping) - allowed)
    if unknown:
        raise OpsError(f"unknown {label} key(s): {', '.join(unknown)}")


def require_string(value: object, label: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value):
        raise OpsError(f"{label} must be a non-empty string")
    if any(character in value for character in ("\0", "\n", "\r")):
        raise OpsError(f"{label} must not contain control characters")
    return value


def require_bool(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise OpsError(f"{label} must be true or false")
    return value


def require_int(value: object, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise OpsError(f"{label} must be an integer")
    if not minimum <= value <= maximum:
        raise OpsError(f"{label} must be between {minimum} and {maximum}")
    return value


def resolve_local_path(value: str, inventory_dir: Path) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = inventory_dir / path
    # Normalize relative components without resolving symlinks. Secret and
    # inventory files are checked with lstat() so a symlink cannot bypass the
    # ownership and mode checks by resolving to its target first.
    return Path(os.path.abspath(path))


def ensure_private_file(path: Path, label: str) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError as error:
        raise OpsError(f"{label} does not exist: {path}") from error
    if stat.S_ISLNK(metadata.st_mode):
        raise OpsError(f"{label} must not be a symbolic link: {path}")
    if not stat.S_ISREG(metadata.st_mode):
        raise OpsError(f"{label} is not a regular file: {path}")
    if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
        raise OpsError(f"{label} is not owned by the current user: {path}")
    if metadata.st_mode & 0o077:
        raise OpsError(f"{label} must not be accessible by group or others: {path}")


def ensure_integrity_file(path: Path, label: str) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError as error:
        raise OpsError(f"{label} does not exist: {path}") from error
    if stat.S_ISLNK(metadata.st_mode):
        raise OpsError(f"{label} must not be a symbolic link: {path}")
    if not stat.S_ISREG(metadata.st_mode):
        raise OpsError(f"{label} is not a regular file: {path}")
    allowed_owners = {0}
    if hasattr(os, "getuid"):
        allowed_owners.add(os.getuid())
    if metadata.st_uid not in allowed_owners:
        raise OpsError(f"{label} has an untrusted owner: {path}")
    if metadata.st_mode & 0o022:
        raise OpsError(f"{label} must not be writable by group or others: {path}")


def ensure_private_parent(path: Path, label: str) -> None:
    parent = path.parent
    try:
        metadata = parent.lstat()
    except FileNotFoundError as error:
        raise OpsError(f"{label} parent directory does not exist") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise OpsError(f"{label} parent must be a real directory")
    if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
        raise OpsError(f"{label} parent is not owned by the current user")
    if metadata.st_mode & 0o077:
        raise OpsError(f"{label} parent must not be accessible by group or others")
    try:
        resolved_destination = parent.resolve(strict=True) / path.name
    except OSError as error:
        raise OpsError(f"could not resolve {label} parent") from error
    try:
        resolved_destination.relative_to(PROTECTED_SOURCE_ROOT.resolve())
    except ValueError:
        pass
    else:
        raise OpsError(f"{label} must be stored outside the operations tool directory")


def ensure_secret_destination(path: Path, label: str, *, allow_existing: bool) -> None:
    ensure_private_parent(path, label)
    try:
        path.lstat()
    except FileNotFoundError:
        return
    if not allow_existing:
        raise OpsError(f"{label} already exists; refusing to overwrite it")
    ensure_private_file(path, label)


def write_private_file(path: Path, data: bytes, label: str) -> None:
    ensure_secret_destination(path, label, allow_existing=False)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as error:
        raise OpsError(f"could not create {label}") from error
    succeeded = False
    try:
        remaining = memoryview(data)
        while remaining:
            written = os.write(descriptor, remaining)
            if written == 0:
                raise OSError("short write")
            remaining = remaining[written:]
        os.fsync(descriptor)
        succeeded = True
    except OSError as error:
        raise OpsError(f"could not write {label}") from error
    finally:
        os.close(descriptor)
        if not succeeded:
            try:
                path.unlink()
            except OSError:
                pass


def read_private_password(path: Path, label: str) -> str:
    ensure_private_file(path, label)
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise OpsError(f"could not read {label}") from error
    if raw.endswith(b"\n"):
        raw = raw[:-1]
    if not raw or len(raw) > 1024 or b"\0" in raw or b"\n" in raw or b"\r" in raw:
        raise OpsError(f"{label} must contain exactly one non-empty line")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise OpsError(f"{label} must be UTF-8") from error


def normalize_version(value: str) -> str:
    tag = value if value.startswith("v") else f"v{value}"
    if not VERSION_RE.fullmatch(tag):
        raise OpsError(f"invalid release version: {value}")
    return tag


def installed_version(value: str | None) -> str | None:
    if not value:
        return None
    match = re.search(
        r"(?<![0-9A-Za-z])([0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z][0-9A-Za-z.-]*)?)",
        value,
    )
    if not match:
        return None
    try:
        return normalize_version(match.group(1))
    except OpsError:
        return None


def version_order(
    tag: str,
) -> tuple[int, int, int, int, tuple[tuple[int, int, str], ...]]:
    match = VERSION_RE.fullmatch(normalize_version(tag))
    if match is None:
        raise OpsError(f"invalid release version: {tag}")
    prerelease = match.group("prerelease")
    identifiers: tuple[tuple[int, int, str], ...] = tuple(
        (0, int(identifier), "") if identifier.isdigit() else (1, 0, identifier)
        for identifier in (prerelease or "").lstrip("-").split(".")
        if identifier
    )
    return (
        int(match.group("major")),
        int(match.group("minor")),
        int(match.group("patch")),
        1 if prerelease is None else 0,
        identifiers,
    )


def safe_tail(stdout: str, stderr: str) -> str:
    sensitive = re.compile(
        r"password|password_hash|private[_ -]?key|authorization|username|"
        r"client-certificate enrollment|effective server configuration",
        re.IGNORECASE,
    )
    lines: list[str] = []
    for line in (stdout + "\n" + stderr).splitlines():
        if sensitive.search(line):
            continue
        cleaned = line.strip()
        if cleaned:
            lines.append(cleaned[:240])
    return " | ".join(lines[-6:]) or "no non-sensitive remote error was returned"


def sanitize_diagnostics(output: str) -> str:
    """Remove authentication material from otherwise bounded diagnostics."""
    sensitive = re.compile(
        r"password|password_hash|proxy-authorization|authorization:|"
        r"username|(?:client|identity|account)\s*=|private[_ -]?key|"
        r"client[_ -]?key|basic\s+[A-Za-z0-9+/=]+",
        re.IGNORECASE,
    )
    pem_begin = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")
    pem_end = re.compile(r"-----END [A-Z0-9 ]*PRIVATE KEY-----")
    redacted: list[str] = []
    inside_private_key = False
    for line in output.splitlines():
        if pem_begin.search(line):
            inside_private_key = True
            redacted.append("[redacted private key material]")
            continue
        if inside_private_key:
            if pem_end.search(line):
                inside_private_key = False
            continue
        if sensitive.search(line):
            redacted.append("[redacted sensitive diagnostic line]")
        else:
            redacted.append(line)
    return "\n".join(redacted) + ("\n" if output.endswith("\n") else "")


@dataclasses.dataclass(frozen=True)
class ProbeConfig:
    endpoint: str
    transport: str = "auto"
    username: str | None = None
    password_file: Path | None = None
    client_config: Path | None = None
    server_name: str | None = None
    resolve: str | None = None
    interface: str | None = None
    connect_ip: bool = False
    skip_tcp: bool = False
    skip_udp: bool = False
    tcp_target: str | None = None
    udp_target: str | None = None
    udp_mode: str = "dns"
    timeout_secs: int = 8
    ca_cert: Path | None = None


@dataclasses.dataclass(frozen=True)
class BootstrapConfig:
    auth_mode: str
    listen_port: int
    cert_listen_port: int | None
    tls_cert_path: str
    tls_key_path: str
    basic_username: str | None = None
    basic_stealth: bool = False
    basic_password_file: Path | None = None
    basic_client_endpoint: str | None = None
    basic_client_name: str | None = None
    basic_client_config: Path | None = None
    client_name: str | None = None
    client_endpoint: str | None = None
    client_ipv4: str | None = None
    client_ipv6: str | None = None
    client_config: Path | None = None

    @property
    def uses_basic(self) -> bool:
        return self.auth_mode in {"basic", "dual"}

    @property
    def uses_client_certs(self) -> bool:
        return self.auth_mode in {"client_cert", "dual"}


@dataclasses.dataclass(frozen=True)
class Host:
    name: str
    address: str
    user: str
    port: int
    identity_file: Path | None
    known_hosts_file: Path | None
    use_sudo: bool
    service: str
    config_path: str
    binary_path: str
    cert_path: str
    maintenance_path: str
    connect_timeout_secs: int
    command_timeout_secs: int
    deploy_timeout_secs: int
    canary: bool
    probe: ProbeConfig | None
    bootstrap: BootstrapConfig | None


@dataclasses.dataclass(frozen=True)
class Inventory:
    path: Path
    repository: str
    state_path: Path
    probe_binary: str
    hosts: tuple[Host, ...]

    def select(
        self, names: Sequence[str], *, require_names: bool = False
    ) -> tuple[Host, ...]:
        if not names:
            if require_names:
                raise OpsError("select an explicit host for this command")
            return self.hosts
        duplicates = sorted({name for name in names if names.count(name) > 1})
        if duplicates:
            raise OpsError(f"host selected more than once: {', '.join(duplicates)}")
        by_name = {host.name: host for host in self.hosts}
        unknown = [name for name in names if name not in by_name]
        if unknown:
            raise OpsError(f"unknown host(s): {', '.join(unknown)}")
        return tuple(by_name[name] for name in names)


TOP_LEVEL_KEYS = {
    "schema_version",
    "repository",
    "state_path",
    "probe_binary",
    "defaults",
    "hosts",
}
CONNECTION_KEYS = {
    "user",
    "port",
    "identity_file",
    "known_hosts_file",
    "sudo",
    "connect_timeout_secs",
    "command_timeout_secs",
    "deploy_timeout_secs",
}
HOST_KEYS = CONNECTION_KEYS | {"name", "address", "canary", "probe", "bootstrap"}
PROBE_KEYS = {
    "endpoint",
    "transport",
    "username",
    "password_file",
    "client_config",
    "server_name",
    "resolve",
    "interface",
    "connect_ip",
    "skip_tcp",
    "skip_udp",
    "tcp_target",
    "udp_target",
    "udp_mode",
    "timeout_secs",
    "ca_cert",
}
BOOTSTRAP_KEYS = {
    "auth_mode",
    "listen_port",
    "cert_listen_port",
    "tls_cert_path",
    "tls_key_path",
    "basic_username",
    "basic_stealth",
    "basic_password_file",
    "basic_client_endpoint",
    "basic_client_name",
    "basic_client_config",
    "client_name",
    "client_endpoint",
    "client_ipv4",
    "client_ipv6",
    "client_config",
}


def optional_path(
    mapping: dict[str, Any], key: str, inventory_dir: Path
) -> Path | None:
    value = mapping.get(key)
    if value is None:
        return None
    return resolve_local_path(require_string(value, key), inventory_dir)


def merged_value(
    host: dict[str, Any], defaults: dict[str, Any], key: str, fallback: object
) -> object:
    if key in host:
        return host[key]
    return defaults.get(key, fallback)


def parse_probe(raw: object, inventory_dir: Path, host_name: str) -> ProbeConfig:
    table = require_mapping(raw, f"hosts[{host_name}].probe")
    reject_unknown(table, PROBE_KEYS, f"hosts[{host_name}].probe")
    endpoint = require_string(
        table.get("endpoint"), f"hosts[{host_name}].probe.endpoint"
    )
    if any(character.isspace() for character in endpoint):
        raise OpsError(f"hosts[{host_name}].probe.endpoint must not contain whitespace")
    transport = require_string(table.get("transport", "auto"), "probe.transport")
    if transport not in {"auto", "http3", "http2"}:
        raise OpsError("probe.transport must be auto, http3, or http2")
    udp_mode = require_string(table.get("udp_mode", "dns"), "probe.udp_mode")
    if udp_mode not in {"dns", "echo"}:
        raise OpsError("probe.udp_mode must be dns or echo")

    username_raw = table.get("username")
    username = (
        None if username_raw is None else require_string(username_raw, "probe.username")
    )
    if username is not None and (
        ":" in username or any(character.isspace() for character in username)
    ):
        raise OpsError("probe.username must not contain a colon or whitespace")
    password_file = optional_path(table, "password_file", inventory_dir)
    client_config = optional_path(table, "client_config", inventory_dir)
    if (username is None) != (password_file is None):
        raise OpsError(
            "probe.username and probe.password_file must be configured together"
        )
    if client_config is not None and username is not None:
        raise OpsError("probe.client_config cannot be combined with Basic credentials")

    def optional_text(key: str) -> str | None:
        value = table.get(key)
        return None if value is None else require_string(value, f"probe.{key}")

    return ProbeConfig(
        endpoint=endpoint,
        transport=transport,
        username=username,
        password_file=password_file,
        client_config=client_config,
        server_name=optional_text("server_name"),
        resolve=optional_text("resolve"),
        interface=optional_text("interface"),
        connect_ip=require_bool(table.get("connect_ip", False), "probe.connect_ip"),
        skip_tcp=require_bool(table.get("skip_tcp", False), "probe.skip_tcp"),
        skip_udp=require_bool(table.get("skip_udp", False), "probe.skip_udp"),
        tcp_target=optional_text("tcp_target"),
        udp_target=optional_text("udp_target"),
        udp_mode=udp_mode,
        timeout_secs=require_int(
            table.get("timeout_secs", 8), "probe.timeout_secs", 1, 60
        ),
        ca_cert=optional_path(table, "ca_cert", inventory_dir),
    )


def require_endpoint(value: object, label: str) -> str:
    endpoint = require_string(value, label)
    if any(character.isspace() for character in endpoint):
        raise OpsError(f"{label} must not contain whitespace")
    return endpoint


def require_remote_path(value: object, label: str) -> str:
    path = require_string(value, label)
    if not path.startswith("/") or posixpath.normpath(path) != path:
        raise OpsError(f"{label} must be a normalized absolute path")
    return path


def optional_bootstrap_address(
    table: dict[str, Any], key: str, version: int
) -> str | None:
    raw = table.get(key)
    if raw is None:
        return "10.89.0.2" if version == 4 else "fd00:abcd::2"
    value = require_string(raw, f"bootstrap.{key}")
    if value.lower() in {"none", "-"}:
        return None
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError as error:
        raise OpsError(
            f"bootstrap.{key} must be an IPv{version} address or 'none'"
        ) from error
    if parsed.version != version:
        raise OpsError(f"bootstrap.{key} must be an IPv{version} address or 'none'")
    return str(parsed)


def parse_bootstrap(
    raw: object, inventory_dir: Path, host_name: str
) -> BootstrapConfig:
    table = require_mapping(raw, f"hosts[{host_name}].bootstrap")
    reject_unknown(table, BOOTSTRAP_KEYS, f"hosts[{host_name}].bootstrap")
    auth_mode = require_string(
        table.get("auth_mode"), f"hosts[{host_name}].bootstrap.auth_mode"
    )
    if auth_mode not in {"basic", "client_cert", "dual"}:
        raise OpsError("bootstrap.auth_mode must be basic, client_cert, or dual")
    uses_basic = auth_mode in {"basic", "dual"}
    uses_client_certs = auth_mode in {"client_cert", "dual"}
    listen_port = require_int(
        table.get("listen_port", 443), "bootstrap.listen_port", 1, 65535
    )
    cert_listen_port = None
    if auth_mode == "dual":
        cert_listen_port = require_int(
            table.get("cert_listen_port", 4443),
            "bootstrap.cert_listen_port",
            1,
            65535,
        )
        if cert_listen_port == listen_port:
            raise OpsError("bootstrap listener ports must be different")
    elif "cert_listen_port" in table:
        raise OpsError("bootstrap.cert_listen_port is valid only for dual mode")

    basic_username = None
    basic_password_file = None
    basic_client_endpoint = None
    basic_client_name = None
    basic_client_config = None
    if uses_basic:
        basic_username = require_string(
            table.get("basic_username", "masque"), "bootstrap.basic_username"
        )
        if not AUTH_USER_RE.fullmatch(basic_username):
            raise OpsError(
                "bootstrap.basic_username may contain only letters, digits, '.', '_', and '-'"
            )
        basic_password_file = optional_path(table, "basic_password_file", inventory_dir)
        if basic_password_file is None:
            raise OpsError("bootstrap.basic_password_file is required for Basic mode")
        if "basic_client_endpoint" in table:
            basic_client_endpoint = require_endpoint(
                table["basic_client_endpoint"], "bootstrap.basic_client_endpoint"
            )
        basic_client_name_raw = table.get("basic_client_name")
        if basic_client_name_raw is not None:
            basic_client_name = require_string(
                basic_client_name_raw, "bootstrap.basic_client_name"
            )
        basic_client_config = optional_path(table, "basic_client_config", inventory_dir)
        if (basic_client_endpoint is None) != (basic_client_config is None):
            raise OpsError(
                "bootstrap.basic_client_endpoint and basic_client_config must be configured together"
            )
    elif any(key.startswith("basic_") for key in table):
        raise OpsError("bootstrap Basic settings require basic or dual auth_mode")

    client_name = None
    client_endpoint = None
    client_ipv4 = None
    client_ipv6 = None
    client_config = None
    if uses_client_certs:
        client_name = require_string(
            table.get("client_name", "client"), "bootstrap.client_name"
        )
        client_endpoint = require_endpoint(
            table.get("client_endpoint"), "bootstrap.client_endpoint"
        )
        client_ipv4 = optional_bootstrap_address(table, "client_ipv4", 4)
        client_ipv6 = optional_bootstrap_address(table, "client_ipv6", 6)
        if client_ipv4 is None and client_ipv6 is None:
            raise OpsError(
                "bootstrap certificate client needs at least one pinned address"
            )
        client_config = optional_path(table, "client_config", inventory_dir)
        if client_config is None:
            raise OpsError("bootstrap.client_config is required for certificate mode")
    elif any(key.startswith("client_") for key in table):
        raise OpsError(
            "bootstrap certificate-client settings require client_cert or dual auth_mode"
        )

    return BootstrapConfig(
        auth_mode=auth_mode,
        listen_port=listen_port,
        cert_listen_port=cert_listen_port,
        tls_cert_path=require_remote_path(
            table.get("tls_cert_path"), "bootstrap.tls_cert_path"
        ),
        tls_key_path=require_remote_path(
            table.get("tls_key_path"), "bootstrap.tls_key_path"
        ),
        basic_username=basic_username,
        basic_stealth=require_bool(
            table.get("basic_stealth", False), "bootstrap.basic_stealth"
        ),
        basic_password_file=basic_password_file,
        basic_client_endpoint=basic_client_endpoint,
        basic_client_name=basic_client_name,
        basic_client_config=basic_client_config,
        client_name=client_name,
        client_endpoint=client_endpoint,
        client_ipv4=client_ipv4,
        client_ipv6=client_ipv6,
        client_config=client_config,
    )


def load_inventory(path: Path) -> Inventory:
    path = Path(os.path.abspath(path.expanduser()))
    ensure_private_file(path, "inventory")
    try:
        with path.open("rb") as handle:
            raw = tomllib.load(handle)
    except tomllib.TOMLDecodeError as error:
        raise OpsError(f"invalid inventory TOML: {error}") from error
    except OSError as error:
        raise OpsError(f"could not read inventory: {path}") from error
    reject_unknown(raw, TOP_LEVEL_KEYS, "top-level inventory")
    if (
        type(raw.get("schema_version")) is not int
        or raw["schema_version"] != SCHEMA_VERSION
    ):
        raise OpsError(f"inventory schema_version must be {SCHEMA_VERSION}")
    repository = require_string(raw.get("repository", DEFAULT_REPOSITORY), "repository")
    if not REPOSITORY_RE.fullmatch(repository):
        raise OpsError("repository must be in owner/name form")
    if repository != DEFAULT_REPOSITORY:
        raise OpsError(
            f"repository must be {DEFAULT_REPOSITORY}; the remote maintenance "
            "entrypoint is pinned to that release source"
        )
    inventory_dir = path.parent
    state_path_value = require_string(
        raw.get("state_path", str(DEFAULT_STATE)), "state_path"
    )
    state_path = resolve_local_path(state_path_value, inventory_dir)
    probe_binary = require_string(
        raw.get("probe_binary", "masque-probe"), "probe_binary"
    )
    defaults = require_mapping(raw.get("defaults", {}), "defaults")
    reject_unknown(defaults, CONNECTION_KEYS, "defaults")

    raw_hosts = raw.get("hosts")
    if not isinstance(raw_hosts, list) or not raw_hosts:
        raise OpsError("inventory must contain at least one [[hosts]] entry")
    hosts: list[Host] = []
    seen_names: set[str] = set()
    seen_destinations: set[tuple[str, str, int]] = set()
    for index, raw_host in enumerate(raw_hosts):
        table = require_mapping(raw_host, f"hosts[{index}]")
        reject_unknown(table, HOST_KEYS, f"hosts[{index}]")
        name = require_string(table.get("name"), f"hosts[{index}].name")
        if not NAME_RE.fullmatch(name):
            raise OpsError(f"invalid host name: {name}")
        if name in seen_names:
            raise OpsError(f"duplicate host name: {name}")
        seen_names.add(name)
        address = require_string(table.get("address"), f"hosts[{name}].address")
        if not HOST_RE.fullmatch(address):
            raise OpsError(f"invalid SSH address for host {name}: {address}")
        user = require_string(
            merged_value(table, defaults, "user", "root"), f"hosts[{name}].user"
        )
        if not USER_RE.fullmatch(user):
            raise OpsError(f"invalid SSH user for host {name}: {user}")
        port = require_int(
            merged_value(table, defaults, "port", 22), f"hosts[{name}].port", 1, 65535
        )
        destination = (user, address, port)
        if destination in seen_destinations:
            raise OpsError(f"duplicate SSH destination for host {name}")
        seen_destinations.add(destination)

        identity_raw = merged_value(table, defaults, "identity_file", None)
        identity_file = (
            None
            if identity_raw is None
            else resolve_local_path(
                require_string(identity_raw, "identity_file"), inventory_dir
            )
        )
        known_hosts_raw = merged_value(table, defaults, "known_hosts_file", None)
        known_hosts_file = (
            None
            if known_hosts_raw is None
            else resolve_local_path(
                require_string(known_hosts_raw, "known_hosts_file"), inventory_dir
            )
        )
        use_sudo = require_bool(
            merged_value(table, defaults, "sudo", user != "root"), f"hosts[{name}].sudo"
        )
        probe = None
        if "probe" in table:
            probe = parse_probe(table["probe"], inventory_dir, name)
        bootstrap = None
        if "bootstrap" in table:
            bootstrap = parse_bootstrap(table["bootstrap"], inventory_dir, name)
        if bootstrap is not None and probe is not None:
            if probe.password_file is not None and (
                not bootstrap.uses_basic
                or probe.username != bootstrap.basic_username
                or probe.password_file != bootstrap.basic_password_file
            ):
                raise OpsError(
                    f"hosts[{name}] Basic probe must use the bootstrap username and password file"
                )
            if probe.client_config is not None and (
                not bootstrap.uses_client_certs
                or probe.client_config != bootstrap.client_config
            ):
                raise OpsError(
                    f"hosts[{name}] certificate probe must use the bootstrap client configuration"
                )
        hosts.append(
            Host(
                name=name,
                address=address,
                user=user,
                port=port,
                identity_file=identity_file,
                known_hosts_file=known_hosts_file,
                use_sudo=use_sudo,
                service=REMOTE_SERVICE,
                config_path=REMOTE_CONFIG,
                binary_path=REMOTE_BINARY,
                cert_path=REMOTE_CERT,
                maintenance_path=REMOTE_MAINTENANCE,
                connect_timeout_secs=require_int(
                    merged_value(table, defaults, "connect_timeout_secs", 10),
                    f"hosts[{name}].connect_timeout_secs",
                    1,
                    60,
                ),
                command_timeout_secs=require_int(
                    merged_value(table, defaults, "command_timeout_secs", 60),
                    f"hosts[{name}].command_timeout_secs",
                    5,
                    600,
                ),
                deploy_timeout_secs=require_int(
                    merged_value(table, defaults, "deploy_timeout_secs", 900),
                    f"hosts[{name}].deploy_timeout_secs",
                    60,
                    3600,
                ),
                canary=require_bool(
                    table.get("canary", False), f"hosts[{name}].canary"
                ),
                probe=probe,
                bootstrap=bootstrap,
            )
        )
    return Inventory(path, repository, state_path, probe_binary, tuple(hosts))


def remote_argv(host: Host, arguments: Sequence[str], *, admin: bool) -> str:
    command = list(arguments)
    if admin and host.use_sudo:
        command = ["sudo", "-n", "--", *command]
    return " ".join(shlex.quote(argument) for argument in command)


class SshClient:
    def __init__(self) -> None:
        configured = os.environ.get("MASQUE_OPS_SSH", "ssh")
        resolved = shutil.which(configured) if "/" not in configured else configured
        if not resolved or not os.access(resolved, os.X_OK):
            raise OpsError(f"SSH client is not executable: {configured}")
        self.executable = resolved

    def arguments(self, host: Host, command: str) -> list[str]:
        arguments = [
            self.executable,
            "-F",
            "/dev/null",
            "-o",
            "BatchMode=yes",
            "-o",
            "PasswordAuthentication=no",
            "-o",
            "KbdInteractiveAuthentication=no",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "ClearAllForwardings=yes",
            "-o",
            "ForwardAgent=no",
            "-o",
            "PermitLocalCommand=no",
            "-o",
            "RequestTTY=no",
            "-o",
            "ControlMaster=no",
            "-o",
            "LogLevel=ERROR",
            "-o",
            f"ConnectTimeout={host.connect_timeout_secs}",
            "-o",
            "ServerAliveInterval=15",
            "-o",
            "ServerAliveCountMax=2",
            "-p",
            str(host.port),
        ]
        if host.identity_file is not None:
            ensure_private_file(host.identity_file, f"SSH identity for {host.name}")
            arguments.extend(
                ["-o", "IdentitiesOnly=yes", "-i", str(host.identity_file)]
            )
        if host.known_hosts_file is not None:
            ensure_integrity_file(
                host.known_hosts_file, f"known_hosts file for {host.name}"
            )
            arguments.extend(["-o", f"UserKnownHostsFile={host.known_hosts_file}"])
        arguments.extend([f"{host.user}@{host.address}", command])
        return arguments

    def run(
        self,
        host: Host,
        command: str,
        *,
        input_text: str | None = None,
        timeout: int | None = None,
    ) -> subprocess.CompletedProcess[str]:
        try:
            return subprocess.run(
                self.arguments(host, command),
                input=input_text,
                stdin=subprocess.DEVNULL if input_text is None else None,
                text=True,
                capture_output=True,
                timeout=timeout or host.command_timeout_secs,
                check=False,
            )
        except subprocess.TimeoutExpired as error:
            raise OpsError(f"SSH command timed out on {host.name}") from error
        except OSError as error:
            raise OpsError(f"could not start SSH for {host.name}: {error}") from error

    def download_private(
        self, host: Host, command: str, destination: Path, label: str
    ) -> None:
        """Stream a remote secret directly to a new mode-0600 local file."""
        ensure_secret_destination(destination, label, allow_existing=False)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(destination, flags, 0o600)
        except OSError as error:
            raise OpsError(f"could not create {label}") from error
        succeeded = False
        try:
            with os.fdopen(descriptor, "wb", closefd=True) as output:
                try:
                    completed = subprocess.run(
                        self.arguments(host, command),
                        stdin=subprocess.DEVNULL,
                        stdout=output,
                        stderr=subprocess.PIPE,
                        timeout=host.command_timeout_secs,
                        check=False,
                    )
                except subprocess.TimeoutExpired as error:
                    raise OpsError(
                        f"secret retrieval timed out on {host.name}"
                    ) from error
                except OSError as error:
                    raise OpsError(
                        f"could not start SSH for {host.name}: {error}"
                    ) from error
                output.flush()
                os.fsync(output.fileno())
            if completed.returncode != 0:
                stderr = completed.stderr.decode("utf-8", errors="replace")
                raise OpsError(
                    f"could not retrieve {label} from {host.name}: "
                    f"{safe_tail('', stderr)}"
                )
            size = destination.stat().st_size
            if size == 0:
                raise OpsError(f"{host.name} returned an empty {label}")
            if size > 1024 * 1024:
                raise OpsError(f"{host.name} returned an oversized {label}")
            succeeded = True
        finally:
            if not succeeded:
                try:
                    destination.unlink()
                except OSError:
                    pass


STATUS_SCRIPT = r"""# MASQUE_OPS_STATUS_V1
set -u
binary=$1
config=$2
service=$3
cert=$4
use_sudo=$5

admin() {
    if [ "$use_sudo" = 1 ]; then
        sudo -n -- "$@"
    else
        "$@"
    fi
}

version=$("$binary" --version 2>/dev/null | sed -n '1p')
arch=$(uname -m 2>/dev/null || true)
active=$(systemctl is-active "$service" 2>/dev/null || true)
enabled=$(systemctl is-enabled "$service" 2>/dev/null || true)
config_exists=no
config_check=missing
config_sha256=
if admin test -f "$config" 2>/dev/null; then
    config_exists=yes
    if admin "$binary" --config "$config" check-config >/dev/null 2>&1; then
        config_check=ok
    else
        config_check=failed
    fi
    config_sha256=$(admin sha256sum "$config" 2>/dev/null | awk 'NR == 1 { print $1 }')
fi
cert_not_after=$(admin openssl x509 -in "$cert" -noout -enddate 2>/dev/null |
    sed -n 's/^notAfter=//p')
disk_available_kb=$(df -Pk / 2>/dev/null | awk 'NR == 2 { print $4 }')
disk_used_percent=$(df -Pk / 2>/dev/null | awk 'NR == 2 { print $5 }')

printf '%s\n' \
    'masque_ops_status=1' \
    "version=$version" \
    "arch=$arch" \
    "service_active=$active" \
    "service_enabled=$enabled" \
    "config_exists=$config_exists" \
    "config_check=$config_check" \
    "config_sha256=$config_sha256" \
    "cert_not_after=$cert_not_after" \
    "disk_available_kb=$disk_available_kb" \
    "disk_used_percent=$disk_used_percent"
"""


DIAGNOSE_SCRIPT = r"""# MASQUE_OPS_DIAGNOSE_V1
set -u
binary=$1
config=$2
service=$3
cert=$4
use_sudo=$5
lines=$6

admin() {
    if [ "$use_sudo" = 1 ]; then
        sudo -n -- "$@"
    else
        "$@"
    fi
}

echo '== version =='
"$binary" --version 2>&1 || true
echo '== service =='
systemctl status "$service" --no-pager -l 2>&1 || true
echo '== configuration check =='
admin "$binary" --config "$config" check-config 2>&1 || true
echo '== host prerequisites =='
admin "$binary" --config "$config" doctor 2>&1 || true
echo '== certificate expiry =='
admin openssl x509 -in "$cert" -noout -enddate 2>&1 || true
echo '== root filesystem =='
df -h / 2>&1 || true
echo '== listening sockets =='
ss -H -lntu 2>&1 || true
echo '== recent warning journal =='
admin journalctl -u "$service" -p warning -n "$lines" --no-pager 2>&1 || true
"""


BOOTSTRAP_PREFLIGHT_SCRIPT = r"""# MASQUE_OPS_BOOTSTRAP_PREFLIGHT_V1
set -u
cert=$1
key=$2
binary=$3
config=$4

missing=
for required in curl tar sha256sum awk grep head mktemp install systemctl openssl getent groupadd useradd; do
    if ! command -v "$required" >/dev/null 2>&1; then
        if [ -n "$missing" ]; then
            missing="$missing,$required"
        else
            missing=$required
        fi
    fi
done

printf '%s\n' \
    'masque_ops_bootstrap_preflight=1' \
    "os=$(uname -s 2>/dev/null || true)" \
    "arch=$(uname -m 2>/dev/null || true)" \
    "binary_exists=$([ -e "$binary" ] && printf yes || printf no)" \
    "config_exists=$([ -e "$config" ] && printf yes || printf no)" \
    "tls_cert_readable=$([ -r "$cert" ] && printf yes || printf no)" \
    "tls_key_readable=$([ -r "$key" ] && printf yes || printf no)" \
    "missing_commands=$missing"
"""


@dataclasses.dataclass(frozen=True)
class BootstrapPreflight:
    reachable: bool
    os: str | None = None
    arch: str | None = None
    binary_exists: bool = False
    config_exists: bool = False
    tls_cert_readable: bool = False
    tls_key_readable: bool = False
    missing_commands: tuple[str, ...] = ()
    error: str | None = None


def parse_bootstrap_preflight(output: str) -> BootstrapPreflight:
    fields: dict[str, str] = {}
    for line in output.splitlines():
        key, separator, value = line.partition("=")
        if separator:
            fields[key] = value
    if fields.get("masque_ops_bootstrap_preflight") != "1":
        raise OpsError("remote returned an unsupported bootstrap preflight format")
    missing = tuple(
        item for item in fields.get("missing_commands", "").split(",") if item
    )
    return BootstrapPreflight(
        reachable=True,
        os=fields.get("os") or None,
        arch=fields.get("arch") or None,
        binary_exists=fields.get("binary_exists") == "yes",
        config_exists=fields.get("config_exists") == "yes",
        tls_cert_readable=fields.get("tls_cert_readable") == "yes",
        tls_key_readable=fields.get("tls_key_readable") == "yes",
        missing_commands=missing,
    )


@dataclasses.dataclass(frozen=True)
class HostStatus:
    name: str
    reachable: bool
    version_output: str | None = None
    version: str | None = None
    arch: str | None = None
    service_active: str | None = None
    service_enabled: str | None = None
    config_exists: bool = False
    config_check: str | None = None
    config_sha256: str | None = None
    cert_not_after: str | None = None
    cert_days_remaining: int | None = None
    disk_available_kb: int | None = None
    disk_used_percent: str | None = None
    error: str | None = None

    @property
    def healthy(self) -> bool:
        return (
            self.reachable
            and self.version is not None
            and self.service_active == "active"
            and self.config_exists
            and self.config_check == "ok"
            and self.config_sha256 is not None
            and re.fullmatch(r"[0-9a-fA-F]{64}", self.config_sha256) is not None
        )

    def public_dict(self) -> dict[str, object]:
        return dataclasses.asdict(self)


def parse_cert_days(value: str | None) -> int | None:
    if not value:
        return None
    try:
        expires = dt.datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=dt.timezone.utc
        )
    except ValueError:
        return None
    return int((expires - dt.datetime.now(dt.timezone.utc)).total_seconds() // 86400)


def parse_status(name: str, output: str) -> HostStatus:
    fields: dict[str, str] = {}
    for line in output.splitlines():
        key, separator, value = line.partition("=")
        if separator:
            fields[key] = value
    if fields.get("masque_ops_status") != "1":
        raise OpsError(f"{name} returned an unsupported maintenance status format")

    def optional_int(key: str) -> int | None:
        value = fields.get(key, "")
        try:
            return int(value) if value else None
        except ValueError:
            return None

    version_output = fields.get("version") or None
    cert_not_after = fields.get("cert_not_after") or None
    return HostStatus(
        name=name,
        reachable=True,
        version_output=version_output,
        version=installed_version(version_output),
        arch=fields.get("arch") or None,
        service_active=fields.get("service_active") or None,
        service_enabled=fields.get("service_enabled") or None,
        config_exists=fields.get("config_exists") == "yes",
        config_check=fields.get("config_check") or None,
        config_sha256=fields.get("config_sha256") or None,
        cert_not_after=cert_not_after,
        cert_days_remaining=parse_cert_days(cert_not_after),
        disk_available_kb=optional_int("disk_available_kb"),
        disk_used_percent=fields.get("disk_used_percent") or None,
    )


@dataclasses.dataclass(frozen=True)
class Release:
    tag: str
    prerelease: bool
    published_at: str | None
    assets: frozenset[str]

    def required_assets(self, architecture: str) -> tuple[str, str]:
        mapped = {
            "x86_64": "x86_64",
            "amd64": "x86_64",
            "aarch64": "aarch64",
            "arm64": "aarch64",
        }.get(architecture)
        if mapped is None:
            raise OpsError(f"unsupported remote architecture: {architecture}")
        version = self.tag.removeprefix("v")
        archive = f"masque-v{version}-linux-{mapped}.tar.gz"
        return archive, f"{archive}.sha256"

    def supports(self, architecture: str) -> bool:
        try:
            required = self.required_assets(architecture)
        except OpsError:
            return False
        return all(name in self.assets for name in required)


class ReleaseClient:
    def __init__(self, repository: str) -> None:
        self.repository = repository

    def fetch(self, version: str | None) -> Release:
        if version is None:
            suffix = "latest"
            requested_tag = None
        else:
            requested_tag = normalize_version(version)
            suffix = f"tags/{urllib.parse.quote(requested_tag, safe='')}"
        url = f"https://api.github.com/repos/{self.repository}/releases/{suffix}"
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "masque-ops/1",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
        if token:
            headers["Authorization"] = f"Bearer {token}"
        request = urllib.request.Request(url, headers=headers)
        try:
            # The origin is a literal and inventory loading fixes the repository
            # to DEFAULT_REPOSITORY, so urlopen cannot receive another scheme.
            with urllib.request.urlopen(request, timeout=20) as response:  # nosec B310
                payload = json.load(response)
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
            requested = version or "latest stable release"
            raise OpsError(
                f"could not read {requested} metadata from GitHub"
            ) from error
        if not isinstance(payload, dict):
            raise OpsError("GitHub returned malformed release metadata")
        if payload.get("draft"):
            raise OpsError("refusing to deploy a draft GitHub release")
        tag = normalize_version(
            require_string(payload.get("tag_name"), "release tag_name")
        )
        if requested_tag is not None and tag != requested_tag:
            raise OpsError(
                f"GitHub returned release {tag} when {requested_tag} was requested"
            )
        assets_raw = payload.get("assets", [])
        if not isinstance(assets_raw, list):
            raise OpsError(f"GitHub release {tag} has malformed assets")
        assets = frozenset(
            asset.get("name")
            for asset in assets_raw
            if isinstance(asset, dict) and isinstance(asset.get("name"), str)
        )
        return Release(
            tag=tag,
            prerelease=bool(payload.get("prerelease")),
            published_at=payload.get("published_at"),
            assets=assets,
        )


class ProbeRunner:
    def __init__(self, configured_binary: str, inventory_dir: Path) -> None:
        self.configured_binary = configured_binary
        self.inventory_dir = inventory_dir

    def resolve_binary(self) -> str:
        configured = self.configured_binary
        if "/" in configured:
            candidate = resolve_local_path(configured, self.inventory_dir)
            if not candidate.is_file() or not os.access(candidate, os.X_OK):
                raise OpsError(f"masque-probe is not executable: {candidate}")
            return str(candidate)
        resolved = shutil.which(configured)
        if resolved is None and configured == "masque-probe":
            local_candidate = Path.home() / ".local" / "bin" / configured
            if local_candidate.is_file() and os.access(local_candidate, os.X_OK):
                resolved = str(local_candidate)
        if resolved is None:
            raise OpsError(
                "masque-probe was not found; run the Skill's bundled "
                "scripts/install-probe.sh or set probe_binary"
            )
        return resolved

    def preflight(
        self, probe: ProbeConfig | None, *, allow_missing: frozenset[Path] = frozenset()
    ) -> None:
        if probe is None:
            return
        self.resolve_binary()
        if probe.password_file is not None and (
            probe.password_file not in allow_missing or probe.password_file.exists()
        ):
            ensure_private_file(probe.password_file, "probe password file")
        if probe.client_config is not None and (
            probe.client_config not in allow_missing or probe.client_config.exists()
        ):
            ensure_private_file(probe.client_config, "probe client configuration")
        if probe.ca_cert is not None:
            ensure_integrity_file(probe.ca_cert, "probe CA certificate")

    def run(self, host: Host) -> dict[str, object]:
        probe = host.probe
        if probe is None:
            return {"status": "not_configured"}
        self.preflight(probe)
        command = [
            self.resolve_binary(),
            probe.endpoint,
            "--transport",
            probe.transport,
            "--timeout",
            str(probe.timeout_secs),
            "--udp-mode",
            probe.udp_mode,
            "--json",
        ]
        for option, value in (
            ("--server-name", probe.server_name),
            ("--resolve", probe.resolve),
            ("--interface", probe.interface),
            ("--tcp-target", probe.tcp_target),
            ("--udp-target", probe.udp_target),
        ):
            if value is not None:
                command.extend([option, value])
        if probe.connect_ip:
            command.append("--connect-ip")
        if probe.skip_tcp:
            command.append("--skip-tcp")
        if probe.skip_udp:
            command.append("--skip-udp")
        if probe.ca_cert is not None:
            command.extend(["--ca-cert", str(probe.ca_cert)])
        stdin_handle: Any = subprocess.DEVNULL
        password_handle = None
        if probe.username is not None:
            command.extend(["--username", probe.username, "--password-stdin"])
            if probe.password_file is None:
                raise OpsError(f"probe password file is missing for {host.name}")
            try:
                password_handle = probe.password_file.open("rb")
            except OSError as error:
                raise OpsError(
                    f"could not open probe password file for {host.name}"
                ) from error
            stdin_handle = password_handle
        elif probe.client_config is not None:
            command.extend(["--client-config", str(probe.client_config)])
        try:
            completed = subprocess.run(
                command,
                stdin=stdin_handle,
                capture_output=True,
                timeout=probe.timeout_secs * 6 + 15,
                check=False,
            )
        except subprocess.TimeoutExpired as error:
            raise OpsError(
                f"external MASQUE probe timed out for {host.name}"
            ) from error
        except OSError as error:
            raise OpsError(
                f"could not start masque-probe for {host.name}: {error}"
            ) from error
        finally:
            if password_handle is not None:
                password_handle.close()
        try:
            report = json.loads(completed.stdout.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise OpsError(
                f"masque-probe returned invalid JSON for {host.name}"
            ) from error
        if not isinstance(report, dict):
            raise OpsError(f"masque-probe returned invalid JSON for {host.name}")
        checks = report.get("checks", [])
        if not isinstance(checks, list) or type(report.get("success")) is not bool:
            raise OpsError(f"masque-probe returned invalid JSON for {host.name}")
        failed_codes = [
            check.get("code", "UNKNOWN")
            for check in checks
            if isinstance(check, dict) and check.get("status") == "fail"
        ]
        summary: dict[str, object] = {
            "status": "passed" if report.get("success") else "failed",
            "transport": report.get("selected_transport"),
            "failed_codes": failed_codes,
        }
        if completed.returncode != 0 or not report.get("success"):
            codes = ", ".join(str(code) for code in failed_codes) or "UNKNOWN"
            raise OpsError(f"external MASQUE probe failed for {host.name}: {codes}")
        return summary


class StateStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.audit_path = path.with_name("ops-audit.jsonl")

    def _prepare_parent(self) -> None:
        try:
            self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        except OSError as error:
            raise OpsError(
                f"could not prepare operations state directory: {self.path.parent}"
            ) from error

    def load(self) -> dict[str, Any]:
        if not self.path.exists():
            return {"schema_version": SCHEMA_VERSION, "hosts": {}}
        ensure_private_file(self.path, "operations state")
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise OpsError(f"invalid operations state: {self.path}") from error
        if (
            not isinstance(payload, dict)
            or payload.get("schema_version") != SCHEMA_VERSION
            or not isinstance(payload.get("hosts"), dict)
        ):
            raise OpsError(f"unsupported operations state schema: {self.path}")
        return payload

    def save_transition(self, host: str, old: str, new: str) -> None:
        payload = self.load()
        payload["hosts"][host] = {
            "current_version": new,
            "rollback_version": old,
            "updated_at": utc_now(),
        }
        self._prepare_parent()
        try:
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{self.path.name}.", dir=self.path.parent
            )
        except OSError as error:
            raise OpsError(f"could not create operations state: {self.path}") from error
        temporary = Path(temporary_name)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.path)
        except OSError as error:
            raise OpsError(f"could not write operations state: {self.path}") from error
        finally:
            if temporary.exists():
                try:
                    temporary.unlink()
                except OSError:
                    pass

    def rollback_target(self, host: str, current: str) -> str:
        payload = self.load()
        entry = payload["hosts"].get(host)
        if not isinstance(entry, dict):
            raise OpsError(f"no successful deployment history exists for {host}")
        if entry.get("current_version") != current:
            raise OpsError(
                f"rollback state for {host} expects {entry.get('current_version')}, "
                f"but the server runs {current}"
            )
        return normalize_version(
            require_string(entry.get("rollback_version"), "rollback_version")
        )

    def audit(self, event: str, host: str, **fields: object) -> None:
        self._prepare_parent()
        record = {"timestamp": utc_now(), "event": event, "host": host, **fields}
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NONBLOCK
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(self.audit_path, flags, 0o600)
        except OSError as error:
            raise OpsError(
                f"could not open operations audit: {self.audit_path}"
            ) from error
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise OpsError(
                    f"operations audit is not a regular file: {self.audit_path}"
                )
            if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
                raise OpsError(
                    f"operations audit is not owned by the current user: {self.audit_path}"
                )
            if metadata.st_mode & 0o077:
                raise OpsError(f"operations audit is not private: {self.audit_path}")
            os.write(descriptor, (json.dumps(record, sort_keys=True) + "\n").encode())
            os.fsync(descriptor)
        except OSError as error:
            raise OpsError(
                f"could not write operations audit: {self.audit_path}"
            ) from error
        finally:
            os.close(descriptor)


class FleetOperator:
    def __init__(self, inventory: Inventory, ssh: SshClient | None = None) -> None:
        self.inventory = inventory
        self.ssh = ssh or SshClient()
        self.probes = ProbeRunner(inventory.probe_binary, inventory.path.parent)
        self.state = StateStore(inventory.state_path)

    def _audit_best_effort(self, event: str, host: str, **fields: object) -> bool:
        try:
            self.state.audit(event, host, **fields)
            return True
        except OpsError:
            return False

    def _maintenance(
        self, host: Host, *arguments: str, timeout: int | None = None
    ) -> subprocess.CompletedProcess[str]:
        command = remote_argv(host, [host.maintenance_path, *arguments], admin=True)
        return self.ssh.run(host, command, timeout=timeout or host.command_timeout_secs)

    def status(self, host: Host) -> HostStatus:
        maintenance = self._maintenance(host, "status")
        if maintenance.returncode == 0:
            try:
                return parse_status(host.name, maintenance.stdout)
            except OpsError:
                pass
        command = remote_argv(
            host,
            [
                "sh",
                "-s",
                "--",
                host.binary_path,
                host.config_path,
                host.service,
                host.cert_path,
                "1" if host.use_sudo else "0",
            ],
            admin=False,
        )
        completed = self.ssh.run(host, command, input_text=STATUS_SCRIPT)
        if completed.returncode != 0:
            return HostStatus(
                name=host.name,
                reachable=False,
                error=safe_tail(completed.stdout, completed.stderr),
            )
        try:
            return parse_status(host.name, completed.stdout)
        except OpsError as error:
            return HostStatus(name=host.name, reachable=False, error=str(error))

    def bootstrap_preflight(self, host: Host) -> BootstrapPreflight:
        bootstrap = host.bootstrap
        if bootstrap is None:
            return BootstrapPreflight(
                reachable=False, error="bootstrap settings are not configured"
            )
        command = remote_argv(
            host,
            [
                "sh",
                "-s",
                "--",
                bootstrap.tls_cert_path,
                bootstrap.tls_key_path,
                host.binary_path,
                host.config_path,
            ],
            admin=False,
        )
        completed = self.ssh.run(
            host,
            command,
            input_text=BOOTSTRAP_PREFLIGHT_SCRIPT,
            timeout=host.command_timeout_secs,
        )
        if completed.returncode != 0:
            return BootstrapPreflight(
                reachable=False,
                error=safe_tail(completed.stdout, completed.stderr),
            )
        try:
            return parse_bootstrap_preflight(completed.stdout)
        except OpsError as error:
            return BootstrapPreflight(reachable=False, error=str(error))

    def statuses(self, hosts: Sequence[Host]) -> list[HostStatus]:
        results: dict[str, HostStatus] = {}
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(8, len(hosts))
        ) as executor:
            futures = {executor.submit(self.status, host): host for host in hosts}
            for future, host in ((future, futures[future]) for future in futures):
                try:
                    results[host.name] = future.result()
                except OpsError as error:
                    results[host.name] = HostStatus(
                        name=host.name, reachable=False, error=str(error)
                    )
        return [results[host.name] for host in hosts]

    @staticmethod
    def _bootstrap_missing_probe_credentials(host: Host) -> frozenset[Path]:
        bootstrap = host.bootstrap
        probe = host.probe
        if bootstrap is None or probe is None:
            return frozenset()
        generated = {
            path
            for path in (
                bootstrap.basic_password_file,
                bootstrap.client_config,
            )
            if path is not None
        }
        return frozenset(
            path
            for path in (probe.password_file, probe.client_config)
            if path is not None and path in generated and not path.exists()
        )

    def preflight_bootstrap_local(self, host: Host) -> None:
        bootstrap = host.bootstrap
        if bootstrap is None:
            raise OpsError(f"bootstrap settings are not configured for {host.name}")
        if bootstrap.basic_password_file is not None:
            ensure_secret_destination(
                bootstrap.basic_password_file,
                "bootstrap Basic password file",
                allow_existing=True,
            )
            if bootstrap.basic_password_file.exists():
                read_private_password(
                    bootstrap.basic_password_file, "bootstrap Basic password file"
                )
        for path, label in (
            (bootstrap.basic_client_config, "bootstrap Basic client configuration"),
            (bootstrap.client_config, "bootstrap certificate client configuration"),
        ):
            if path is not None:
                ensure_secret_destination(path, label, allow_existing=False)
        self.probes.preflight(
            host.probe,
            allow_missing=self._bootstrap_missing_probe_credentials(host),
        )

    @staticmethod
    def _bootstrap_environment(
        bootstrap: BootstrapConfig,
        version: str,
        repository: str,
        password: str | None,
        remote_basic_config: str | None,
        remote_client_config: str | None,
    ) -> dict[str, str]:
        environment = {
            "MASQUE_VERSION": version,
            "MASQUE_GITHUB_REPOSITORY": repository,
            "MASQUE_START_SERVICE": "1",
            "MASQUE_RUN_HOST_DIAGNOSTICS": "0",
            "MASQUE_PRINT_SECRETS": "0",
            "MASQUE_AUTH_MODE": bootstrap.auth_mode,
            "MASQUE_LISTEN_PORT": str(bootstrap.listen_port),
            "MASQUE_TLS_CERT": bootstrap.tls_cert_path,
            "MASQUE_TLS_KEY": bootstrap.tls_key_path,
        }
        if bootstrap.uses_basic:
            if bootstrap.basic_username is None or password is None:
                raise OpsError("internal Basic bootstrap credentials are incomplete")
            environment.update(
                {
                    "MASQUE_AUTH_USERNAME": bootstrap.basic_username,
                    "MASQUE_AUTH_PASSWORD": password,
                    "MASQUE_BASIC_STEALTH": ("1" if bootstrap.basic_stealth else "0"),
                }
            )
            if bootstrap.basic_client_endpoint is not None:
                if remote_basic_config is None:
                    raise OpsError("internal Basic client output is incomplete")
                environment["MASQUE_BASIC_CLIENT_ENDPOINT"] = (
                    bootstrap.basic_client_endpoint
                )
                environment["MASQUE_BASIC_CLIENT_CONFIG_OUT"] = remote_basic_config
                if bootstrap.basic_client_name is not None:
                    environment["MASQUE_BASIC_CLIENT_NAME"] = (
                        bootstrap.basic_client_name
                    )
        if bootstrap.auth_mode == "dual":
            if bootstrap.cert_listen_port is None:
                raise OpsError("internal dual-listener bootstrap is incomplete")
            environment["MASQUE_CERT_LISTEN_PORT"] = str(bootstrap.cert_listen_port)
        if bootstrap.uses_client_certs:
            if (
                bootstrap.client_name is None
                or bootstrap.client_endpoint is None
                or remote_client_config is None
            ):
                raise OpsError("internal certificate bootstrap settings are incomplete")
            environment.update(
                {
                    "MASQUE_CLIENT_NAME": bootstrap.client_name,
                    "MASQUE_CLIENT_ENDPOINT": bootstrap.client_endpoint,
                    "MASQUE_CLIENT_IPV4": bootstrap.client_ipv4 or "none",
                    "MASQUE_CLIENT_IPV6": bootstrap.client_ipv6 or "none",
                    "MASQUE_CLIENT_CONFIG_OUT": remote_client_config,
                }
            )
        return environment

    def _run_fresh_install(
        self, host: Host, version: str, password: str | None
    ) -> tuple[str | None, str | None]:
        bootstrap = host.bootstrap
        if bootstrap is None:
            raise OpsError(f"bootstrap settings are not configured for {host.name}")
        installer_text = bundled_installer_text()

        token = secrets.token_hex(16)
        remote_basic_config = (
            f"/root/.masque-ops-{token}.surge.conf"
            if bootstrap.basic_client_config is not None
            else None
        )
        remote_client_config = (
            f"/root/.masque-ops-{token}.client.json"
            if bootstrap.client_config is not None
            else None
        )
        environment = self._bootstrap_environment(
            bootstrap,
            version,
            self.inventory.repository,
            password,
            remote_basic_config,
            remote_client_config,
        )
        prefix = "\n".join(
            f"export {name}={shlex.quote(value)}" for name, value in environment.items()
        )
        # Values, including the Basic password, travel only in encrypted SSH
        # standard input. They never appear in local or remote process argv.
        payload = f"{prefix}\n{installer_text}"
        command = remote_argv(host, ["sh", "-s"], admin=False)
        completed = self.ssh.run(
            host,
            command,
            input_text=payload,
            timeout=host.deploy_timeout_secs,
        )
        if completed.returncode != 0:
            for remote_path in (remote_basic_config, remote_client_config):
                if remote_path is not None:
                    self._remove_remote_secret_best_effort(host, remote_path)
            raise OpsError(
                f"fresh installer failed on {host.name}: "
                f"{safe_tail(completed.stdout, completed.stderr)}"
            )
        return remote_basic_config, remote_client_config

    def _remove_remote_secret_best_effort(self, host: Host, path: str) -> bool:
        command = remote_argv(host, ["rm", "-f", "--", path], admin=False)
        try:
            completed = self.ssh.run(host, command)
        except OpsError:
            return False
        return completed.returncode == 0

    def _retrieve_bootstrap_secret(
        self, host: Host, remote_path: str, destination: Path, label: str
    ) -> None:
        command = remote_argv(
            host, ["head", "-c", "1048577", "--", remote_path], admin=False
        )
        self.ssh.download_private(host, command, destination, label)
        if not self._remove_remote_secret_best_effort(host, remote_path):
            raise OpsError(
                f"{label} was saved, but its remote temporary file could not be removed"
            )

    def verify_bootstrap(self, host: Host, expected: str) -> HostStatus:
        last: HostStatus | None = None
        for attempt in range(4):
            if attempt:
                time.sleep(1)
            maintenance = self._maintenance(host, "status")
            if maintenance.returncode != 0:
                continue
            try:
                last = parse_status(host.name, maintenance.stdout)
            except OpsError:
                continue
            if last.healthy and last.version == expected:
                return last
        if last is None:
            raise OpsError(
                f"post-install verification could not run the maintenance helper on {host.name}"
            )
        raise OpsError(
            f"post-install verification failed for {host.name}: expected {expected}, "
            f"got version={last.version or 'unknown'} active={last.service_active or 'unknown'} "
            f"config={last.config_check or 'unknown'}"
        )

    def bootstrap_one(self, host: Host, release: Release) -> dict[str, object]:
        plan = plan_bootstrap(self, host, release)
        if not plan["ready"]:
            blockers = plan.get("blockers", [])
            raise OpsError(f"bootstrap preflight failed: {'; '.join(blockers)}")
        bootstrap = host.bootstrap
        if bootstrap is None:
            raise OpsError(f"bootstrap settings are not configured for {host.name}")

        self.state.audit("bootstrap_started", host.name, to_version=release.tag)
        password = None
        password_created = False
        try:
            if bootstrap.basic_password_file is not None:
                if bootstrap.basic_password_file.exists():
                    password = read_private_password(
                        bootstrap.basic_password_file,
                        "bootstrap Basic password file",
                    )
                else:
                    password = secrets.token_urlsafe(32)
                    write_private_file(
                        bootstrap.basic_password_file,
                        f"{password}\n".encode(),
                        "bootstrap Basic password file",
                    )
                    password_created = True
            remote_basic, remote_client = self._run_fresh_install(
                host, release.tag, password
            )
            if remote_basic is not None and bootstrap.basic_client_config is not None:
                self._retrieve_bootstrap_secret(
                    host,
                    remote_basic,
                    bootstrap.basic_client_config,
                    "bootstrap Basic client configuration",
                )
            if remote_client is not None and bootstrap.client_config is not None:
                self._retrieve_bootstrap_secret(
                    host,
                    remote_client,
                    bootstrap.client_config,
                    "bootstrap certificate client configuration",
                )
            after = self.verify_bootstrap(host, release.tag)
            probe = self.probes.run(host)
        except OpsError as error:
            self._audit_best_effort(
                "bootstrap_failed",
                host.name,
                to_version=release.tag,
                error=type(error).__name__,
            )
            raise OpsError(
                f"bootstrap did not complete cleanly on {host.name}; inspect status "
                "before retrying because a first install has no previous release to restore"
            ) from error
        try:
            self.state.audit(
                "bootstrap_succeeded",
                host.name,
                to_version=release.tag,
                config_sha256=after.config_sha256,
                probe=probe.get("status"),
            )
        except OpsError as audit_error:
            raise OpsError(
                f"bootstrap succeeded on {host.name}, but audit finalization failed; "
                "stop further operations"
            ) from audit_error
        return {
            "host": host.name,
            "status": "installed",
            "version": release.tag,
            "probe": probe,
            "basic_password_created": password_created,
            "credential_files_saved": sum(
                path is not None
                for path in (
                    bootstrap.basic_password_file,
                    bootstrap.basic_client_config,
                    bootstrap.client_config,
                )
            ),
        }

    def diagnose(self, host: Host, lines: int) -> str:
        completed = self._maintenance(host, "diagnose", str(lines))
        if completed.returncode == 0:
            return sanitize_diagnostics(completed.stdout)
        command = remote_argv(
            host,
            [
                "sh",
                "-s",
                "--",
                host.binary_path,
                host.config_path,
                host.service,
                host.cert_path,
                "1" if host.use_sudo else "0",
                str(lines),
            ],
            admin=False,
        )
        fallback = self.ssh.run(host, command, input_text=DIAGNOSE_SCRIPT)
        if fallback.returncode != 0:
            raise OpsError(
                f"diagnostics failed on {host.name}: "
                f"{safe_tail(fallback.stdout, fallback.stderr)}"
            )
        return sanitize_diagnostics(fallback.stdout)

    def verify_remote(
        self, host: Host, expected: str, expected_config_sha256: str
    ) -> HostStatus:
        last: HostStatus | None = None
        for attempt in range(4):
            if attempt:
                time.sleep(1)
            last = self.status(host)
            if (
                last.healthy
                and last.version == expected
                and last.config_sha256 == expected_config_sha256
            ):
                return last
        if last is None:
            raise OpsError(f"post-deploy verification did not run for {host.name}")
        raise OpsError(
            f"post-deploy verification failed for {host.name}: expected {expected}, "
            f"got version={last.version or 'unknown'} active={last.service_active or 'unknown'} "
            f"config={last.config_check or 'unknown'} "
            f"config_unchanged={last.config_sha256 == expected_config_sha256}"
        )

    @staticmethod
    def ensure_release(host: Host, status: HostStatus, release: Release) -> None:
        if not status.reachable:
            raise OpsError(f"{host.name} is unreachable: {status.error}")
        if not status.healthy:
            raise OpsError(
                f"{host.name} is not healthy before deployment: "
                f"active={status.service_active or 'unknown'} "
                f"config={status.config_check or 'unknown'}"
            )
        if status.arch is None or not release.supports(status.arch):
            raise OpsError(
                f"release {release.tag} has no verified archive and checksum for "
                f"{host.name} architecture {status.arch or 'unknown'}"
            )

    def _run_upgrade(self, host: Host, target: str, *, bootstrap: bool) -> None:
        if bootstrap:
            if host.user != "root" or host.use_sudo:
                raise OpsError(
                    "--bootstrap is restricted to an explicit root SSH inventory entry"
                )
            installer_text = bundled_installer_text()
            command = remote_argv(
                host,
                [
                    "env",
                    f"MASQUE_VERSION={target}",
                    f"MASQUE_GITHUB_REPOSITORY={self.inventory.repository}",
                    "MASQUE_START_SERVICE=1",
                    "MASQUE_RUN_HOST_DIAGNOSTICS=0",
                    "sh",
                    "-s",
                ],
                admin=False,
            )
            completed = self.ssh.run(
                host,
                command,
                input_text=installer_text,
                timeout=host.deploy_timeout_secs,
            )
        else:
            completed = self._maintenance(
                host, "upgrade", target, timeout=host.deploy_timeout_secs
            )
        if completed.returncode != 0:
            raise OpsError(
                f"installer failed on {host.name}: "
                f"{safe_tail(completed.stdout, completed.stderr)}"
            )

    def _restore(
        self,
        host: Host,
        version: str,
        expected_config_sha256: str,
        *,
        bootstrap: bool,
    ) -> None:
        self._run_upgrade(host, version, bootstrap=bootstrap)
        self.verify_remote(host, version, expected_config_sha256)

    def deploy_one(
        self,
        host: Host,
        release: Release,
        releases: ReleaseClient,
        *,
        bootstrap: bool = False,
    ) -> dict[str, object]:
        before = self.status(host)
        self.ensure_release(host, before, release)
        previous_version = before.version
        config_sha256 = before.config_sha256
        if previous_version is None or config_sha256 is None:
            raise OpsError(
                f"installed version or configuration hash is unknown on {host.name}"
            )
        if previous_version == release.tag:
            probe = self.probes.run(host)
            return {
                "host": host.name,
                "status": "already_current",
                "version": release.tag,
                "probe": probe,
            }
        previous_release = releases.fetch(previous_version)
        self.ensure_release(host, before, previous_release)
        self.probes.preflight(host.probe)
        self.state.audit(
            "deploy_started",
            host.name,
            from_version=previous_version,
            to_version=release.tag,
        )
        try:
            self._run_upgrade(host, release.tag, bootstrap=bootstrap)
            after = self.verify_remote(host, release.tag, config_sha256)
            probe = self.probes.run(host)
            self.state.save_transition(host.name, previous_version, release.tag)
        except OpsError as deploy_error:
            audit_ok = self._audit_best_effort(
                "deploy_failed",
                host.name,
                from_version=previous_version,
                to_version=release.tag,
                error=type(deploy_error).__name__,
            )
            try:
                current = self.status(host)
                if not (
                    current.healthy
                    and current.version == previous_version
                    and current.config_sha256 == config_sha256
                ):
                    self._restore(
                        host,
                        previous_version,
                        config_sha256,
                        bootstrap=bootstrap,
                    )
            except OpsError as rollback_error:
                self._audit_best_effort(
                    "automatic_rollback_failed",
                    host.name,
                    intended_version=previous_version,
                    error=type(rollback_error).__name__,
                )
                suffix = "" if audit_ok else "; audit logging also failed"
                raise OpsError(
                    f"deployment and automatic rollback both failed on {host.name}; "
                    f"manual recovery is required{suffix}"
                ) from rollback_error
            audit_ok = (
                self._audit_best_effort(
                    "automatic_rollback_succeeded",
                    host.name,
                    restored_version=previous_version,
                )
                and audit_ok
            )
            suffix = "" if audit_ok else "; audit logging also failed"
            raise OpsError(
                f"deployment failed on {host.name}; {previous_version} was restored: "
                f"{deploy_error}{suffix}"
            ) from deploy_error
        try:
            self.state.audit(
                "deploy_succeeded",
                host.name,
                from_version=previous_version,
                to_version=release.tag,
                config_sha256=after.config_sha256,
                probe=probe.get("status"),
            )
        except OpsError as audit_error:
            raise OpsError(
                f"deployment succeeded on {host.name} and local state was recorded, "
                "but audit finalization failed; stop the rollout"
            ) from audit_error
        return {
            "host": host.name,
            "status": "deployed",
            "from_version": previous_version,
            "version": release.tag,
            "probe": probe,
        }

    def rollback_one(self, host: Host, releases: ReleaseClient) -> dict[str, object]:
        before = self.status(host)
        if not before.healthy or before.version is None or before.config_sha256 is None:
            raise OpsError(f"{host.name} is not healthy enough to roll back safely")
        config_sha256 = before.config_sha256
        target = self.state.rollback_target(host.name, before.version)
        release = releases.fetch(target)
        self.ensure_release(host, before, release)
        self.probes.preflight(host.probe)
        self.state.audit(
            "rollback_started",
            host.name,
            from_version=before.version,
            to_version=target,
        )
        try:
            self._run_upgrade(host, target, bootstrap=False)
            self.verify_remote(host, target, config_sha256)
            probe = self.probes.run(host)
            self.state.save_transition(host.name, before.version, target)
        except OpsError as rollback_error:
            audit_ok = self._audit_best_effort(
                "rollback_failed",
                host.name,
                from_version=before.version,
                to_version=target,
                error=type(rollback_error).__name__,
            )
            try:
                self._restore(host, before.version, config_sha256, bootstrap=False)
            except OpsError as recovery_error:
                self._audit_best_effort(
                    "rollback_recovery_failed",
                    host.name,
                    intended_version=before.version,
                    error=type(recovery_error).__name__,
                )
                suffix = "" if audit_ok else "; audit logging also failed"
                raise OpsError(
                    f"rollback and recovery both failed on {host.name}; "
                    f"manual recovery is required{suffix}"
                ) from recovery_error
            audit_ok = (
                self._audit_best_effort(
                    "rollback_recovery_succeeded",
                    host.name,
                    restored_version=before.version,
                )
                and audit_ok
            )
            suffix = "" if audit_ok else "; audit logging also failed"
            raise OpsError(
                f"rollback failed on {host.name}; {before.version} was restored: "
                f"{rollback_error}{suffix}"
            ) from rollback_error
        try:
            self.state.audit(
                "rollback_succeeded",
                host.name,
                from_version=before.version,
                to_version=target,
                probe=probe.get("status"),
            )
        except OpsError as audit_error:
            raise OpsError(
                f"rollback succeeded on {host.name} and local state was recorded, "
                "but audit finalization failed; stop further operations"
            ) from audit_error
        return {
            "host": host.name,
            "status": "rolled_back",
            "from_version": before.version,
            "version": target,
            "probe": probe,
        }


def plan_bootstrap(
    operator: FleetOperator, host: Host, release: Release
) -> dict[str, object]:
    blockers: list[str] = []
    if host.bootstrap is None:
        blockers.append("bootstrap settings are not configured")
    if host.user != "root" or host.use_sudo:
        blockers.append("fresh bootstrap requires an explicit root SSH inventory entry")
    try:
        operator.preflight_bootstrap_local(host)
    except OpsError as error:
        blockers.append(str(error))

    remote = operator.bootstrap_preflight(host)
    if not remote.reachable:
        blockers.append(
            f"remote bootstrap preflight failed: {remote.error or 'unknown'}"
        )
    else:
        if remote.os != "Linux":
            blockers.append("target host is not Linux")
        if remote.binary_exists or remote.config_exists:
            blockers.append("MASQUE is already installed or partially configured")
        if not remote.tls_cert_readable or not remote.tls_key_readable:
            blockers.append("configured remote TLS material is not readable")
        if remote.missing_commands:
            blockers.append(
                "target is missing required commands: "
                + ", ".join(remote.missing_commands)
            )
        if remote.arch is None or not release.supports(remote.arch):
            blockers.append(
                "target release assets are missing for the remote architecture"
            )
    return {
        "host": host.name,
        "target_version": release.tag,
        "action": "fresh_install",
        "ready": not blockers,
        "blockers": blockers,
        "probe_configured": host.probe is not None,
    }


def plan_upgrade(
    operator: FleetOperator,
    hosts: Sequence[Host],
    release: Release,
    releases: ReleaseClient,
) -> dict[str, object]:
    statuses = operator.statuses(hosts)
    plans: list[dict[str, object]] = []
    previous_cache: dict[str, bool] = {}
    for host, status in zip(hosts, statuses, strict=True):
        blockers: list[str] = []
        if not status.reachable:
            blockers.append("unreachable")
        elif not status.healthy:
            blockers.append("pre-deploy health check failed")
        if status.arch is None or not release.supports(status.arch):
            blockers.append("target release assets missing for architecture")
        if status.version is None:
            blockers.append("installed version is unknown")
        elif status.version != release.tag:
            if status.version not in previous_cache:
                try:
                    old_release = releases.fetch(status.version)
                    previous_cache[status.version] = bool(
                        status.arch and old_release.supports(status.arch)
                    )
                except OpsError:
                    previous_cache[status.version] = False
            if not previous_cache[status.version]:
                blockers.append("current release is unavailable for automatic rollback")
        if host.probe is not None:
            try:
                operator.probes.preflight(host.probe)
            except OpsError as error:
                blockers.append(str(error))
        if status.version == release.tag:
            action = "verify"
        elif status.version and version_order(status.version) > version_order(
            release.tag
        ):
            action = "downgrade"
        else:
            action = "upgrade"
        plans.append(
            {
                "host": host.name,
                "current_version": status.version,
                "target_version": release.tag,
                "action": action,
                "canary": host.canary,
                "probe_configured": host.probe is not None,
                "ready": not blockers,
                "blockers": blockers,
            }
        )
    return {
        "target_version": release.tag,
        "prerelease": release.prerelease,
        "published_at": release.published_at,
        "ready": all(plan["ready"] for plan in plans),
        "hosts": plans,
    }


def format_statuses(statuses: Sequence[HostStatus]) -> None:
    print(
        f"{'HOST':<18} {'VERSION':<14} {'ACTIVE':<10} {'CONFIG':<9} {'ARCH':<10} {'DISK':<8} CERT"
    )
    for status in statuses:
        if not status.reachable:
            print(
                f"{status.name:<18} {'-':<14} {'-':<10} {'-':<9} {'-':<10} {'-':<8} ERROR"
            )
            continue
        disk = status.disk_used_percent or "-"
        cert = (
            f"{status.cert_days_remaining}d"
            if status.cert_days_remaining is not None
            else "unknown"
        )
        print(
            f"{status.name:<18} {(status.version or 'unknown'):<14} "
            f"{(status.service_active or 'unknown'):<10} "
            f"{(status.config_check or 'unknown'):<9} "
            f"{(status.arch or 'unknown'):<10} {disk:<8} {cert}"
        )


def print_plan(plan: dict[str, object]) -> None:
    print(f"Target release: {plan['target_version']}")
    print(f"Fleet ready:   {'yes' if plan['ready'] else 'no'}")
    print()
    hosts = plan.get("hosts")
    if not isinstance(hosts, list):
        raise OpsError("invalid internal upgrade plan")
    for host in hosts:
        if not isinstance(host, dict):
            raise OpsError("invalid internal host upgrade plan")
        blockers = host["blockers"]
        suffix = "" if not blockers else f" — blocked: {'; '.join(blockers)}"
        marker = "canary" if host["canary"] else "node"
        print(
            f"[{marker}] {host['host']}: {host['current_version'] or 'unknown'} "
            f"-> {host['target_version']} ({host['action']}){suffix}"
        )


def emit(payload: object, json_output: bool) -> None:
    if json_output:
        print(json.dumps(payload, indent=2, sort_keys=True))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="masque-ops",
        description="Inspect and safely operate a masque-server fleet over SSH",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {load_ops_version()}"
    )
    parser.add_argument(
        "--inventory",
        type=Path,
        default=DEFAULT_INVENTORY,
        help=f"private fleet TOML (default: {DEFAULT_INVENTORY})",
    )
    parser.add_argument("--json", action="store_true", help="emit stable JSON output")
    subcommands = parser.add_subparsers(dest="command", required=True)

    subcommands.add_parser(
        "validate", help="validate local inventory and secret file permissions"
    )

    status = subcommands.add_parser(
        "status", help="read fleet version and health state"
    )
    status.add_argument("hosts", nargs="*")

    plan = subcommands.add_parser(
        "plan", help="prepare a non-mutating release upgrade plan"
    )
    plan.add_argument("hosts", nargs="*")
    plan.add_argument("--version", help="exact tag; omit for latest stable release")

    deploy = subcommands.add_parser(
        "deploy", help="deploy one exact release to one host"
    )
    deploy.add_argument("host")
    deploy.add_argument("--version", required=True, help="exact release tag")
    deploy.add_argument(
        "--apply", action="store_true", help="authorize the remote mutation"
    )
    deploy.add_argument(
        "--bootstrap",
        action="store_true",
        help="one-time root install of masque-maintain on a pre-operations release",
    )

    bootstrap = subcommands.add_parser(
        "bootstrap",
        help="preflight or install an exact release on one unconfigured Linux host",
    )
    bootstrap.add_argument("host")
    bootstrap.add_argument("--version", required=True, help="exact release tag")
    bootstrap.add_argument(
        "--apply", action="store_true", help="authorize the fresh installation"
    )

    rollout = subcommands.add_parser(
        "rollout",
        help="deploy canary first, then the remaining selected hosts sequentially",
    )
    rollout.add_argument("hosts", nargs="*")
    rollout.add_argument("--version", required=True, help="exact release tag")
    rollout.add_argument(
        "--canary", help="override the inventory canary for this rollout"
    )
    rollout.add_argument(
        "--apply", action="store_true", help="authorize remote mutations"
    )
    rollout.add_argument(
        "--allow-no-probe",
        action="store_true",
        help="allow canary verification without an external masque-probe",
    )

    rollback = subcommands.add_parser(
        "rollback", help="restore the prior successful version recorded for one host"
    )
    rollback.add_argument("host")
    rollback.add_argument(
        "--apply", action="store_true", help="authorize the remote mutation"
    )

    diagnose = subcommands.add_parser(
        "diagnose",
        help="collect bounded read-only diagnostics without reading raw configuration",
    )
    diagnose.add_argument("hosts", nargs="*")
    diagnose.add_argument("--journal-lines", type=int, default=100)
    return parser


def require_apply(enabled: bool) -> None:
    if not enabled:
        raise OpsError(
            "mutation not authorized; inspect the plan, then repeat with --apply"
        )


def main(argv: Sequence[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    inventory = load_inventory(arguments.inventory)
    operator = FleetOperator(inventory)
    releases = ReleaseClient(inventory.repository)

    if arguments.command == "validate":
        for host in inventory.hosts:
            if host.identity_file is not None:
                ensure_private_file(host.identity_file, f"SSH identity for {host.name}")
            if host.known_hosts_file is not None:
                ensure_integrity_file(
                    host.known_hosts_file, f"known_hosts file for {host.name}"
                )
            if host.bootstrap is not None:
                for path, label in (
                    (
                        host.bootstrap.basic_password_file,
                        "bootstrap Basic password file",
                    ),
                    (
                        host.bootstrap.basic_client_config,
                        "bootstrap Basic client configuration",
                    ),
                    (
                        host.bootstrap.client_config,
                        "bootstrap certificate client configuration",
                    ),
                ):
                    if path is not None:
                        ensure_secret_destination(path, label, allow_existing=True)
                if (
                    host.bootstrap.basic_password_file is not None
                    and host.bootstrap.basic_password_file.exists()
                ):
                    read_private_password(
                        host.bootstrap.basic_password_file,
                        "bootstrap Basic password file",
                    )
            operator.probes.preflight(
                host.probe,
                allow_missing=operator._bootstrap_missing_probe_credentials(host),
            )
        payload = {
            "schema_version": SCHEMA_VERSION,
            "repository": inventory.repository,
            "hosts": [host.name for host in inventory.hosts],
            "canaries": [host.name for host in inventory.hosts if host.canary],
            "valid": True,
        }
        if not arguments.json:
            print(
                f"Inventory valid: {len(inventory.hosts)} host(s), "
                f"{len(payload['canaries'])} canary designation(s)"
            )
        emit(payload, arguments.json)
        return 0

    if arguments.command == "status":
        hosts = inventory.select(arguments.hosts)
        statuses = operator.statuses(hosts)
        if not arguments.json:
            format_statuses(statuses)
        emit(
            {
                "schema_version": SCHEMA_VERSION,
                "hosts": [item.public_dict() for item in statuses],
            },
            arguments.json,
        )
        return 0 if all(status.reachable for status in statuses) else 1

    if arguments.command == "plan":
        hosts = inventory.select(arguments.hosts)
        release = releases.fetch(arguments.version)
        plan = plan_upgrade(operator, hosts, release, releases)
        if not arguments.json:
            print_plan(plan)
        emit(plan, arguments.json)
        return 0 if plan["ready"] else 1

    if arguments.command == "deploy":
        require_apply(arguments.apply)
        host = inventory.select([arguments.host], require_names=True)[0]
        release = releases.fetch(arguments.version)
        result = operator.deploy_one(
            host, release, releases, bootstrap=arguments.bootstrap
        )
        if not arguments.json:
            print(f"{host.name}: {result['status']} at {result['version']}")
        emit(result, arguments.json)
        return 0

    if arguments.command == "bootstrap":
        host = inventory.select([arguments.host], require_names=True)[0]
        release = releases.fetch(arguments.version)
        plan = plan_bootstrap(operator, host, release)
        if not arguments.apply:
            if not arguments.json:
                blockers = plan["blockers"]
                suffix = "" if not blockers else f" — blocked: {'; '.join(blockers)}"
                print(
                    f"[fresh] {host.name}: uninstalled -> {release.tag} "
                    f"(fresh_install){suffix}"
                )
            emit(plan, arguments.json)
            return 0 if plan["ready"] else 1
        if not plan["ready"]:
            raise OpsError("bootstrap preflight failed; the host was not modified")
        result = operator.bootstrap_one(host, release)
        if not arguments.json:
            print(f"{host.name}: installed {result['version']}")
            print(
                f"Credential files saved privately: {result['credential_files_saved']}"
            )
        emit(result, arguments.json)
        return 0

    if arguments.command == "rollout":
        require_apply(arguments.apply)
        hosts = inventory.select(arguments.hosts)
        release = releases.fetch(arguments.version)
        plan = plan_upgrade(operator, hosts, release, releases)
        if not plan["ready"]:
            if not arguments.json:
                print_plan(plan)
            raise OpsError("rollout preflight failed; no host was modified")
        if arguments.canary:
            selected = [host for host in hosts if host.name == arguments.canary]
            if not selected:
                raise OpsError(
                    "the requested canary is not in the selected rollout hosts"
                )
            canary = selected[0]
        else:
            selected = [host for host in hosts if host.canary]
            if len(selected) != 1:
                raise OpsError("rollout requires exactly one selected canary")
            canary = selected[0]
        if canary.probe is None and not arguments.allow_no_probe:
            raise OpsError(
                "the canary has no external probe; configure one or explicitly use --allow-no-probe"
            )
        ordered = [canary, *(host for host in hosts if host.name != canary.name)]
        results = []
        for host in ordered:
            result = operator.deploy_one(host, release, releases)
            results.append(result)
            if not arguments.json:
                print(f"{host.name}: {result['status']} at {result['version']}")
        payload = {
            "target_version": release.tag,
            "status": "completed",
            "hosts": results,
        }
        emit(payload, arguments.json)
        return 0

    if arguments.command == "rollback":
        require_apply(arguments.apply)
        host = inventory.select([arguments.host], require_names=True)[0]
        result = operator.rollback_one(host, releases)
        if not arguments.json:
            print(f"{host.name}: rolled back to {result['version']}")
        emit(result, arguments.json)
        return 0

    if arguments.command == "diagnose":
        if not 1 <= arguments.journal_lines <= 500:
            raise OpsError("--journal-lines must be between 1 and 500")
        hosts = inventory.select(arguments.hosts)
        results = []
        if not arguments.json:
            print(
                "Warning: diagnostic journals may contain destination metadata; "
                "review before sharing."
            )
        for host in hosts:
            output = operator.diagnose(host, arguments.journal_lines)
            results.append({"host": host.name, "output": output})
            if not arguments.json:
                print(f"\n===== {host.name} =====\n{output.rstrip()}")
        emit({"schema_version": SCHEMA_VERSION, "hosts": results}, arguments.json)
        return 0

    raise AssertionError(f"unhandled command: {arguments.command}")


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except OpsError as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)
    except KeyboardInterrupt:
        print("error: interrupted", file=sys.stderr)
        raise SystemExit(130)
