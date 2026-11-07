from __future__ import annotations

import importlib.util
import io
import json
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
SKILL_ROOT = ROOT / ".agents" / "skills" / "masque-ops"
SCRIPT = SKILL_ROOT / "scripts" / "masque-ops.py"
REPOSITORY_LAUNCHER = ROOT / "scripts" / "masque-ops.py"
PACKAGE_VERSION = tomllib.loads((ROOT / "Cargo.toml").read_text())["package"]["version"]
SPEC = importlib.util.spec_from_file_location("masque_ops", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
ops = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = ops
SPEC.loader.exec_module(ops)


def release(tag: str) -> object:
    version = tag.removeprefix("v")
    archive = f"masque-v{version}-linux-x86_64.tar.gz"
    return ops.Release(
        tag=tag,
        prerelease="-" in tag,
        published_at="2026-09-02T00:00:00Z",
        assets=frozenset({archive, f"{archive}.sha256"}),
    )


class FakeReleases:
    def __init__(self, *tags: str) -> None:
        self.releases = {tag: release(tag) for tag in tags}

    def fetch(self, version: str | None) -> object:
        if version is None:
            return self.releases[max(self.releases)]
        tag = ops.normalize_version(version)
        try:
            return self.releases[tag]
        except KeyError as error:
            raise ops.OpsError(f"release not found: {tag}") from error


class FakeSsh:
    def __init__(
        self,
        version: str,
        unhealthy: set[str] | None = None,
        config_drift: set[str] | None = None,
    ) -> None:
        self.version = version
        self.unhealthy = unhealthy or set()
        self.config_drift = config_drift or set()
        self.upgrades: list[str] = []

    def run(
        self,
        host: object,
        command: str,
        *,
        input_text: str | None = None,
        timeout: int | None = None,
    ) -> subprocess.CompletedProcess[str]:
        del input_text, timeout
        arguments = shlex.split(command)
        if arguments[-1] == "status":
            active = "failed" if self.version in self.unhealthy else "active"
            config_sha256 = ("b" if self.version in self.config_drift else "a") * 64
            output = "\n".join(
                [
                    "masque_ops_status=1",
                    f"version=masque-server {self.version.removeprefix('v')}",
                    "arch=x86_64",
                    f"service_active={active}",
                    "service_enabled=enabled",
                    "config_exists=yes",
                    "config_check=ok",
                    f"config_sha256={config_sha256}",
                    "cert_not_after=Sep 30 12:00:00 2030 GMT",
                    "disk_available_kb=1048576",
                    "disk_used_percent=40%",
                    "",
                ]
            )
            return subprocess.CompletedProcess(arguments, 0, output, "")
        if "upgrade" in arguments:
            target = arguments[-1]
            self.version = target
            self.upgrades.append(target)
            return subprocess.CompletedProcess(arguments, 0, "installed", "")
        raise AssertionError(f"unexpected fake SSH command: {command}")


class FakeBootstrapSsh:
    def __init__(self) -> None:
        self.installed = False
        self.install_command = ""
        self.install_input = ""

    def run(
        self,
        host: object,
        command: str,
        *,
        input_text: str | None = None,
        timeout: int | None = None,
    ) -> subprocess.CompletedProcess[str]:
        del host, timeout
        arguments = shlex.split(command)
        if input_text == ops.BOOTSTRAP_PREFLIGHT_SCRIPT:
            output = (
                "masque_ops_bootstrap_preflight=1\n"
                "os=Linux\n"
                "arch=x86_64\n"
                "binary_exists=no\n"
                "config_exists=no\n"
                "tls_cert_readable=yes\n"
                "tls_key_readable=yes\n"
                "missing_commands=\n"
            )
            return subprocess.CompletedProcess(arguments, 0, output, "")
        if input_text is not None and "export MASQUE_VERSION=" in input_text:
            self.install_command = command
            self.install_input = input_text
            self.installed = True
            return subprocess.CompletedProcess(arguments, 0, "installed", "")
        if arguments[-1] == "status" and self.installed:
            output = "\n".join(
                [
                    "masque_ops_status=1",
                    "version=masque-server 0.13.0",
                    "arch=x86_64",
                    "service_active=active",
                    "service_enabled=enabled",
                    "config_exists=yes",
                    "config_check=ok",
                    f"config_sha256={'a' * 64}",
                    "cert_not_after=Sep 30 12:00:00 2030 GMT",
                    "disk_available_kb=1048576",
                    "disk_used_percent=40%",
                    "",
                ]
            )
            return subprocess.CompletedProcess(arguments, 0, output, "")
        if arguments[:3] == ["rm", "-f", "--"]:
            return subprocess.CompletedProcess(arguments, 0, "", "")
        raise AssertionError(f"unexpected fake SSH command: {command}")

    def download_private(
        self,
        host: object,
        command: str,
        destination: Path,
        label: str,
    ) -> None:
        del host, command
        ops.write_private_file(
            destination,
            b'{"private_key":"client-secret"}\n',
            label,
        )


class FakeSelfSignedBootstrapSsh(FakeBootstrapSsh):
    def __init__(self) -> None:
        super().__init__()
        self.certificate_prepared = False

    def run(self, host: object, command: str, *, input_text: str | None = None,
            timeout: int | None = None) -> subprocess.CompletedProcess[str]:
        if input_text is not None and "MASQUE_OPS_SELF_SIGNED_CERT_V1" in input_text:
            self.certificate_prepared = True
            return subprocess.CompletedProcess(shlex.split(command), 0, "", "")
        return super().run(host, command, input_text=input_text, timeout=timeout)

    def download_private(self, host: object, command: str, destination: Path, label: str) -> None:
        if label == "bootstrap CA certificate":
            ops.write_private_file(destination, b"synthetic-certificate", label)
        else:
            super().download_private(host, command, destination, label)


class FakeEmptyBootstrapSsh(FakeSelfSignedBootstrapSsh):
    def __init__(self) -> None:
        super().__init__()
        self.dependencies_installed = False

    def run(self, host: object, command: str, *, input_text: str | None = None,
            timeout: int | None = None) -> subprocess.CompletedProcess[str]:
        if input_text == ops.BOOTSTRAP_PREFLIGHT_SCRIPT:
            missing = "" if self.dependencies_installed else "curl,openssl"
            return subprocess.CompletedProcess(shlex.split(command), 0,
                "masque_ops_bootstrap_preflight=1\nos=Linux\narch=x86_64\n"
                "binary_exists=no\nconfig_exists=no\ntls_cert_readable=no\n"
                f"tls_key_readable=no\npackage_manager=apt\nmissing_commands={missing}\n", "")
        if input_text == ops.PREPARE_DEPENDENCIES_SCRIPT:
            self.dependencies_installed = True
            return subprocess.CompletedProcess(shlex.split(command), 0, "", "")
        return super().run(host, command, input_text=input_text, timeout=timeout)


class FailingState:
    def audit(self, _event: str, _host: str, **_fields: object) -> None:
        pass

    def save_transition(self, _host: str, _old: str, _new: str) -> None:
        raise ops.OpsError("state write failed")


class AuditFailsAfterStart:
    def __init__(self) -> None:
        self.calls = 0

    def audit(self, _event: str, _host: str, **_fields: object) -> None:
        self.calls += 1
        if self.calls > 1:
            raise ops.OpsError("audit write failed")

    def save_transition(self, _host: str, _old: str, _new: str) -> None:
        pass


class InventoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.key = self.root / "id_ed25519"
        self.key.write_text("fixture", encoding="utf-8")
        self.key.chmod(0o600)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_inventory(self, extra: str = "") -> Path:
        path = self.root / "fleet.toml"
        path.write_text(
            "\n".join(
                [
                    "schema_version = 1",
                    'repository = "Vincent-bin/masque-server"',
                    f'state_path = "{self.root / "state.json"}"',
                    "[defaults]",
                    'user = "root"',
                    f'identity_file = "{self.key}"',
                    "sudo = false",
                    "[[hosts]]",
                    'name = "canary"',
                    'address = "203.0.113.10"',
                    "canary = true",
                    extra,
                    "",
                ]
            ),
            encoding="utf-8",
        )
        path.chmod(0o600)
        return path

    def test_inventory_is_private_and_typed(self) -> None:
        inventory = ops.load_inventory(self.write_inventory())
        self.assertEqual(inventory.hosts[0].name, "canary")
        self.assertFalse(inventory.hosts[0].use_sudo)
        self.assertEqual(inventory.hosts[0].identity_file, self.key)

        inventory.path.chmod(0o644)
        with self.assertRaisesRegex(ops.OpsError, "group or others"):
            ops.load_inventory(inventory.path)

    def test_required_profiles_support_legacy_and_explicit_transports(self) -> None:
        path = self.write_inventory(
            '[hosts.probe]\nendpoint = "primary.example:443"\n'
            '[[hosts.probes]]\nendpoint = "fallback.example:8443"\ntransport = "http2"\n'
            'client_config = "secrets/client.json"\n'
        )
        host = ops.load_inventory(path).hosts[0]
        profiles = ops.required_probes(host)
        self.assertEqual(len(profiles), 2)
        self.assertEqual(profiles[0].transport, "auto")
        self.assertEqual(profiles[1].transport, "http2")
        self.assertEqual(profiles[1].client_config, self.root / "secrets/client.json")

    def test_required_profiles_validate_shape_transport_and_secret_references(self) -> None:
        invalid = [
            ('probes = {}', "must be a list"),
            ('probes = [1]', "must be a TOML table"),
            ('[[hosts.probes]]\nendpoint = "proxy.example:443"', "explicit http2 or http3"),
            ('[[hosts.probes]]\nendpoint = "proxy.example:443"\ntransport = "auto"', "explicit http2 or http3"),
            ('[[hosts.probes]]\nendpoint = "proxy.example:443"\ntransport = "http2"\npassword = "secret"', "unknown"),
        ]
        for stanza, expected in invalid:
            with self.subTest(stanza=stanza), self.assertRaisesRegex(ops.OpsError, expected):
                ops.load_inventory(self.write_inventory(stanza))

    def test_required_profile_bound_includes_primary_and_legacy_dual(self) -> None:
        stanza = '[[hosts.probes]]\nendpoint = "proxy.example:443"\ntransport = "http3"\n'
        host = ops.load_inventory(self.write_inventory(stanza * ops.MAX_REQUIRED_PROBES)).hosts[0]
        self.assertEqual(len(ops.required_probes(host)), ops.MAX_REQUIRED_PROBES)
        for text in (
            stanza * (ops.MAX_REQUIRED_PROBES + 1),
            '[hosts.probe]\nendpoint = "proxy.example:443"\n' + stanza * ops.MAX_REQUIRED_PROBES,
        ):
            with self.assertRaisesRegex(ops.OpsError, "at most 8"):
                ops.load_inventory(self.write_inventory(text))
        path = self.root / "dual.toml"
        ops.initialize_inventory(path, ssh_host="203.0.113.10", endpoint_host="proxy.example.com",
                                 auth_mode="dual", self_signed=True)
        dual = ops.load_inventory(path).hosts[0]
        legacy = ops.dataclasses.replace(dual, probes=())
        self.assertEqual(len(ops.required_probes(legacy)), 2)
        with self.assertRaisesRegex(ops.OpsError, "at most 8"):
            ops.required_probes(ops.dataclasses.replace(legacy, probes=(host.probes[0],) * 7))

    def test_new_dual_profiles_survive_removing_bootstrap_and_do_not_duplicate(self) -> None:
        for transport in ("http2", "http3"):
            path = self.root / f"dual-{transport}.toml"
            ops.initialize_inventory(path, ssh_host="203.0.113.10", endpoint_host="proxy.example.com",
                                     auth_mode="dual", transport=transport, self_signed=True,
                                     connect_ip=True, skip_tcp=True)
            host = ops.load_inventory(path).hosts[0]
            self.assertEqual(len(ops.required_probes(host)), 2)
            self.assertEqual(ops.required_probes(host), ops.required_probes(ops.dataclasses.replace(host, bootstrap=None)))
            certificate = host.probes[0]
            self.assertEqual(certificate.transport, transport)
            self.assertTrue(certificate.connect_ip)
            self.assertTrue(certificate.skip_tcp)
            self.assertIsNone(certificate.username)
            self.assertIsNone(certificate.ca_cert)
            self.assertEqual(certificate.client_config, host.bootstrap.client_config)
            self.assertIn(certificate.client_config, ops.FleetOperator._bootstrap_missing_probe_credentials(host))

    def test_initialize_inventory_generates_safe_bootstrap_and_probe(self) -> None:
        path = self.root / "fresh" / "fleet.toml"
        result = ops.initialize_inventory(
            path,
            ssh_host="203.0.113.10",
            endpoint_host="proxy.example.com",
            identity_file=str(self.key),
        )
        inventory = ops.load_inventory(path)
        host = inventory.hosts[0]
        self.assertEqual(result["status"], "created")
        self.assertTrue(host.canary)
        self.assertEqual(host.user, "root")
        self.assertIsNotNone(host.bootstrap)
        self.assertIsNotNone(host.probe)
        self.assertEqual(host.probe.endpoint, "proxy.example.com:443")
        self.assertEqual(host.probe.password_file, host.bootstrap.basic_password_file)
        self.assertFalse(host.probe.password_file.exists())
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(host.probe.password_file.parent.stat().st_mode), 0o700)
        before = path.read_bytes()
        with self.assertRaisesRegex(ops.OpsError, "already exists"):
            ops.initialize_inventory(path, ssh_host="203.0.113.11", endpoint_host="proxy.example.com")
        self.assertEqual(path.read_bytes(), before)

    def test_initialize_inventory_ipv6_endpoint_and_injection_rejection(self) -> None:
        path = self.root / "fleet.toml"
        ops.initialize_inventory(
            path, ssh_host="2001:db8::1", endpoint_host="2001:db8::1", listen_port=8449
        )
        self.assertEqual(ops.load_inventory(path).hosts[0].probe.endpoint, "[2001:db8::1]:8449")
        with self.assertRaises(ops.OpsError):
            ops.initialize_inventory(
                self.root / "invalid.toml", ssh_host="example.com\nmalicious=true", endpoint_host="example.com"
            )
        self.assertFalse((self.root / "invalid.toml").exists())

    def test_add_host_preserves_existing_canary_and_authentication(self) -> None:
        path = self.write_inventory()
        before = ops.load_inventory(path).hosts[0]
        result = ops.initialize_inventory(
            path, ssh_host="203.0.113.20", endpoint_host="proxy.example.com",
            ssh_password="private-ssh-password", self_signed=True, add_host=True,
        )
        updated = ops.load_inventory(path)
        self.assertEqual(result["status"], "added")
        self.assertEqual(updated.hosts[0], before)
        self.assertFalse(updated.hosts[1].canary)
        self.assertEqual(updated.hosts[1].name, result["host"])
        self.assertIsNone(updated.hosts[1].identity_file)
        self.assertIsNotNone(updated.hosts[1].ssh_password_file)
        self.assertNotIn("private-ssh-password", path.read_text())

    def test_add_host_rejects_duplicate_without_changing_inventory(self) -> None:
        path = self.write_inventory()
        original = path.read_bytes()
        with self.assertRaisesRegex(ops.OpsError, "duplicate SSH destination"):
            ops.initialize_inventory(
                path, ssh_host="203.0.113.10", endpoint_host="proxy.example.com", add_host=True
            )
        self.assertEqual(path.read_bytes(), original)

    def test_initialize_password_auth_keeps_secret_private_and_uses_askpass(self) -> None:
        path = self.root / "fresh" / "fleet.toml"
        ops.initialize_inventory(
            path, ssh_host="203.0.113.10", endpoint_host="proxy.example.com",
            ssh_password="private-ssh-password",
        )
        host = ops.load_inventory(path).hosts[0]
        self.assertNotIn("private-ssh-password", path.read_text())
        self.assertEqual(stat.S_IMODE(host.ssh_password_file.stat().st_mode), 0o600)
        fake_ssh = self.root / "fake-ssh"
        fake_ssh.write_text(
            "#!/usr/bin/env python3\n"
            "import os,subprocess,sys\n"
            "assert 'private-ssh-password' not in ' '.join(sys.argv)\n"
            "assert subprocess.check_output([os.environ['SSH_ASKPASS']]).decode() == 'private-ssh-password'\n"
            "assert sys.stdin.read() == 'remote payload'\n"
            "print('ok')\n",
            encoding="utf-8",
        )
        fake_ssh.chmod(0o700)
        with mock.patch.dict(ops.os.environ, {"MASQUE_OPS_SSH": str(fake_ssh)}):
            ssh = ops.SshClient()
        args = ssh.arguments(host, "sh -s")
        self.assertIn("StrictHostKeyChecking=yes", args)
        self.assertIn("PasswordAuthentication=yes", args)
        self.assertNotIn("private-ssh-password", " ".join(args))
        result = ssh.run(host, "sh -s", input_text="remote payload")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "ok")
        self.assertEqual(list(host.ssh_password_file.parent.glob(".masque-askpass-*")), [])

    def test_initialize_interactively_accepts_passwords_without_printing_them(self) -> None:
        path = self.root / "fleet.toml"
        with mock.patch.object(ops.sys.stdin, "isatty", return_value=True), \
             mock.patch("builtins.input", side_effect=["203.0.113.10", "1", "1", "", "", "", "2"]), \
             mock.patch.object(ops.getpass, "getpass", side_effect=["ssh-secret", "proxy-secret"]), \
             mock.patch("sys.stdout", new_callable=io.StringIO) as stdout, \
             mock.patch("sys.stderr", new_callable=io.StringIO) as stderr:
            result = ops.main(["--inventory", str(path), "init-inventory", "--proxy-password-prompt"])
        self.assertEqual(result, 0)
        rendered = path.read_text() + stdout.getvalue() + stderr.getvalue()
        self.assertNotIn("ssh-secret", rendered)
        self.assertNotIn("proxy-secret", rendered)
        host = ops.load_inventory(path).hosts[0]
        self.assertEqual(host.ssh_password_file.read_text(), "ssh-secret")
        self.assertEqual(host.bootstrap.basic_password_file.read_text(), "proxy-secret")
        self.assertEqual(host.bootstrap.tls_mode, "self_signed")

    def test_noninteractive_initialization_requires_explicit_capabilities(self) -> None:
        path = self.root / "fleet.toml"
        with mock.patch.object(ops.sys.stdin, "isatty", return_value=False), \
             self.assertRaisesRegex(ops.OpsError, "specify --auth-mode"):
            ops.main(["--inventory", str(path), "init-inventory", "--ssh-host", "203.0.113.10"])
        self.assertFalse(path.exists())

    def test_initialize_self_signed_bootstrap_prepares_probe_trust(self) -> None:
        path = self.root / "fleet.toml"
        ops.initialize_inventory(
            path, ssh_host="203.0.113.10", endpoint_host="proxy.example.com",
            self_signed=True,
        )
        host = ops.load_inventory(path).hosts[0]
        self.assertEqual(host.bootstrap.tls_mode, "self_signed")
        self.assertEqual(host.bootstrap.tls_name, "proxy.example.com")
        self.assertTrue(host.bootstrap.basic_stealth)
        self.assertRegex(host.bootstrap.basic_username, r"^user-[0-9a-f]{24}$")
        self.assertEqual(host.probe.username, host.bootstrap.basic_username)
        self.assertEqual(host.probe.ca_cert, host.bootstrap.tls_ca_file)
        self.assertFalse(host.bootstrap.tls_ca_file.exists())
        self.assertIn(host.probe.ca_cert, ops.FleetOperator._bootstrap_missing_probe_credentials(host))
        probe = self.root / "masque-probe"
        probe.write_text("#!/bin/sh\nexit 0\n")
        probe.chmod(0o700)
        with mock.patch.dict(ops.os.environ, {"PATH": str(self.root) + ":" + ops.os.environ.get("PATH", "")}), \
             mock.patch("sys.stdout", new_callable=io.StringIO) as output:
            self.assertEqual(ops.main(["--inventory", str(path), "--json", "validate"]), 0)
        self.assertTrue(json.loads(output.getvalue())["valid"])

    def test_legacy_inventory_cannot_reenable_basic_challenges(self) -> None:
        path = self.root / "fleet.toml"
        ops.initialize_inventory(
            path, ssh_host="203.0.113.10", endpoint_host="proxy.example.com",
            basic_stealth=False,
        )
        self.assertIn("basic_stealth = true", path.read_text())
        original = path.read_text()
        for setting in ["basic_stealth = false\n", ""]:
            path.write_text(original.replace("basic_stealth = true\n", setting))
            self.assertTrue(ops.load_inventory(path).hosts[0].bootstrap.basic_stealth)

    def test_initialize_client_certificate_and_dual_authentication(self) -> None:
        for mode in ("client_cert", "dual"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as folder:
                path = Path(folder) / "fleet.toml"
                result = ops.initialize_inventory(
                    path, ssh_host="203.0.113.10", endpoint_host="proxy.example.com",
                    self_signed=True, auth_mode=mode, transport="http2", connect_ip=True,
                )
                host = ops.load_inventory(path).hosts[0]
                self.assertEqual(host.bootstrap.auth_mode, mode)
                self.assertEqual(host.bootstrap.transport, "http2")
                self.assertEqual(host.probe.transport, "http2")
                self.assertTrue(host.probe.connect_ip)
                self.assertEqual(result["auth_mode"], mode)
                if mode == "client_cert":
                    self.assertIsNone(host.probe.ca_cert)
                    self.assertEqual(host.probe.client_config, host.bootstrap.client_config)
                    self.assertEqual(result["password"], "not_used")
                else:
                    self.assertTrue(host.bootstrap.verify_dual)
                    self.assertTrue(host.bootstrap.basic_stealth)
                    self.assertEqual(host.probe.password_file, host.bootstrap.basic_password_file)
                    self.assertEqual(host.probe.ca_cert, host.bootstrap.tls_ca_file)
                    self.assertNotEqual(host.bootstrap.client_endpoint, host.probe.endpoint)

    def test_initialize_requires_at_least_one_protocol_check(self) -> None:
        with self.assertRaisesRegex(ops.OpsError, "at least one protocol"):
            ops.initialize_inventory(self.root / "fleet.toml", ssh_host="203.0.113.10",
                                     endpoint_host="proxy.example.com", skip_tcp=True, skip_udp=True)
        self.assertFalse((self.root / "fleet.toml").exists())

    def test_self_signed_script_creates_valid_certificate_and_refuses_existing_directory(self) -> None:
        directory = self.root / "generated"
        certificate = directory / "fullchain.pem"
        private_key = directory / "privkey.pem"
        env = dict(ops.os.environ, MASQUE_CERT_PATH=str(certificate), MASQUE_KEY_PATH=str(private_key),
                   MASQUE_CERT_COMMON_NAME="proxy.example.com", MASQUE_CERT_SAN="DNS:proxy.example.com")
        completed = subprocess.run(["sh", "-s"], input=ops.SELF_SIGNED_CERT_SCRIPT,
                                   text=True, capture_output=True, env=env, check=False)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(stat.S_IMODE(private_key.stat().st_mode), 0o600)
        verify = subprocess.run(["openssl", "verify", "-CAfile", str(certificate), "-verify_hostname",
                                 "proxy.example.com", str(certificate)], capture_output=True, text=True)
        self.assertEqual(verify.returncode, 0, verify.stderr)
        identity = subprocess.run(["openssl", "x509", "-in", str(certificate), "-noout",
                                   "-subject", "-issuer", "-nameopt", "RFC2253"],
                                  capture_output=True, text=True, check=True).stdout
        self.assertEqual(identity.splitlines(), ["subject=CN=proxy.example.com",
                                                "issuer=CN=proxy.example.com"])
        original = certificate.read_bytes()
        second = subprocess.run(["sh", "-s"], input=ops.SELF_SIGNED_CERT_SCRIPT,
                                text=True, capture_output=True, env=env, check=False)
        self.assertNotEqual(second.returncode, 0)
        self.assertEqual(certificate.read_bytes(), original)

    def test_export_probe_ca_never_overwrites_or_exports_private_keys(self) -> None:
        path = self.root / "fleet.toml"
        ops.initialize_inventory(path, ssh_host="203.0.113.10",
                                 endpoint_host="proxy.example.com", self_signed=True)
        path.write_text(path.read_text().replace("canary = true", "canary = false"))
        host = ops.load_inventory(path).hosts[0]
        ca = host.bootstrap.tls_ca_file
        ca.write_text("-----BEGIN CERTIFICATE-----\nfixture\n-----END CERTIFICATE-----\n")
        ca.chmod(0o600)
        target = self.root / "public-ca.pem"
        with mock.patch("sys.stdout", new_callable=io.StringIO):
            self.assertEqual(ops.main(["--inventory", str(path), "export-probe-ca", "--out", str(target)]), 0)
        self.assertEqual(target.read_bytes(), ca.read_bytes())
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
        with self.assertRaisesRegex(ops.OpsError, "already exists"):
            ops.main(["--inventory", str(path), "export-probe-ca", "--out", str(target)])
        ca.write_text(ca.read_text() + "-----BEGIN PRIVATE KEY-----\nfixture\n-----END PRIVATE KEY-----\n")
        with self.assertRaisesRegex(ops.OpsError, "private key"):
            ops.main(["--inventory", str(path), "export-probe-ca", "--out", str(self.root / "other.pem")])

    def test_repository_example_inventory_matches_the_schema(self) -> None:
        path = self.root / "fleet.example.toml"
        path.write_text(
            (ROOT / "deploy/config/fleet.example.toml").read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        path.chmod(0o600)
        inventory = ops.load_inventory(path)
        self.assertEqual(len(inventory.hosts), 2)
        self.assertIsNotNone(inventory.hosts[0].bootstrap)
        self.assertIsNotNone(inventory.hosts[0].probe)

    def test_unknown_inventory_key_is_rejected(self) -> None:
        with self.assertRaisesRegex(ops.OpsError, "unknown hosts.* key"):
            ops.load_inventory(self.write_inventory("unexpected = true"))

    def test_remote_installation_paths_cannot_be_overridden(self) -> None:
        with self.assertRaisesRegex(ops.OpsError, "unknown hosts.*config_path"):
            ops.load_inventory(
                self.write_inventory('config_path = "/tmp/untrusted.toml"')
            )

    def test_release_source_is_pinned_to_the_official_repository(self) -> None:
        path = self.write_inventory()
        contents = path.read_text(encoding="utf-8").replace(
            'repository = "Vincent-bin/masque-server"',
            'repository = "example/masque-server"',
        )
        path.write_text(contents, encoding="utf-8")
        with self.assertRaisesRegex(ops.OpsError, "release source"):
            ops.load_inventory(path)

    def test_inventory_symlink_is_rejected(self) -> None:
        target = self.write_inventory()
        link = self.root / "linked.toml"
        link.symlink_to(target)
        with self.assertRaisesRegex(ops.OpsError, "symbolic link"):
            ops.load_inventory(link)

    def test_probe_setup_tests_before_saving_and_preserves_other_hosts(self) -> None:
        path = self.write_inventory(
            '# preserved comment\n[[hosts]]\nname = "other"\naddress = "203.0.113.11"'
        )
        inventory = ops.load_inventory(path)
        host = inventory.hosts[0]
        runner = mock.Mock()
        runner.run.return_value = {"status": "passed", "transport": "http3"}
        result = ops.configure_probe(
            inventory, host,
            {"endpoint": "proxy.example:443", "transport": "http3", "username": "probe"},
            "private-test-password", runner,
        )
        self.assertEqual(result["status"], "configured")
        self.assertEqual(runner.run.call_count, 1)
        updated = ops.load_inventory(path)
        self.assertIsNotNone(updated.hosts[0].probe)
        self.assertIsNone(updated.hosts[1].probe)
        self.assertIn("# preserved comment", path.read_text())
        self.assertNotIn("private-test-password", path.read_text())
        password_file = updated.hosts[0].probe.password_file
        self.assertEqual(password_file.read_text(), "private-test-password")
        self.assertEqual(stat.S_IMODE(password_file.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_probe_setup_failure_preserves_inventory_and_removes_new_secret(self) -> None:
        path = self.write_inventory()
        original = path.read_bytes()
        inventory = ops.load_inventory(path)
        runner = mock.Mock()
        runner.run.side_effect = ops.OpsError("probe failed")
        with self.assertRaisesRegex(ops.OpsError, "probe failed"):
            ops.configure_probe(
                inventory, inventory.hosts[0],
                {"endpoint": "proxy.example:443", "username": "probe"},
                "private-test-password", runner,
            )
        self.assertEqual(path.read_bytes(), original)
        self.assertEqual(list((self.root / "secrets").iterdir()), [])

    def test_probe_setup_rejects_concurrent_inventory_change(self) -> None:
        path = self.write_inventory()
        inventory = ops.load_inventory(path)
        runner = mock.Mock()
        def change_inventory(_host: object) -> dict[str, str]:
            path.write_text(path.read_text() + "# concurrent change\n")
            return {"status": "passed"}
        runner.run.side_effect = change_inventory
        with self.assertRaisesRegex(ops.OpsError, "changed during"):
            ops.configure_probe(
                inventory, inventory.hosts[0],
                {"endpoint": "proxy.example:443", "username": "probe"},
                "private-test-password", runner,
            )
        self.assertIn("# concurrent change", path.read_text())
        self.assertEqual(list((self.root / "secrets").iterdir()), [])

    def test_probe_setup_does_not_remove_an_existing_secret_on_collision(self) -> None:
        path = self.write_inventory()
        inventory = ops.load_inventory(path)
        secret_dir = self.root / "secrets"
        secret_dir.mkdir(mode=0o700)
        existing = secret_dir / "probe-collision.password"
        existing.write_text("existing-secret", encoding="utf-8")
        existing.chmod(0o600)
        runner = mock.Mock()
        with mock.patch.object(ops.secrets, "token_hex", return_value="collision"), \
             self.assertRaisesRegex(ops.OpsError, "already exists"):
            ops.configure_probe(
                inventory, inventory.hosts[0],
                {"endpoint": "proxy.example:443", "username": "probe"},
                "new-password", runner,
            )
        self.assertEqual(existing.read_text(), "existing-secret")
        runner.run.assert_not_called()

    def test_probe_setup_refuses_replacing_an_existing_probe(self) -> None:
        path = self.write_inventory('[hosts.probe]\nendpoint = "proxy.example:443"')
        inventory = ops.load_inventory(path)
        runner = mock.Mock()
        with self.assertRaisesRegex(ops.OpsError, "already configured"):
            ops.configure_probe(inventory, inventory.hosts[0], {}, None, runner)
        runner.run.assert_not_called()

    def test_ip_probe_requires_packet_evidence_and_forwards_payload_options(self) -> None:
        path = self.write_inventory('[hosts.probe]\nendpoint = "proxy.example:443"\nconnect_ip = true\ntcp_mode = "echo"\nip_target = "198.51.100.1:9999"\nip_mode = "echo"')
        host = ops.load_inventory(path).hosts[0]
        runner = ops.ProbeRunner("masque-probe", self.root)
        for code, verified in [("CONNECT_IP_READY", False), ("CONNECT_IP_SETUP_ONLY", False), ("CONNECT_IP_ROUND_TRIP", True)]:
            report = {"success": True, "selected_transport": "http3", "checks": [{"name": "connect_ip", "status": "pass", "code": code}]}
            completed = subprocess.CompletedProcess([], 0, json.dumps(report).encode(), b"")
            with mock.patch.object(runner, "preflight"), mock.patch.object(runner, "resolve_binary", return_value="masque-probe"), mock.patch.object(ops.subprocess, "run", return_value=completed) as run:
                if verified:
                    self.assertTrue(runner.run(host)["connect_ip_forwarding_verified"])
                else:
                    with self.assertRaisesRegex(ops.OpsError, "forwarding was not verified"):
                        runner.run(host)
                command = run.call_args.args[0]
                self.assertIn("--tcp-mode", command)
                self.assertIn("--ip-target", command)
                self.assertIn("--ip-mode", command)
                if not verified:
                    setup = ops.dataclasses.replace(host, probe=ops.dataclasses.replace(host.probe, ip_setup_only=True))
                    self.assertFalse(runner.run(setup)["connect_ip_forwarding_verified"])
                    self.assertIn("--ip-setup-only", run.call_args.args[0])

    def test_probe_setup_cli_uses_existing_private_credentials_without_disclosure(self) -> None:
        path = self.write_inventory()
        path.write_text(path.read_text().replace("canary = true", "canary = false"))
        password = self.root / "password"
        password.write_text("private-test-password", encoding="utf-8")
        password.chmod(0o600)
        probe = self.root / "fake-probe"
        probe.write_text(
            "#!/usr/bin/env python3\n"
            "import json,sys\n"
            "assert sys.stdin.buffer.read() == b'private-test-password'\n"
            "print(json.dumps({'success': True, 'selected_transport': 'http3', 'checks': []}))\n",
            encoding="utf-8",
        )
        probe.chmod(0o700)
        path.write_text(path.read_text().replace("[defaults]", f'probe_binary = "{probe}"\n[defaults]'))
        completed = subprocess.run(
            [sys.executable, str(SCRIPT), "--inventory", str(path), "--json",
             "configure-probe", "--endpoint", "proxy.example:443",
             "--username", "probe", "--password-file", str(password)],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(json.loads(completed.stdout)["status"], "configured")
        self.assertNotIn("private-test-password", completed.stdout + completed.stderr)
        self.assertEqual(ops.load_inventory(path).hosts[0].probe.password_file, password)

    def test_probe_setup_interactive_password_is_hidden_and_not_printed(self) -> None:
        path = self.write_inventory()
        probe = self.root / "fake-probe"
        probe.write_text(
            "#!/usr/bin/env python3\n"
            "import json,sys\n"
            "assert sys.stdin.buffer.read() == b'private-test-password'\n"
            "print(json.dumps({'success': True, 'selected_transport': 'http3', 'checks': []}))\n",
            encoding="utf-8",
        )
        probe.chmod(0o700)
        path.write_text(path.read_text().replace("[defaults]", f'probe_binary = "{probe}"\n[defaults]'))
        with mock.patch.object(ops.sys.stdin, "isatty", return_value=True), \
             mock.patch("builtins.input", side_effect=["proxy.example:443", "", "probe"]), \
             mock.patch.object(ops.getpass, "getpass", return_value="private-test-password") as hidden, \
             mock.patch("sys.stdout", new_callable=io.StringIO) as stdout, \
             mock.patch("sys.stderr", new_callable=io.StringIO) as stderr:
            self.assertEqual(ops.main(["--inventory", str(path), "configure-probe"]), 0)
        hidden.assert_called_once()
        self.assertNotIn("private-test-password", stdout.getvalue() + stderr.getvalue())
        self.assertNotIn("private-test-password", path.read_text())

    def test_probe_requires_secret_reference_not_inline_password(self) -> None:
        with self.assertRaisesRegex(ops.OpsError, "unknown .*probe.*password"):
            ops.load_inventory(
                self.write_inventory(
                    "[hosts.probe]\n"
                    'endpoint = "proxy.example:443"\n'
                    'username = "probe"\n'
                    'password = "must-not-be-supported"'
                )
            )

    def test_bootstrap_requires_external_password_file_not_inline_secret(self) -> None:
        with self.assertRaisesRegex(ops.OpsError, "unknown .*bootstrap.*password"):
            ops.load_inventory(
                self.write_inventory(
                    "[hosts.bootstrap]\n"
                    'auth_mode = "basic"\n'
                    'tls_cert_path = "/root/fullchain.pem"\n'
                    'tls_key_path = "/root/privkey.pem"\n'
                    f'basic_password_file = "{self.root / "password"}"\n'
                    'password = "must-not-be-supported"'
                )
            )

    def test_bootstrap_probe_must_share_generated_credentials(self) -> None:
        other_password = self.root / "other-password"
        with self.assertRaisesRegex(ops.OpsError, "must use the bootstrap"):
            ops.load_inventory(
                self.write_inventory(
                    "[hosts.bootstrap]\n"
                    'auth_mode = "basic"\n'
                    'tls_cert_path = "/root/fullchain.pem"\n'
                    'tls_key_path = "/root/privkey.pem"\n'
                    f'basic_password_file = "{self.root / "password"}"\n'
                    "[hosts.probe]\n"
                    'endpoint = "proxy.example:443"\n'
                    'username = "masque"\n'
                    f'password_file = "{other_password}"'
                )
            )

    def test_release_versions_follow_semver_prerelease_rules(self) -> None:
        for invalid in ("v1.2.3-01", "v1.2.3-a..b", "v1.2.3-a."):
            with self.subTest(invalid=invalid), self.assertRaises(ops.OpsError):
                ops.normalize_version(invalid)
        self.assertLess(
            ops.version_order("v1.2.3-rc.2"), ops.version_order("v1.2.3-rc.10")
        )
        self.assertLess(ops.version_order("v1.2.3-rc.10"), ops.version_order("v1.2.3"))


class OperationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        inventory_path = self.root / "fleet.toml"
        inventory_path.write_text(
            "\n".join(
                [
                    "schema_version = 1",
                    f'state_path = "{self.root / "state.json"}"',
                    "[[hosts]]",
                    'name = "edge-a"',
                    'address = "203.0.113.10"',
                    'user = "root"',
                    "sudo = false",
                    "canary = true",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        inventory_path.chmod(0o600)
        self.inventory = ops.load_inventory(inventory_path)
        self.host = self.inventory.hosts[0]
        self.original_sleep = ops.time.sleep
        ops.time.sleep = lambda _seconds: None

    def test_generated_self_signed_inventory_bootstraps_and_probes(self) -> None:
        path = self.root / "new-fleet.toml"
        ops.initialize_inventory(path, ssh_host="203.0.113.10",
                                 endpoint_host="proxy.example.com", self_signed=True)
        path.write_text(path.read_text().replace(
            "schema_version = 1", f'schema_version = 1\nstate_path = "{self.root / "fresh-state.json"}"'
        ))
        inventory = ops.load_inventory(path)
        host = inventory.hosts[0]
        ssh = FakeEmptyBootstrapSsh()
        operator = ops.FleetOperator(inventory, ssh=ssh)
        operator.probes = mock.Mock()
        operator.probes.run.return_value = {"status": "passed", "transport": "http3"}
        result = operator.bootstrap_one(host, release("v0.13.0"))
        self.assertTrue(ssh.dependencies_installed)
        self.assertTrue(ssh.certificate_prepared)
        self.assertTrue(host.bootstrap.tls_ca_file.exists())
        self.assertTrue(host.bootstrap.basic_password_file.exists())
        self.assertEqual(result["status"], "installed")
        self.assertEqual(result["probe"]["status"], "passed")

    def test_dual_bootstrap_tests_both_authentication_modes(self) -> None:
        path = self.root / "dual-fleet.toml"
        ops.initialize_inventory(path, ssh_host="203.0.113.10", endpoint_host="proxy.example.com",
                                 self_signed=True, auth_mode="dual", connect_ip=True)
        path.write_text(path.read_text().replace(
            "schema_version = 1", f'schema_version = 1\nstate_path = "{self.root / "dual-state.json"}"'
        ))
        inventory = ops.load_inventory(path)
        host = inventory.hosts[0]
        ssh = FakeEmptyBootstrapSsh()
        operator = ops.FleetOperator(inventory, ssh=ssh)
        operator.probes = mock.Mock()
        operator.probes.run.return_value = {"status": "passed", "transport": "http3"}
        result = operator.bootstrap_one(host, release("v0.13.0"))
        self.assertEqual(operator.probes.run.call_count, 2)
        basic, certificate = (call.args[0].probe for call in operator.probes.run.call_args_list)
        self.assertIsNotNone(basic.username)
        self.assertIsNone(certificate.username)
        self.assertEqual(certificate.client_config, host.bootstrap.client_config)
        self.assertIsNone(certificate.ca_cert)
        self.assertTrue(certificate.connect_ip)
        self.assertEqual(result["certificate_probe"]["status"], "passed")
        self.assertFalse(result["connect_ip_forwarding_verified"])

    def test_http2_bootstrap_rejects_older_releases(self) -> None:
        path = self.root / "h2-fleet.toml"
        ops.initialize_inventory(path, ssh_host="203.0.113.10", endpoint_host="proxy.example.com",
                                 self_signed=True, transport="http2")
        inventory = ops.load_inventory(path)
        operator = ops.FleetOperator(inventory, ssh=FakeEmptyBootstrapSsh())
        operator.probes = mock.Mock()
        old = ops.plan_bootstrap(operator, inventory.hosts[0], release("v0.14.3"))
        new = ops.plan_bootstrap(operator, inventory.hosts[0], release("v0.14.4"))
        self.assertFalse(old["ready"])
        self.assertTrue(any("HTTP/2 bootstrap" in x for x in old["blockers"]))
        self.assertTrue(new["ready"])

    def tearDown(self) -> None:
        ops.time.sleep = self.original_sleep
        self.temporary.cleanup()

    def test_single_host_rollout_requires_probe_but_not_a_canary(self) -> None:
        host = ops.dataclasses.replace(self.host, canary=False,
                                       probe=ops.ProbeConfig(endpoint="proxy.example:443"))
        inventory = ops.dataclasses.replace(self.inventory, hosts=(host,))
        operator = mock.Mock()
        operator.deploy_one.return_value = {"status": "deployed", "version": "v0.13.0"}
        with mock.patch.object(ops, "load_inventory", return_value=inventory), \
             mock.patch.object(ops, "FleetOperator", return_value=operator), \
             mock.patch.object(ops, "ReleaseClient", return_value=FakeReleases("v0.13.0")), \
             mock.patch.object(ops, "plan_upgrade", return_value={"ready": True}), \
             mock.patch("sys.stdout", new_callable=io.StringIO):
            self.assertEqual(ops.main(["--json", "rollout", "--version", "v0.13.0", "--apply"]), 0)
        self.assertEqual(operator.deploy_one.call_count, 1)
        self.assertEqual(operator.deploy_one.call_args.args[0], host)

        no_probe = ops.dataclasses.replace(host, probe=None)
        inventory = ops.dataclasses.replace(inventory, hosts=(no_probe,))
        operator.reset_mock()
        with mock.patch.object(ops, "load_inventory", return_value=inventory), \
             mock.patch.object(ops, "FleetOperator", return_value=operator), \
             mock.patch.object(ops, "ReleaseClient", return_value=FakeReleases("v0.13.0")), \
             mock.patch.object(ops, "plan_upgrade", return_value={"ready": True}), \
             self.assertRaisesRegex(ops.OpsError, "no external probe"):
            ops.main(["--json", "rollout", "--version", "v0.13.0", "--apply"])
        operator.deploy_one.assert_not_called()

        with mock.patch.object(ops, "load_inventory", return_value=inventory), \
             mock.patch.object(ops, "FleetOperator", return_value=operator), \
             mock.patch.object(ops, "ReleaseClient", return_value=FakeReleases("v0.13.0")), \
             mock.patch.object(ops, "plan_upgrade", return_value={"ready": True}), \
             self.assertRaisesRegex(ops.OpsError, "requested canary"):
            ops.main(["--json", "rollout", "--version", "v0.13.0", "--apply", "--canary", "unknown"])
        operator.deploy_one.assert_not_called()

    def test_rollout_of_single_selected_host_from_fleet_needs_no_canary(self) -> None:
        host = ops.dataclasses.replace(self.host, canary=False,
                                       probe=ops.ProbeConfig(endpoint="proxy.example:443"))
        other = ops.dataclasses.replace(host, name="other", canary=True)
        inventory = ops.dataclasses.replace(self.inventory, hosts=(host, other))
        operator = mock.Mock()
        operator.deploy_one.return_value = {"status": "deployed", "version": "v0.13.0"}
        with mock.patch.object(ops, "load_inventory", return_value=inventory), \
             mock.patch.object(ops, "FleetOperator", return_value=operator), \
             mock.patch.object(ops, "ReleaseClient", return_value=FakeReleases("v0.13.0")), \
             mock.patch.object(ops, "plan_upgrade", return_value={"ready": True}), \
             mock.patch("sys.stdout", new_callable=io.StringIO):
            self.assertEqual(ops.main(["--json", "rollout", host.name, "--version", "v0.13.0", "--apply"]), 0)
        self.assertEqual(operator.deploy_one.call_count, 1)
        self.assertEqual(operator.deploy_one.call_args.args[0], host)

    def test_multi_host_rollout_still_requires_canary_and_stops_on_failure(self) -> None:
        first = ops.dataclasses.replace(self.host, canary=False,
                                        probe=ops.ProbeConfig(endpoint="proxy.example:443"))
        second = ops.dataclasses.replace(first, name="second")
        inventory = ops.dataclasses.replace(self.inventory, hosts=(first, second))
        operator = mock.Mock()
        with mock.patch.object(ops, "load_inventory", return_value=inventory), \
             mock.patch.object(ops, "FleetOperator", return_value=operator), \
             mock.patch.object(ops, "ReleaseClient", return_value=FakeReleases("v0.13.0")), \
             mock.patch.object(ops, "plan_upgrade", return_value={"ready": True}), \
             self.assertRaisesRegex(ops.OpsError, "exactly one selected canary"):
            ops.main(["--json", "rollout", "--version", "v0.13.0", "--apply"])
        operator.deploy_one.assert_not_called()

        canary = ops.dataclasses.replace(second, canary=True)
        inventory = ops.dataclasses.replace(inventory, hosts=(first, canary))
        operator.deploy_one.side_effect = ops.OpsError("verification failed")
        with mock.patch.object(ops, "load_inventory", return_value=inventory), \
             mock.patch.object(ops, "FleetOperator", return_value=operator), \
             mock.patch.object(ops, "ReleaseClient", return_value=FakeReleases("v0.13.0")), \
             mock.patch.object(ops, "plan_upgrade", return_value={"ready": True}), \
             self.assertRaisesRegex(ops.OpsError, "verification failed"):
            ops.main(["--json", "rollout", "--version", "v0.13.0", "--apply"])
        self.assertEqual(operator.deploy_one.call_count, 1)
        self.assertEqual(operator.deploy_one.call_args.args[0], canary)

    def test_single_host_deploy_and_rollback_do_not_need_host_name(self) -> None:
        host = ops.dataclasses.replace(self.host, canary=False)
        inventory = ops.dataclasses.replace(self.inventory, hosts=(host,))
        operator = mock.Mock()
        operator.deploy_one.return_value = {"status": "deployed", "version": "v0.13.0"}
        operator.rollback_one.return_value = {"status": "rolled_back", "version": "v0.12.2"}
        with mock.patch.object(ops, "load_inventory", return_value=inventory), \
             mock.patch.object(ops, "FleetOperator", return_value=operator), \
             mock.patch.object(ops, "ReleaseClient", return_value=FakeReleases("v0.13.0")), \
             mock.patch("sys.stdout", new_callable=io.StringIO):
            self.assertEqual(ops.main(["--json", "deploy", "--version", "v0.13.0", "--apply"]), 0)
            self.assertEqual(ops.main(["--json", "rollback", "--apply"]), 0)
        self.assertEqual(operator.deploy_one.call_args.args[0], host)
        self.assertEqual(operator.rollback_one.call_args.args[0], host)

    def profile_operator(self, version: str = "v0.12.2") -> tuple[object, object, object]:
        password = self.root / "secret.password"
        password.write_text("fixture-password")
        password.chmod(0o600)
        client = self.root / "client.json"
        client.write_text('{"private_key":"fixture-key"}')
        client.chmod(0o600)
        profiles = tuple(
            ops.ProbeConfig(endpoint=f"proxy.example:{port}", transport=transport,
                            username="fixture-user" if auth == "basic" else None,
                            password_file=password if auth == "basic" else None,
                            client_config=client if auth == "certificate" else None)
            for transport, port in (("http3", 443), ("http2", 8443))
            for auth in ("basic", "certificate")
        )
        host = ops.dataclasses.replace(self.host, probe=profiles[0], probes=profiles[1:])
        inventory = ops.dataclasses.replace(self.inventory, hosts=(host,))
        ssh = FakeSsh(version)
        operator = ops.FleetOperator(inventory, ssh=ssh)
        return host, ssh, operator

    @staticmethod
    def passing_probe(host: object) -> dict[str, object]:
        return {"status": "passed", "transport": host.probe.transport, "failed_codes": [],
                "connect_ip_forwarding_verified": True if host.probe.connect_ip else None}

    def test_upgrade_rollback_and_already_current_run_complete_matrix(self) -> None:
        host, ssh, operator = self.profile_operator()
        operator.probes = mock.Mock()
        operator.probes.run.side_effect = self.passing_probe
        releases = FakeReleases("v0.12.2", "v0.13.0")
        for action in (
            lambda: operator.deploy_one(host, release("v0.13.0"), releases),
            lambda: operator.deploy_one(host, release("v0.13.0"), releases),
            lambda: operator.rollback_one(host, releases),
        ):
            operator.probes.reset_mock()
            result = action()
            self.assertEqual([call.args[0].probe for call in operator.probes.run.call_args_list], list(ops.required_probes(host)))
            self.assertEqual(len(result["probe"]["profiles"]), 4)
            output = json.dumps(result)
            for private in ("proxy.example", "fixture-user", "secret.password", "client.json", "fixture-key"):
                self.assertNotIn(private, output)
        self.assertEqual(ssh.upgrades, ["v0.13.0", "v0.12.2"])

    def test_real_runner_matrix_uses_explicit_transport_and_private_credentials(self) -> None:
        host, _ssh, operator = self.profile_operator()
        calls = []
        def probe_process(command: list[str], **kwargs: object) -> object:
            transport = command[command.index("--transport") + 1]
            calls.append(command)
            self.assertEqual(kwargs["timeout"], 63)
            if "--username" in command:
                self.assertIn("--password-stdin", command)
                self.assertEqual(kwargs["stdin"].read(), b"fixture-password")
                self.assertNotIn("fixture-password", " ".join(command))
            else:
                self.assertIn("--client-config", command)
            report = {"success": True, "selected_transport": transport, "checks": []}
            return subprocess.CompletedProcess(command, 0, json.dumps(report).encode(), b"")
        with mock.patch.object(operator.probes, "resolve_binary", return_value="fixture-probe"), \
             mock.patch.object(ops.subprocess, "run", side_effect=probe_process):
            result = operator.run_probes(host)
        self.assertEqual(len(result["profiles"]), 4)
        self.assertEqual([args[args.index("--transport") + 1] for args in calls], ["http3", "http3", "http2", "http2"])

    def test_explicit_transport_cannot_pass_through_another_transport(self) -> None:
        host, _ssh, operator = self.profile_operator()
        report = {"success": True, "selected_transport": "http2", "checks": []}
        completed = subprocess.CompletedProcess([], 0, json.dumps(report).encode(), b"")
        with mock.patch.object(operator.probes, "resolve_binary", return_value="fixture-probe"), \
             mock.patch.object(ops.subprocess, "run", return_value=completed):
            with self.assertRaisesRegex(ops.OpsError, "required transport"):
                operator.run_probes(host)

    def test_legacy_dual_upgrade_runs_certificate_probe(self) -> None:
        path = self.root / "legacy-dual.toml"
        ops.initialize_inventory(path, ssh_host="203.0.113.10", endpoint_host="proxy.example.com",
                                 auth_mode="dual", self_signed=True)
        host = ops.dataclasses.replace(ops.load_inventory(path).hosts[0], probes=())
        operator = ops.FleetOperator(self.inventory, ssh=FakeSsh("v0.12.2"))
        operator.probes = mock.Mock()
        operator.probes.run.side_effect = self.passing_probe
        result = operator.deploy_one(host, release("v0.13.0"), FakeReleases("v0.12.2", "v0.13.0"))
        self.assertEqual(len(result["probe"]["profiles"]), 2)
        self.assertEqual(operator.probes.run.call_args_list[1].args[0].probe.client_config, host.bootstrap.client_config)

    def test_missing_secondary_credential_blocks_before_upgrade_or_any_probe(self) -> None:
        host, ssh, operator = self.profile_operator()
        host.probes[0].client_config.unlink()
        with mock.patch.object(operator.probes, "resolve_binary", return_value="fixture-probe"), \
             mock.patch.object(operator.probes, "run") as run:
            plan = ops.plan_upgrade(operator, [host], release("v0.13.0"), FakeReleases("v0.12.2", "v0.13.0"))
            self.assertFalse(plan["ready"])
            self.assertEqual(plan["hosts"][0]["required_probe_count"], 4)
            with self.assertRaises(ops.OpsError):
                operator.deploy_one(host, release("v0.13.0"), FakeReleases("v0.12.2", "v0.13.0"))
            run.assert_not_called()
        self.assertEqual(ssh.upgrades, [])
        self.assertFalse(self.inventory.state_path.exists())

    def test_secondary_failure_rolls_back_and_rechecks_every_profile(self) -> None:
        host, ssh, operator = self.profile_operator()
        operator.probes = mock.Mock()
        seen = []
        def run(selected: object) -> dict[str, object]:
            seen.append((ssh.version, selected.probe))
            if ssh.version == "v0.13.0" and selected.probe == host.probes[-1]:
                raise ops.OpsError("fixture secondary failed")
            return self.passing_probe(selected)
        operator.probes.run.side_effect = run
        with self.assertRaisesRegex(ops.OpsError, "was restored.*required probe 4/4"):
            operator.deploy_one(host, release("v0.13.0"), FakeReleases("v0.12.2", "v0.13.0"))
        self.assertEqual(seen, [(version, profile) for version in ("v0.13.0", "v0.12.2") for profile in ops.required_probes(host)])
        self.assertFalse(self.inventory.state_path.exists())

    def test_unverified_automatic_recovery_never_reports_restored(self) -> None:
        host, ssh, operator = self.profile_operator()
        operator.probes = mock.Mock()
        operator.probes.run.side_effect = ops.OpsError("fixture path unavailable")
        with self.assertRaisesRegex(ops.OpsError, "manual recovery is required"):
            operator.deploy_one(host, release("v0.13.0"), FakeReleases("v0.12.2", "v0.13.0"))
        self.assertEqual(ssh.version, "v0.12.2")
        self.assertFalse(self.inventory.state_path.exists())
        audit = operator.state.audit_path.read_text()
        self.assertIn("automatic_rollback_failed", audit)
        self.assertNotIn("automatic_rollback_succeeded", audit)

    def test_installer_self_recovery_still_requires_external_probes(self) -> None:
        host, ssh, operator = self.profile_operator()
        operator.probes = mock.Mock()
        operator.probes.run.side_effect = self.passing_probe
        with mock.patch.object(operator, "_run_upgrade", side_effect=ops.OpsError("fixture install failed")):
            with self.assertRaisesRegex(ops.OpsError, "was restored"):
                operator.deploy_one(host, release("v0.13.0"), FakeReleases("v0.12.2", "v0.13.0"))
        self.assertEqual(operator.probes.run.call_count, 4)
        self.assertEqual(ssh.upgrades, [])

    def test_failed_rollback_checks_recovery_and_preserves_local_state(self) -> None:
        host, ssh, operator = self.profile_operator("v0.13.0")
        operator.state.save_transition(host.name, "v0.12.2", "v0.13.0")
        before = self.inventory.state_path.read_bytes()
        operator.probes = mock.Mock()
        seen = []
        def run(selected: object) -> dict[str, object]:
            seen.append((ssh.version, selected.probe))
            if ssh.version == "v0.12.2" and selected.probe == host.probes[-1]:
                raise ops.OpsError("fixture older release failed")
            return self.passing_probe(selected)
        operator.probes.run.side_effect = run
        with self.assertRaisesRegex(ops.OpsError, "rollback failed.*was restored"):
            operator.rollback_one(host, FakeReleases("v0.12.2", "v0.13.0"))
        self.assertEqual(seen, [(version, profile) for version in ("v0.12.2", "v0.13.0") for profile in ops.required_probes(host)])
        self.assertEqual(self.inventory.state_path.read_bytes(), before)
        self.assertEqual(ssh.upgrades, ["v0.12.2", "v0.13.0"])

    def test_failed_rollback_recovery_probe_requires_manual_recovery(self) -> None:
        host, ssh, operator = self.profile_operator("v0.13.0")
        operator.state.save_transition(host.name, "v0.12.2", "v0.13.0")
        before = self.inventory.state_path.read_bytes()
        operator.probes = mock.Mock()
        operator.probes.run.side_effect = ops.OpsError("fixture path unavailable")
        with self.assertRaisesRegex(ops.OpsError, "rollback and recovery both failed.*manual recovery"):
            operator.rollback_one(host, FakeReleases("v0.12.2", "v0.13.0"))
        self.assertEqual(ssh.version, "v0.13.0")
        self.assertEqual(self.inventory.state_path.read_bytes(), before)
        audit = operator.state.audit_path.read_text()
        self.assertIn("rollback_recovery_failed", audit)
        self.assertNotIn("rollback_recovery_succeeded", audit)

    def test_multi_profile_ip_summary_never_promotes_setup_only_to_forwarding(self) -> None:
        host, _ssh, operator = self.profile_operator()
        host = ops.dataclasses.replace(host, probes=(ops.dataclasses.replace(host.probes[0], connect_ip=True),))
        operator.probes = mock.Mock()
        operator.probes.run.side_effect = [self.passing_probe(host), {"status": "passed", "connect_ip_forwarding_verified": False}]
        self.assertFalse(operator.run_probes(host)["connect_ip_forwarding_verified"])

    def test_profiles_only_rollout_and_plan_do_not_need_a_primary(self) -> None:
        host, _ssh, operator = self.profile_operator()
        host = ops.dataclasses.replace(host, probe=None)
        operator.probes = mock.Mock()
        operator.probes.run.side_effect = self.passing_probe
        releases = FakeReleases("v0.12.2", "v0.13.0")
        plan = ops.plan_upgrade(operator, [host], release("v0.13.0"), releases)
        self.assertTrue(plan["ready"])
        self.assertTrue(plan["hosts"][0]["probe_configured"])
        self.assertEqual(plan["hosts"][0]["required_probe_count"], 3)
        with mock.patch("sys.stdout", new_callable=io.StringIO) as output:
            ops.print_plan(plan)
        self.assertIn("3 required probes", output.getvalue())
        inventory = ops.dataclasses.replace(self.inventory, hosts=(host,))
        with mock.patch.object(ops, "load_inventory", return_value=inventory), \
             mock.patch.object(ops, "FleetOperator", return_value=operator), \
             mock.patch.object(ops, "ReleaseClient", return_value=releases), \
             mock.patch("sys.stdout", new_callable=io.StringIO):
            self.assertEqual(ops.main(["--json", "rollout", "--version", "v0.13.0", "--apply"]), 0)
        self.assertEqual(operator.probes.run.call_count, 3)
        with self.assertRaisesRegex(ops.OpsError, "already configured"):
            ops.configure_probe(inventory, host, {}, None, operator.probes)

    def test_legacy_single_probe_result_remains_unchanged(self) -> None:
        host, _ssh, operator = self.profile_operator()
        host = ops.dataclasses.replace(host, probes=())
        operator.probes = mock.Mock()
        expected = self.passing_probe(host)
        operator.probes.run.return_value = expected
        self.assertEqual(operator.run_probes(host), expected)
        self.assertEqual(operator.run_probes(self.host), {"status": "not_configured"})

    def test_deploy_records_transition_and_rollback_is_reversible(self) -> None:
        ssh = FakeSsh("v0.12.2")
        operator = ops.FleetOperator(self.inventory, ssh=ssh)
        releases = FakeReleases("v0.12.2", "v0.13.0")

        deployed = operator.deploy_one(self.host, release("v0.13.0"), releases)
        self.assertEqual(deployed["status"], "deployed")
        self.assertEqual(ssh.upgrades, ["v0.13.0"])
        state = json.loads(self.inventory.state_path.read_text(encoding="utf-8"))
        self.assertEqual(state["hosts"]["edge-a"]["rollback_version"], "v0.12.2")
        self.assertEqual(stat.S_IMODE(self.inventory.state_path.stat().st_mode), 0o600)
        audit = self.inventory.state_path.with_name("ops-audit.jsonl")
        self.assertEqual(stat.S_IMODE(audit.stat().st_mode), 0o600)
        self.assertNotIn(self.host.address, audit.read_text(encoding="utf-8"))

        rolled_back = operator.rollback_one(self.host, releases)
        self.assertEqual(rolled_back["version"], "v0.12.2")
        self.assertEqual(ssh.upgrades, ["v0.13.0", "v0.12.2"])

    def test_failed_post_deploy_health_check_restores_previous_release(self) -> None:
        ssh = FakeSsh("v0.12.2", unhealthy={"v0.13.0"})
        operator = ops.FleetOperator(self.inventory, ssh=ssh)
        releases = FakeReleases("v0.12.2", "v0.13.0")

        with self.assertRaisesRegex(ops.OpsError, "was restored"):
            operator.deploy_one(self.host, release("v0.13.0"), releases)
        self.assertEqual(ssh.version, "v0.12.2")
        self.assertEqual(ssh.upgrades, ["v0.13.0", "v0.12.2"])
        self.assertFalse(self.inventory.state_path.exists())

    def test_configuration_hash_drift_restores_previous_release(self) -> None:
        ssh = FakeSsh("v0.12.2", config_drift={"v0.13.0"})
        operator = ops.FleetOperator(self.inventory, ssh=ssh)
        releases = FakeReleases("v0.12.2", "v0.13.0")

        with self.assertRaisesRegex(ops.OpsError, "was restored"):
            operator.deploy_one(self.host, release("v0.13.0"), releases)
        self.assertEqual(ssh.version, "v0.12.2")
        self.assertEqual(ssh.upgrades, ["v0.13.0", "v0.12.2"])

    def test_failed_local_state_write_restores_previous_release(self) -> None:
        ssh = FakeSsh("v0.12.2")
        operator = ops.FleetOperator(self.inventory, ssh=ssh)
        operator.state = FailingState()
        releases = FakeReleases("v0.12.2", "v0.13.0")

        with self.assertRaisesRegex(ops.OpsError, "was restored"):
            operator.deploy_one(self.host, release("v0.13.0"), releases)
        self.assertEqual(ssh.version, "v0.12.2")
        self.assertEqual(ssh.upgrades, ["v0.13.0", "v0.12.2"])

    def test_failed_audit_does_not_interrupt_automatic_restore(self) -> None:
        ssh = FakeSsh("v0.12.2", unhealthy={"v0.13.0"})
        operator = ops.FleetOperator(self.inventory, ssh=ssh)
        operator.state = AuditFailsAfterStart()
        releases = FakeReleases("v0.12.2", "v0.13.0")

        with self.assertRaisesRegex(ops.OpsError, "audit logging also failed"):
            operator.deploy_one(self.host, release("v0.13.0"), releases)
        self.assertEqual(ssh.version, "v0.12.2")
        self.assertEqual(ssh.upgrades, ["v0.13.0", "v0.12.2"])

    def test_plan_requires_current_release_assets_for_rollback(self) -> None:
        ssh = FakeSsh("v0.12.2")
        operator = ops.FleetOperator(self.inventory, ssh=ssh)
        releases = FakeReleases("v0.13.0")

        plan = ops.plan_upgrade(operator, [self.host], release("v0.13.0"), releases)
        self.assertFalse(plan["ready"])
        self.assertIn(
            "current release is unavailable for automatic rollback",
            plan["hosts"][0]["blockers"],
        )

    def test_mutation_requires_explicit_apply(self) -> None:
        with self.assertRaisesRegex(ops.OpsError, "not authorized"):
            ops.require_apply(False)

    def test_non_object_state_is_rejected_cleanly(self) -> None:
        self.inventory.state_path.write_text("[]\n", encoding="utf-8")
        self.inventory.state_path.chmod(0o600)
        with self.assertRaisesRegex(ops.OpsError, "state schema"):
            ops.StateStore(self.inventory.state_path).load()

    def test_fresh_bootstrap_keeps_password_out_of_ssh_arguments_and_results(
        self,
    ) -> None:
        password_path = self.root / "bootstrap.password"
        inventory_path = self.root / "bootstrap.toml"
        inventory_path.write_text(
            "\n".join(
                [
                    "schema_version = 1",
                    f'state_path = "{self.root / "bootstrap-state.json"}"',
                    "[[hosts]]",
                    'name = "new-edge"',
                    'address = "203.0.113.20"',
                    'user = "root"',
                    "sudo = false",
                    "[hosts.bootstrap]",
                    'auth_mode = "basic"',
                    'tls_cert_path = "/root/fullchain.pem"',
                    'tls_key_path = "/root/privkey.pem"',
                    'basic_username = "probe-user"',
                    f'basic_password_file = "{password_path}"',
                    "",
                ]
            ),
            encoding="utf-8",
        )
        inventory_path.chmod(0o600)
        inventory = ops.load_inventory(inventory_path)
        host = inventory.hosts[0]
        ssh = FakeBootstrapSsh()
        operator = ops.FleetOperator(inventory, ssh=ssh)

        plan = ops.plan_bootstrap(operator, host, release("v0.13.0"))
        self.assertTrue(plan["ready"], plan["blockers"])
        result = operator.bootstrap_one(host, release("v0.13.0"))

        password = password_path.read_text(encoding="utf-8").strip()
        self.assertGreaterEqual(len(password), 32)
        self.assertNotIn(password, ssh.install_command)
        self.assertIn(password, ssh.install_input)
        self.assertIn("export MASQUE_PRINT_SECRETS=0", ssh.install_input)
        self.assertNotIn(password, json.dumps(result))
        self.assertEqual(stat.S_IMODE(password_path.stat().st_mode), 0o600)
        self.assertEqual(result["status"], "installed")
        audit = inventory.state_path.with_name("ops-audit.jsonl").read_text(
            encoding="utf-8"
        )
        self.assertNotIn(password, audit)
        self.assertNotIn(host.address, audit)

    def test_certificate_bootstrap_streams_client_key_to_private_file(self) -> None:
        client_path = self.root / "client.json"
        inventory_path = self.root / "certificate-bootstrap.toml"
        inventory_path.write_text(
            "\n".join(
                [
                    "schema_version = 1",
                    f'state_path = "{self.root / "certificate-state.json"}"',
                    "[[hosts]]",
                    'name = "new-cert-edge"',
                    'address = "203.0.113.30"',
                    'user = "root"',
                    "sudo = false",
                    "[hosts.bootstrap]",
                    'auth_mode = "client_cert"',
                    "listen_port = 4443",
                    'tls_cert_path = "/root/fullchain.pem"',
                    'tls_key_path = "/root/privkey.pem"',
                    'client_name = "laptop"',
                    'client_endpoint = "proxy.example:4443"',
                    f'client_config = "{client_path}"',
                    "",
                ]
            ),
            encoding="utf-8",
        )
        inventory_path.chmod(0o600)
        inventory = ops.load_inventory(inventory_path)
        host = inventory.hosts[0]
        ssh = FakeBootstrapSsh()
        operator = ops.FleetOperator(inventory, ssh=ssh)

        result = operator.bootstrap_one(host, release("v0.13.0"))

        self.assertIn("client-secret", client_path.read_text(encoding="utf-8"))
        self.assertEqual(stat.S_IMODE(client_path.stat().st_mode), 0o600)
        self.assertNotIn("client-secret", json.dumps(result))
        self.assertNotIn("client-secret", ssh.install_command)


class SecurityTests(unittest.TestCase):
    def test_skill_is_self_contained_and_versioned(self) -> None:
        self.assertEqual((SKILL_ROOT / "VERSION").read_text().strip(), PACKAGE_VERSION)
        self.assertEqual(
            (SKILL_ROOT / "scripts/install-latest.sh").read_bytes(),
            (ROOT / "install-latest.sh").read_bytes(),
        )
        self.assertEqual(
            (SKILL_ROOT / "scripts/install-probe.sh").read_bytes(),
            (ROOT / "install-probe.sh").read_bytes(),
        )
        self.assertEqual(
            (SKILL_ROOT / "assets/fleet.example.toml").read_bytes(),
            (ROOT / "deploy/config/fleet.example.toml").read_bytes(),
        )

        with tempfile.TemporaryDirectory() as temporary:
            isolated = Path(temporary) / "masque-ops"
            shutil.copytree(SKILL_ROOT, isolated)
            completed = subprocess.run(
                [str(isolated / "scripts/masque-ops.py"), "--version"],
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout.strip(), f"masque-ops {PACKAGE_VERSION}")

    def test_repository_launcher_uses_the_bundled_cli(self) -> None:
        completed = subprocess.run(
            [str(REPOSITORY_LAUNCHER), "--version"],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout.strip(), f"masque-ops {PACKAGE_VERSION}")

    @unittest.skipUnless(shutil.which("sh"), "POSIX shell is required")
    def test_embedded_remote_scripts_have_valid_shell_syntax(self) -> None:
        for name in (
            "STATUS_SCRIPT",
            "DIAGNOSE_SCRIPT",
            "BOOTSTRAP_PREFLIGHT_SCRIPT",
            "SELF_SIGNED_CERT_SCRIPT",
            "PREPARE_DEPENDENCIES_SCRIPT",
        ):
            with self.subTest(script=name):
                completed = subprocess.run(
                    ["sh", "-n"],
                    input=getattr(ops, name),
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_safe_tail_removes_credentials(self) -> None:
        output = ops.safe_tail(
            "Password: secret\nnormal failure",
            "private_key = hidden\nservice failed",
        )
        self.assertEqual(output, "normal failure | service failed")

    def test_diagnostic_output_redacts_authentication_material(self) -> None:
        output = ops.sanitize_diagnostics(
            "healthy\n"
            "username = alice\n"
            "client=certificate-label connection accepted\n"
            "Proxy-Authorization: Basic c2VjcmV0\n"
            "-----BEGIN PRIVATE KEY-----\n"
            "secret-body\n"
            "-----END PRIVATE KEY-----\n"
            "complete\n"
        )
        self.assertIn("healthy", output)
        self.assertIn("complete", output)
        self.assertNotIn("alice", output)
        self.assertNotIn("certificate-label", output)
        self.assertNotIn("c2VjcmV0", output)
        self.assertNotIn("secret-body", output)

    def test_ssh_arguments_disable_ambient_configuration_and_forwarding(self) -> None:
        host = ops.Host(
            name="edge",
            address="203.0.113.1",
            user="root",
            port=22,
            identity_file=None,
            known_hosts_file=None,
            use_sudo=False,
            service="masque.service",
            config_path="/etc/masque/masque.toml",
            binary_path="/usr/local/bin/masque-server",
            cert_path="/etc/masque/certs/server.crt",
            maintenance_path="/usr/local/sbin/masque-maintain",
            connect_timeout_secs=10,
            command_timeout_secs=60,
            deploy_timeout_secs=900,
            canary=False,
            probe=None,
            bootstrap=None,
        )
        arguments = ops.SshClient().arguments(host, "true")
        joined = " ".join(arguments)
        self.assertIn("-F /dev/null", joined)
        self.assertIn("StrictHostKeyChecking=yes", joined)
        self.assertIn("PasswordAuthentication=no", joined)
        self.assertIn("KbdInteractiveAuthentication=no", joined)
        self.assertIn("ClearAllForwardings=yes", joined)
        self.assertIn("ForwardAgent=no", joined)

    def test_host_key_file_must_not_be_a_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "known_hosts.real"
            target.write_text("example fixture", encoding="utf-8")
            link = root / "known_hosts"
            link.symlink_to(target)
            with self.assertRaisesRegex(ops.OpsError, "symbolic link"):
                ops.ensure_integrity_file(link, "known_hosts")


if __name__ == "__main__":
    unittest.main()
