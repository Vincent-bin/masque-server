from __future__ import annotations

import importlib.util
import json
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKILL_ROOT = ROOT / ".agents" / "skills" / "masque-ops"
SCRIPT = SKILL_ROOT / "scripts" / "masque-ops.py"
REPOSITORY_LAUNCHER = ROOT / "scripts" / "masque-ops.py"
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

    def tearDown(self) -> None:
        ops.time.sleep = self.original_sleep
        self.temporary.cleanup()

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
        self.assertEqual((SKILL_ROOT / "VERSION").read_text().strip(), "0.13.0")
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
        self.assertEqual(completed.stdout.strip(), "masque-ops 0.13.0")

    def test_repository_launcher_uses_the_bundled_cli(self) -> None:
        completed = subprocess.run(
            [str(REPOSITORY_LAUNCHER), "--version"],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout.strip(), "masque-ops 0.13.0")

    @unittest.skipUnless(shutil.which("sh"), "POSIX shell is required")
    def test_embedded_remote_scripts_have_valid_shell_syntax(self) -> None:
        for name in (
            "STATUS_SCRIPT",
            "DIAGNOSE_SCRIPT",
            "BOOTSTRAP_PREFLIGHT_SCRIPT",
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
