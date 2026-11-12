#!/usr/bin/env python3
"""Run bounded raw QUIC experiments; certificates and raw logs stay outside git."""
import argparse
import json
import os
from pathlib import Path
import shlex
import socket
import subprocess
import tempfile
import time
import uuid


def events(path):
    result = []
    for line in path.read_text(errors="replace").splitlines():
        try:
            result.append(json.loads(line))
        except ValueError:
            pass
    return result


def certificates(directory):
    cert, key = directory / "test.crt", directory / "test.key"
    with (directory / "certificate.log").open("w") as log:
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt",
            "ec_paramgen_curve:prime256v1", "-nodes", "-days", "2",
            "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
            "-addext", "basicConstraints=critical,CA:FALSE",
            "-keyout", str(key), "-out", str(cert),
        ], stdout=log, stderr=log, check=True)
    return cert, key


def pair(binary, directory, cert, key, server_backend, client_backend,
         mode, payload=1200, seconds=5, window=256, pps=0, byte_count=268435456,
         repeat=0, remote=None, topology="mac-local"):
    server_remote = topology in ("mac-linux", "linux-local")
    client_remote = topology in ("linux-mac", "linux-local")
    def remote_command(command):
        return ["ssh", "-o", "ConnectTimeout=8", remote["ssh_target"],
                shlex.join(["timeout", "95", *map(str, command)])]
    if server_remote:
        code = "import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(('0.0.0.0',0)); print(s.getsockname()[1])"
        port = int(subprocess.check_output(remote_command(["python3", "-c", code]), timeout=15))
    else:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
    tag = f"{mode}-{payload}-{pps}-{server_backend}-{client_backend}-{repeat}"
    server_log, client_log = directory / f"{tag}.server.log", directory / f"{tag}.client.log"
    common = ["--cert", str(cert), "--mode", mode]
    bind = "127.0.0.1" if topology in ("mac-local", "linux-local") else "0.0.0.0"
    peer = "127.0.0.1" if topology in ("mac-local", "linux-local") else remote["linux_address" if server_remote else "mac_address"]
    server_command = [str(binary), "--backend", server_backend, "--server",
                      "--bind", f"{bind}:{port}", "--key", str(key), *common]
    client_command = [str(binary), "--backend", client_backend, "--bind", f"{bind}:0", "--peer",
                      f"{peer}:{port}", "--payload", str(payload),
                      "--seconds", str(seconds), "--window", str(window),
                      "--pps", str(pps), "--bytes", str(byte_count), *common]
    def remap(command):
        replacements = {str(binary): remote["remote_dir"] + "/quic-compare",
                        str(cert): remote["remote_dir"] + "/test.crt",
                        str(key): remote["remote_dir"] + "/test.key"}
        return remote_command([replacements.get(x, x) for x in command])
    if server_remote:
        server_command = remap(server_command)
    if client_remote:
        client_command = remap(client_command)
    with server_log.open("w") as sout, client_log.open("w") as cout:
        server = subprocess.Popen(server_command, stdout=sout, stderr=sout)
        try:
            deadline = time.monotonic() + 10
            while not any(e.get("event") == "ready" for e in events(server_log)):
                if server.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError(f"server failed to become ready: {tag}")
                time.sleep(0.02)
            client = subprocess.run(client_command, stdout=cout, stderr=cout, timeout=95)
            if client.returncode:
                raise RuntimeError(f"client failed: {tag}")
            if server.wait(timeout=15):
                raise RuntimeError(f"server failed: {tag}")
        finally:
            if server.poll() is None:
                server.terminate()
                try:
                    server.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait()
    ce, se = events(client_log), events(server_log)
    result = next(e for e in ce if e.get("event") == "result")
    result.update(server=server_backend, client=client_backend, repeat=repeat, topology=topology,
                  server_cpu=next(e["cpu_seconds"] for e in se if e.get("event") == "process"),
                  client_cpu=next(e["cpu_seconds"] for e in ce if e.get("event") == "process"),
                  server_socket=next(e for e in se if e.get("event") == "socket"),
                  client_socket=next(e for e in ce if e.get("event") == "socket"))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--smoke", action="store_true")
    parser.add_argument("--keep-going", action="store_true", help="record failed attempts and continue the matrix; exit remains nonzero")
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--seconds", type=float, default=5)
    parser.add_argument("--case", choices=["all", "datagram64", "datagram1200", "latency", "stream"], default="all")
    parser.add_argument("--server-backend", choices=["quiche", "quinn"])
    parser.add_argument("--client-backend", choices=["quiche", "quinn"])
    parser.add_argument("--output", type=Path)
    parser.add_argument("--topology", choices=["mac-local", "linux-local", "mac-linux", "linux-mac"], default="mac-local",
                        help="client location followed by server location")
    parser.add_argument("--remote-config", type=Path, help="private connection JSON outside the repository; SSH handles authentication")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    binary = root / "target/release/quic-compare"
    directory = args.output or Path(tempfile.mkdtemp(prefix="raw-quic-comparison-"))
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    directory.chmod(0o700)
    cert, key = certificates(directory)
    remote = None
    if args.topology != "mac-local":
        if not args.remote_config:
            parser.error("this topology needs --remote-config")
        remote = json.loads(args.remote_config.read_text())
        remote_dir = remote["remote_dir"]
        if not remote_dir.startswith("/tmp/quic-compare-") or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_/" for c in remote_dir):
            parser.error("remote_dir must be an isolated /tmp/quic-compare-* directory")
        remote_dir += "/run-" + uuid.uuid4().hex[:12]
        remote["remote_dir"] = remote_dir
        subprocess.run(["ssh", remote["ssh_target"], shlex.join(["mkdir", "-p", "-m", "700", remote_dir])], check=True, capture_output=True)
        linux_binary = root / "target/x86_64-unknown-linux-musl/release/quic-compare"
        subprocess.run(["scp", "-q", str(linux_binary), str(cert), str(key), remote["ssh_target"] + ":" + remote_dir + "/"], check=True, capture_output=True)
        subprocess.run(["ssh", remote["ssh_target"], shlex.join(["chmod", "700", remote_dir + "/quic-compare"])], check=True, capture_output=True)
    combos = [(s, c) for s in ("quiche", "quinn") for c in ("quiche", "quinn")]
    combos = [(s, c) for s, c in combos if (not args.server_backend or s == args.server_backend)
              and (not args.client_backend or c == args.client_backend)]
    available_cases = dict(datagram64=("datagram", 64, 0), datagram1200=("datagram", 1200, 0),
                           latency=("datagram", 64, 100), stream=("stream", 1200, 0))
    cases = list(available_cases.values()) if args.case == "all" else [available_cases[args.case]]
    repeats = 1 if args.smoke else args.repeats
    failed = 0
    with (directory / "results.jsonl").open("w") as out, (directory / "failures.jsonl").open("w") as failures:
        for repeat in range(repeats):
            for mode, payload, pps in cases:
                order = combos if repeat % 2 == 0 else list(reversed(combos))
                for server, client in order:
                    try:
                        result = pair(binary, directory, cert, key, server, client,
                                      mode, payload, 0.3 if args.smoke else args.seconds,
                                      1 if pps else 256, pps,
                                      1024 * 1024 if args.smoke else 256 * 1024 * 1024,
                                      repeat, remote, args.topology)
                    except (RuntimeError, subprocess.SubprocessError) as error:
                        failed += 1
                        tag = f"{mode}-{payload}-{pps}-{server}-{client}-{repeat}"
                        logs = "\n".join(p.read_text(errors="replace") for p in directory.glob(tag + ".*.log"))
                        reason = "too_many_stream_gaps" if "too many gaps in stream buffer" in logs else "experiment_failed"
                        failure = dict(event="failure", topology=args.topology, mode=mode,
                                       payload=payload, target_pps=pps, server=server,
                                       client=client, repeat=repeat, reason=reason,
                                       error_type=type(error).__name__)
                        failures.write(json.dumps(failure) + "\n")
                        failures.flush()
                        print(json.dumps(failure), flush=True)
                        if not args.keep_going:
                            raise
                        continue
                    out.write(json.dumps(result) + "\n")
                    out.flush()
                    print(json.dumps(result), flush=True)
    # This path is local experimental output, never a fleet inventory.
    print(json.dumps({"event": "complete", "directory": str(directory), "failed_attempts": failed}))
    return int(failed > 0)


if __name__ == "__main__":
    os.umask(0o077)
    raise SystemExit(main())
