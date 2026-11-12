#!/usr/bin/env python3
"""Prepare reproducible P1 patches without editing the registry or production.

The generated source/workspaces live only under this experiment's target/.
The patch is a feasibility prototype, not an adopted production dependency.
"""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess


ROOT = Path(__file__).resolve().parent


def prepare_package(package, sources, manifest):
    entry = manifest[package]
    source = sources[(package, entry["version"])]
    for relative, expected in entry["files"].items():
        actual = hashlib.sha256((source / relative).read_bytes()).hexdigest()
        if actual != expected:
            raise RuntimeError(f"published {package} source hash mismatch")
    target = ROOT / "target" / entry["directory"]
    # Copy the published source afresh on each invocation before applying.
    shutil.copytree(source, target, dirs_exist_ok=True)
    subprocess.run(
        ["patch", "-p1", "-i", str(ROOT / "patches" / entry["patch"])],
        cwd=target, check=True, capture_output=True, text=True,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--variant", choices=("compatibility", "socket-only"), default="compatibility")
    args = parser.parse_args()
    metadata = subprocess.run(
        ["cargo", "metadata", "--locked", "--format-version", "1", "--manifest-path", str(ROOT / "Cargo.toml")],
        check=True, capture_output=True, text=True,
    )
    sources = {
        (p["name"], p["version"]): Path(p["manifest_path"]).parent
        for p in json.loads(metadata.stdout)["packages"]
    }
    manifest = json.loads((ROOT / "patches" / "manifest.json").read_text())
    packages = ["datagram-socket"]
    if args.variant == "compatibility":
        packages.append("tokio-quiche")
    for package in packages:
        prepare_package(package, sources, manifest)
    destination = ROOT / "target" / ("patched-workspace" if args.variant == "compatibility" else "socket-workspace")
    destination.mkdir(parents=True, exist_ok=True)
    shutil.copytree(ROOT / "src", destination / "src", dirs_exist_ok=True)
    shutil.copyfile(ROOT / "Cargo.lock", destination / "Cargo.lock")
    patches = "\n[patch.crates-io]\n" + "".join(
        f'{package} = {{ path = "../{manifest[package]["directory"]}" }}\n'
        for package in packages
    )
    (destination / "Cargo.toml").write_text((ROOT / "Cargo.toml").read_text() + patches)
    # Resolve path patches in the disposable lockfile; retain the production and
    # checked-in experiment lockfiles exactly as they were.
    subprocess.run(
        ["cargo", "metadata", "--offline", "--format-version", "1", "--manifest-path", str(destination / "Cargo.toml")],
        check=True, capture_output=True, text=True,
    )
    print(json.dumps({"prepared": args.variant, "patches": packages}))


if __name__ == "__main__":
    main()
