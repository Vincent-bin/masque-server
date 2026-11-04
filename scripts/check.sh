#!/bin/sh
# Shared local and CI checks. Run from any working directory.
set -eu
cd "$(dirname "$0")/.."

quick() {
    cargo fmt --all --check
    # Check each file individually with the interpreter named by its shebang.
    for script in install-latest.sh install-ops.sh install-probe.sh \
        deploy/install.sh deploy/masque-maintain scripts/*.sh tests/*.sh tests/e2e/*.sh; do
        case "$(head -n 1 "$script")" in
            *bash) bash -n "$script" ;;
            *) sh -n "$script" ;;
        esac
    done
}

quality() {
    quick
    cargo clippy --workspace --all-targets --locked -- -D warnings
    shellcheck install-latest.sh install-ops.sh install-probe.sh \
        deploy/install.sh deploy/masque-maintain scripts/*.sh tests/*.sh tests/e2e/*.sh
    sh tests/install-ops.sh
    sh tests/install-probe.sh
    sh tests/release-metadata.sh
    python3 -m unittest -v tests/test_masque_ops.py
    python3 -m unittest -v tests/test_performance_baseline.py
}

msrv() { cargo +1.88.0 check --workspace --locked; }
test_workspace() { cargo test --workspace --locked; }

case "${1:-}" in
    quick) quick ;;
    quality) quality ;;
    msrv) msrv ;;
    test) test_workspace ;;
    full) quality; msrv; test_workspace ;;
    *) echo "Usage: scripts/check.sh {quick|quality|msrv|test|full}" >&2; exit 2 ;;
esac
