#!/bin/bash
# Build and install the qnet backend for the qqq.qnet shell plugin.
#
# The build directory lives outside the plugin folder on purpose: the shell
# watches ~/.config/omarchy/plugins/ and reloads on every file change there.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export CARGO_TARGET_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/qnet/target"

cargo build --release --manifest-path "$here/backend/Cargo.toml"
install -Dm755 "$CARGO_TARGET_DIR/release/qnet" "$HOME/.local/bin/qnet"
echo "Installed $HOME/.local/bin/qnet"

# Stop a running `qnet watch`: it keeps running the old binary, and an old one
# rewrites the watchdog store without the fields it does not know. The shell
# (QnetService.qml) starts a new one from the installed binary within seconds.
# One-shot verbs catch SIGTERM and finish their step first.
pkill -x qnet || true

echo "Restart the shell to load QML changes: omarchy restart shell"
echo "First run: qnet pihole setup <pi-hole-address>   (in a terminal)"
