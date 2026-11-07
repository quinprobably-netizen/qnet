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

echo "Restart the shell to load QML changes: omarchy restart shell"
echo "First run: qnet pihole setup <pi-hole-address>   (in a terminal)"
