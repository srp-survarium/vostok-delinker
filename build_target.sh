#!/usr/bin/env bash
# Linux equivalent of build_target.bat.
# Runs vostok-delinker natively (no Wine) to delink survarium.exe → target obj files.
#
# Env vars (set automatically by flake.nix devShell):
#   SURVARIUM_BIN — directory containing survarium.exe and survarium.pdb
#                   defaults to vostok/binaries/game/ on Linux
#   ROOT_DIR      — parent of vostok/, vostok-delinker/, etc.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
: "${ROOT_DIR:="$(cd "$SCRIPT_DIR/.." && pwd)"}"
: "${VOSTOK_DIR:="$ROOT_DIR/vostok"}"
: "${SURVARIUM_BIN:="$VOSTOK_DIR/binaries/game"}"

OBJDIFF_DIR="$VOSTOK_DIR/binaries/objdiff"

if [[ ! -f "$SURVARIUM_BIN/survarium.exe" ]]; then
  echo "[delinker] ERROR: survarium.exe not found at $SURVARIUM_BIN"
  echo "  Run: bash vostok/scripts/setup-toolchain.sh (requires result-survarium-game)"
  exit 1
fi

if [[ ! -f "$SURVARIUM_BIN/survarium.pdb" ]]; then
  echo "[delinker] ERROR: survarium.pdb not found at $SURVARIUM_BIN"
  exit 1
fi

rm -rf "$OBJDIFF_DIR/target"
mkdir -p "$OBJDIFF_DIR/target"

echo "[delinker] Delinking target (original game) ..."
cargo run --manifest-path "$SCRIPT_DIR/Cargo.toml" --release -- \
  --pdb-path    "$SURVARIUM_BIN/survarium.pdb" \
  --exe-path    "$SURVARIUM_BIN/survarium.exe" \
  --output-path "$OBJDIFF_DIR/target"

echo "[delinker] Regenerating objdiff config ..."
python3 "$VOSTOK_DIR/scripts/generate_objdiff_config.py"

echo "[delinker] Done. Target obj files at: $OBJDIFF_DIR/target"
