#!/usr/bin/env bash
# Linux equivalent of build_base.bat.
# Runs vostok-delinker natively (no Wine) to delink the compiled EXE → base obj files.
#
# Env vars (set automatically by flake.nix devShell):
#   ROOT_DIR — parent of vostok/, vostok-delinker/, etc.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
: "${ROOT_DIR:="$(cd "$SCRIPT_DIR/.." && pwd)"}"
: "${VOSTOK_DIR:="$ROOT_DIR/vostok"}"

BUILD_DIR="$VOSTOK_DIR/binaries/Win32"
OBJDIFF_DIR="$VOSTOK_DIR/binaries/objdiff"

PDB_FILE="$BUILD_DIR/survarium-dx11-win32-gold.pdb"
EXE_FILE="$BUILD_DIR/survarium-dx11-win32-gold.exe"

if [[ ! -f "$EXE_FILE" ]]; then
  echo "[delinker] ERROR: $EXE_FILE not found."
  echo "  Build with: wine binaries/toolchain/ninja/ninja.exe -C \"\$(winepath -w binaries/ninja)\" -j8"
  exit 1
fi

if [[ ! -f "$PDB_FILE" ]]; then
  echo "[delinker] ERROR: $PDB_FILE not found."
  exit 1
fi

rm -rf "$OBJDIFF_DIR/base"
mkdir -p "$OBJDIFF_DIR/base"

echo "[delinker] Delinking base (compiled game) ..."
cargo run --manifest-path "$SCRIPT_DIR/Cargo.toml" --release -- \
  --pdb-path    "$PDB_FILE" \
  --exe-path    "$EXE_FILE" \
  --output-path "$OBJDIFF_DIR/base" \
  --engine-path "$VOSTOK_DIR/sources"

echo "[delinker] Regenerating objdiff config ..."
python3 "$VOSTOK_DIR/scripts/generate_objdiff_config.py"

echo "[delinker] Done. Base obj files at: $OBJDIFF_DIR/base"
