#!/usr/bin/env bash
# build_qvm.sh — Linux counterpart of build_qvm.ps1.
#
# Requires lcc-based q3lcc and q3asm on PATH (build them from any
# id Tech 3 toolchain source). Usage:
#   ./scripts/build_qvm.sh <SrcDir> [Stem]
set -euo pipefail

if [ $# -lt 1 ]; then
  echo "usage: build_qvm.sh <SrcDir> [Stem]" >&2
  exit 2
fi

src="$1"
stem="${2:-$(basename "$src")}"
cfile="$src/$stem.c"
sys="$src/syscalls.asm"

[ -f "$cfile" ] || { echo "missing $cfile - run emit first" >&2; exit 1; }
[ -f "$sys" ] || { echo "missing $sys" >&2; exit 1; }
command -v q3lcc >/dev/null || { echo "q3lcc not on PATH" >&2; exit 1; }
command -v q3asm >/dev/null || { echo "q3asm not on PATH" >&2; exit 1; }

cd "$src"
echo "q3lcc -DQ3_VM -S $stem.c"
q3lcc -DQ3_VM -S "$stem.c"
echo "q3asm -o $stem"
q3asm -vq3 -m -o "$stem" syscalls.asm "$stem.asm"

echo "OK $(pwd)/$stem.qvm ($(wc -c < "$stem.qvm") bytes)"
