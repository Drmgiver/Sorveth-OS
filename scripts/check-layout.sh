#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
out="$(mktemp)"
trap 'rm -f "$out"' EXIT
cc -std=c11 -Wall -Wextra -Werror tests/uefi_layout.c -o "$out"
"$out"
