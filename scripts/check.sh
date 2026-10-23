#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
./scripts/check-layout.sh
cargo test -p sorveth-abi -p sorveth-cap -p sorveth-memory -p sorveth-frames -p sorveth-paging
cargo build -p sorveth-boot --release --target x86_64-unknown-uefi
echo 'Rust host tests and UEFI cross-build passed. QEMU boot must be tested separately.'
