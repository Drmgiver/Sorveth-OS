#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if ! command -v cargo >/dev/null 2>&1; then
  echo 'Missing cargo/rustup. Install a stable Rust toolchain first.' >&2; exit 1
fi
if ! command -v qemu-system-x86_64 >/dev/null 2>&1; then
  echo 'Missing qemu-system-x86_64. Install QEMU for your distribution.' >&2; exit 1
fi
CODE="${OVMF_CODE:-}"
VARS="${OVMF_VARS:-}"
if [[ -z "$CODE" ]]; then
  for f in /usr/share/OVMF/OVMF_CODE_4M.fd /usr/share/OVMF/OVMF_CODE.fd /usr/share/edk2/ovmf/OVMF_CODE.fd /usr/share/edk2-ovmf/x64/OVMF_CODE.fd; do
    [[ -f "$f" ]] && CODE="$f" && break
  done
fi
if [[ -z "$VARS" ]]; then
  for f in /usr/share/OVMF/OVMF_VARS_4M.fd /usr/share/OVMF/OVMF_VARS.fd /usr/share/edk2/ovmf/OVMF_VARS.fd /usr/share/edk2-ovmf/x64/OVMF_VARS.fd; do
    [[ -f "$f" ]] && VARS="$f" && break
  done
fi
if [[ ! -f "$CODE" || ! -f "$VARS" ]]; then
  echo 'Could not find OVMF code/vars. Set OVMF_CODE and OVMF_VARS.' >&2; exit 1
fi
cargo build -p sorveth-boot --release --target x86_64-unknown-uefi
mkdir -p esp/EFI/BOOT
cp target/x86_64-unknown-uefi/release/sorveth-boot.efi esp/EFI/BOOT/BOOTX64.EFI
# Never modify the system's original OVMF variable store.
TEMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TEMP_DIR"' EXIT
cp "$VARS" "$TEMP_DIR/OVMF_VARS.fd"
extra=()
if [[ "${1:-}" == '--headless' ]]; then extra=(-display none); fi
qemu-system-x86_64 \
  -machine q35 -m 512M \
  -drive "if=pflash,format=raw,readonly=on,file=$CODE" \
  -drive "if=pflash,format=raw,file=$TEMP_DIR/OVMF_VARS.fd" \
  -drive "if=ide,format=raw,file=fat:rw:$(pwd)/esp" \
  -serial stdio -monitor none -net none \
  "${extra[@]}"
