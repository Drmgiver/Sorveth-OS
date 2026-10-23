#!/usr/bin/env bash
# Dedicated automated boot acceptance test. Uses a test-only QEMU debug-exit
# device and requires a serial marker emitted from the native kernel code.
set -euo pipefail
cd "$(dirname "$0")/.."
for binary in cargo qemu-system-x86_64 timeout; do
  if ! command -v "$binary" >/dev/null 2>&1; then
    echo "Missing prerequisite: $binary" >&2
    exit 1
  fi
done
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
  echo 'OVMF firmware missing: install ovmf or specify OVMF_CODE/OVMF_VARS' >&2
  exit 1
fi

cargo test -p sorveth-abi -p sorveth-cap -p sorveth-memory -p sorveth-frames
cargo build -p sorveth-boot --release --target x86_64-unknown-uefi --features qemu-smoke

TMP="$(mktemp -d)"
# CI can set this to retain the evidence needed to debug a failed boot.
# Logs are copied on success and failure before temporary files are removed.
ARTIFACT_DIR="${SORVETH_QEMU_ARTIFACT_DIR:-}"
if [[ -n "$ARTIFACT_DIR" ]]; then
  mkdir -p "$ARTIFACT_DIR"
fi
save_diagnostics() {
  local result=$?
  if [[ -n "$ARTIFACT_DIR" ]]; then
    for name in serial.log qemu.out qemu.err; do
      if [[ -f "$TMP/$name" ]]; then
        cp "$TMP/$name" "$ARTIFACT_DIR/$name"
      fi
    done
    printf 'smoke-script-exit=%s\n' "$result" > "$ARTIFACT_DIR/result.txt"
  fi
  rm -rf "$TMP"
}
trap save_diagnostics EXIT
mkdir -p "$TMP/esp/EFI/BOOT"
cp target/x86_64-unknown-uefi/release/sorveth-boot.efi "$TMP/esp/EFI/BOOT/BOOTX64.EFI"
cp "$VARS" "$TMP/OVMF_VARS.fd"
set +e
timeout --signal=TERM --kill-after=5s 55s qemu-system-x86_64 \
  -machine q35 -m 512M -no-reboot -display none \
  -drive "if=pflash,format=raw,readonly=on,file=$CODE" \
  -drive "if=pflash,format=raw,file=$TMP/OVMF_VARS.fd" \
  -drive "if=ide,format=raw,file=fat:rw:$TMP/esp" \
  -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
  -serial "file:$TMP/serial.log" -monitor none -net none \
  >"$TMP/qemu.out" 2>"$TMP/qemu.err"
STATUS=$?
set -e
cat "$TMP/serial.log" 2>/dev/null || true
if [[ "$STATUS" -ne 33 ]]; then
  echo "QEMU boot failed: expected debug-exit status 33, observed $STATUS" >&2
  cat "$TMP/qemu.err" >&2 || true
  exit 1
fi
for marker in \
  'Native kernel execution: EFI boot services exited' \
  'Boot protocol v1: OK' \
  'UEFI physical memory map: validated' \
  'Physical frame planner: validated (no mappings written)' \
  'Persistent physical frame ledger: installed (unmapped)' \
  'Capability table: initialized' \
  'SORVETH CORE ONLINE / end of milestone 0'; do
  if ! grep -Fq "$marker" "$TMP/serial.log"; then
    echo "QEMU boot failed: missing serial marker: $marker" >&2
    exit 1
  fi
done
echo 'PASS: kernel executed after ExitBootServices, validated memory map, and exited QEMU cleanly.'
