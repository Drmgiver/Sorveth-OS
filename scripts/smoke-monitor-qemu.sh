#!/usr/bin/env bash
# End-to-end integration test: real UEFI boot -> kernel -> serial CLI commands.
set -euo pipefail
cd "$(dirname "$0")/.."

for program in cargo qemu-system-x86_64 python3 timeout; do
  command -v "$program" >/dev/null 2>&1 || {
    echo "Missing prerequisite: $program" >&2
    exit 1
  }
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
  echo 'OVMF firmware unavailable' >&2
  exit 1
fi

# This intentionally builds the NORMAL kernel, not the debug-exit test binary.
cargo build -p sorveth-boot --release --target x86_64-unknown-uefi
TMP="$(mktemp -d)"
QEMU_PID=""
ARTIFACT_DIR="${SORVETH_QEMU_ARTIFACT_DIR:-}"
cleanup() {
  result=$?
  trap - EXIT
  if [[ -n "$QEMU_PID" ]]; then
    kill "$QEMU_PID" 2>/dev/null || true
    wait "$QEMU_PID" 2>/dev/null || true
  fi
  if [[ -n "$ARTIFACT_DIR" ]]; then
    mkdir -p "$ARTIFACT_DIR"
    for name in monitor-serial.log monitor-qemu.out monitor-qemu.err; do
      [[ ! -f "$TMP/$name" ]] || cp "$TMP/$name" "$ARTIFACT_DIR/$name"
    done
    printf 'monitor-test-exit=%s\n' "$result" > "$ARTIFACT_DIR/monitor-result.txt"
  fi
  rm -rf "$TMP"
  exit "$result"
}
trap cleanup EXIT

mkdir -p "$TMP/esp/EFI/BOOT"
cp target/x86_64-unknown-uefi/release/sorveth-boot.efi "$TMP/esp/EFI/BOOT/BOOTX64.EFI"
cp "$VARS" "$TMP/OVMF_VARS.fd"

timeout --signal=TERM --kill-after=5s 60s qemu-system-x86_64 \
  -machine q35 -m 512M -no-reboot -display none \
  -drive "if=pflash,format=raw,readonly=on,file=$CODE" \
  -drive "if=pflash,format=raw,file=$TMP/OVMF_VARS.fd" \
  -drive "if=ide,format=raw,file=fat:rw:$TMP/esp" \
  -chardev "socket,id=serial0,path=$TMP/serial.sock,server=on,wait=off" \
  -serial chardev:serial0 -monitor none -net none \
  >"$TMP/monitor-qemu.out" 2>"$TMP/monitor-qemu.err" &
QEMU_PID=$!

python3 scripts/test-monitor.py "$TMP/serial.sock" "$TMP/monitor-serial.log"
