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

cargo test -p sorveth-abi -p sorveth-cap -p sorveth-memory -p sorveth-frames -p sorveth-paging -p sorveth-ipc -p sorveth-task -p sorveth-exchange -p sorveth-broker
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
    for name in serial.log qemu.out qemu.err fault-serial.log fault-qemu.out fault-qemu.err user-serial.log user-qemu.out user-qemu.err isolation-a-serial.log isolation-a-qemu.out isolation-a-qemu.err isolation-b-serial.log isolation-b-qemu.out isolation-b-qemu.err transfer-a-serial.log transfer-a-qemu.out transfer-a-qemu.err transfer-b-serial.log transfer-b-qemu.out transfer-b-qemu.err; do
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
  'Inherited x86 paging: validated (read-only)' \
  'UEFI physical memory map: validated' \
  'Physical frame planner: validated (no mappings written)' \
  'Persistent physical frame ledger: installed (unmapped)' \
  'Sorveth PML4 root: active (firmware lower levels shared)' \
  'Sorveth private supervisor NX mapping: verified' \
  'Sorveth IDT: installed; breakpoint roundtrip verified' \
  'Sorveth emergency fault stacks: TSS loaded; IST1/IST2 armed' \
  'Sorveth dynamic private pages: 2 additional mappings verified' \
  'Sorveth dedicated kernel stack: active' \
  'Sorveth native context switch: two worker roundtrips verified' \
  'Sorveth scheduled kernel contexts: A B A B verified' \
  'Sorveth process roots: two distinct supervisor PML4 roots verified' \
  'Sorveth private process pages: distinct user RW/NX mappings verified' \
  'Sorveth scheduler CR3: A B A B private address spaces verified' \
  'SORVETH M2-I HARDENING: blocked, stale and damaged mappings denied' \
  'SORVETH M2-J.1: bounded user address ranges validated' \
  'SORVETH M2-J.2: process-owned read/write page walks verified' \
  'SORVETH M2-J.3: bounded copy-in and denied buffers verified' \
  'SORVETH M2-J.4: bounded writable copy-out and denial verified' \
  'Capability table: initialized' \
  'Sorveth IPC: capability-checked mailbox and revocation validated' \
  'Sorveth task registry: fair selection and stale IDs validated' \
  'Sorveth exchange: authorized send wakes a parked task' \
  'SORVETH CORE ONLINE / end of milestone 0'; do
  if ! grep -Fq "$marker" "$TMP/serial.log"; then
    echo "QEMU boot failed: missing serial marker: $marker" >&2
    exit 1
  fi
done
echo 'PASS: kernel executed after ExitBootServices, validated memory map, and exited QEMU cleanly.'

# M1-C acceptance: use a separate EFI image to deliberately fault on the
# absent second page of Sorveth's own high-half mapping. The serial fault
# handler must report the #PF and issue QEMU's debug exit (status 33).
# Normal kernel and production builds never trigger this test.
cargo build -p sorveth-boot --release --target x86_64-unknown-uefi --features qemu-fault
cp target/x86_64-unknown-uefi/release/sorveth-boot.efi "$TMP/esp/EFI/BOOT/BOOTX64.EFI"
cp "$VARS" "$TMP/OVMF_VARS.fd"
set +e
timeout --signal=TERM --kill-after=5s 55s qemu-system-x86_64 \
  -machine q35 -m 512M -no-reboot -display none \
  -drive "if=pflash,format=raw,readonly=on,file=$CODE" \
  -drive "if=pflash,format=raw,file=$TMP/OVMF_VARS.fd" \
  -drive "if=ide,format=raw,file=fat:rw:$TMP/esp" \
  -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
  -serial "file:$TMP/fault-serial.log" -monitor none -net none \
  >"$TMP/fault-qemu.out" 2>"$TMP/fault-qemu.err"
FAULT_STATUS=$?
set -e
cat "$TMP/fault-serial.log" 2>/dev/null || true
if [[ "$FAULT_STATUS" -ne 33 ]]; then
  echo "QEMU fault test failed: expected debug-exit status 33, observed $FAULT_STATUS" >&2
  cat "$TMP/fault-qemu.err" >&2 || true
  exit 1
fi
for marker in \
  'Sorveth IDT: installed; breakpoint roundtrip verified' \
  'Sorveth dynamic private pages: 2 additional mappings verified' \
  'Sorveth IPC: capability-checked mailbox and revocation validated' \
  'Sorveth task registry: fair selection and stale IDs validated' \
  'Sorveth exchange: authorized send wakes a parked task' \
  'Sorveth dedicated kernel stack: active' \
  'Sorveth native context switch: two worker roundtrips verified' \
  'Sorveth scheduled kernel contexts: A B A B verified' \
  'Sorveth process roots: two distinct supervisor PML4 roots verified' \
  'Sorveth private process pages: distinct user RW/NX mappings verified' \
  'Sorveth scheduler CR3: A B A B private address spaces verified' \
  'SORVETH M2-I HARDENING: blocked, stale and damaged mappings denied' \
  'SORVETH M2-J.1: bounded user address ranges validated' \
  'SORVETH M2-J.2: process-owned read/write page walks verified' \
  'SORVETH M2-J.3: bounded copy-in and denied buffers verified' \
  'SORVETH M2-J.4: bounded writable copy-out and denial verified' \
  'SORVETH EXCEPTION: PAGE FAULT' \
  'Sorveth page fault IST1: active' \
  'Fault address (CR2): 0x' \
  'Page fault error code: 0x' \
  'SORVETH CONTROLLED PAGE FAULT: verified'; do
  if ! grep -Fq "$marker" "$TMP/fault-serial.log"; then
    echo "QEMU fault test failed: missing marker: $marker" >&2
    exit 1
  fi
done
echo 'PASS: private unmapped page generated an x86 #PF and Sorveth logged and handled it.'



# M2-F QEMU-only ring-3 test: a tiny unprivileged code page invokes INT80.
# The first call returns a known value to ring 3; the second proves IRETQ
# returned to user instructions and the interrupt gate crossed back to ring 0.
cargo build -p sorveth-boot --release --target x86_64-unknown-uefi --features qemu-user
cp target/x86_64-unknown-uefi/release/sorveth-boot.efi "$TMP/esp/EFI/BOOT/BOOTX64.EFI"
cp "$VARS" "$TMP/OVMF_VARS.fd"
set +e
timeout --signal=TERM --kill-after=5s 55s qemu-system-x86_64 \
  -machine q35 -m 512M -no-reboot -display none \
  -drive "if=pflash,format=raw,readonly=on,file=$CODE" \
  -drive "if=pflash,format=raw,file=$TMP/OVMF_VARS.fd" \
  -drive "if=ide,format=raw,file=fat:rw:$TMP/esp" \
  -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
  -serial "file:$TMP/user-serial.log" -monitor none -net none \
  >"$TMP/user-qemu.out" 2>"$TMP/user-qemu.err"
USER_STATUS=$?
set -e
cat "$TMP/user-serial.log" 2>/dev/null || true
if [[ "$USER_STATUS" -ne 33 ]]; then
  echo "QEMU ring-3 test failed: expected status 33, observed $USER_STATUS" >&2
  cat "$TMP/user-qemu.err" >&2 || true
  exit 1
fi
for marker in \
  'Sorveth scheduled kernel contexts: A B A B verified' \
  'Sorveth process roots: two distinct supervisor PML4 roots verified' \
  'Sorveth private process pages: distinct user RW/NX mappings verified' \
  'Sorveth scheduler CR3: A B A B private address spaces verified' \
  'SORVETH M2-I HARDENING: blocked, stale and damaged mappings denied' \
  'SORVETH M2-J.1: bounded user address ranges validated' \
  'SORVETH M2-J.2: process-owned read/write page walks verified' \
  'SORVETH M2-J.3: bounded copy-in and denied buffers verified' \
  'SORVETH M2-J.4: bounded writable copy-out and denial verified' \
  'Sorveth ring-3 probe: user mappings and trap ready' \
  'Sorveth ring-3 syscall: entered kernel from user mode' \
  'SORVETH RING3 ROUNDTRIP: verified' \
  'SORVETH EXCEPTION: PAGE FAULT' \
  'SORVETH TASK-SCOPED SYSCALL: capability checks verified' \
  'Sorveth page fault IST1: active' \
  'SORVETH USER KERNEL-MEMORY DENIAL: verified'; do
  if ! grep -Fq "$marker" "$TMP/user-serial.log"; then
    echo "QEMU ring-3 test failed: missing marker: $marker" >&2
    exit 1
  fi
done
echo 'PASS: ring-3 task-scoped capability syscalls denied forged/foreign/write handles before supervisor-memory fault.'


# M2-I.4: each QEMU image must prove it can read its own private USER
# page from ring 3 but cannot read the other process's private page.
# Only the matching hardware #PF permits the kernel to exit with status 33.
for side in a b; do
  cargo build -p sorveth-boot --release --target x86_64-unknown-uefi \
    --features "qemu-isolate-$side"
  cp target/x86_64-unknown-uefi/release/sorveth-boot.efi "$TMP/esp/EFI/BOOT/BOOTX64.EFI"
  cp "$VARS" "$TMP/OVMF_VARS.fd"
  set +e
  timeout --signal=TERM --kill-after=5s 55s qemu-system-x86_64 \
    -machine q35 -m 512M -no-reboot -display none \
    -drive "if=pflash,format=raw,readonly=on,file=$CODE" \
    -drive "if=pflash,format=raw,file=$TMP/OVMF_VARS.fd" \
    -drive "if=ide,format=raw,file=fat:rw:$TMP/esp" \
    -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
    -serial "file:$TMP/isolation-$side-serial.log" -monitor none -net none \
    >"$TMP/isolation-$side-qemu.out" 2>"$TMP/isolation-$side-qemu.err"
  ISOLATION_STATUS=$?
  set -e
  cat "$TMP/isolation-$side-serial.log" 2>/dev/null || true
  if [[ "$ISOLATION_STATUS" -ne 33 ]]; then
    echo "QEMU process $side isolation failed: expected exit 33, got $ISOLATION_STATUS" >&2
    cat "$TMP/isolation-$side-qemu.err" >&2 || true
    exit 1
  fi
  if [[ "$side" == a ]]; then
    isolation_marker='SORVETH PROCESS A -> B USER ACCESS DENIED: verified'
  else
    isolation_marker='SORVETH PROCESS B -> A USER ACCESS DENIED: verified'
  fi
  for marker in \
    'Sorveth scheduler CR3: A B A B private address spaces verified' \
    'SORVETH M2-I HARDENING: blocked, stale and damaged mappings denied' \
    'SORVETH M2-J.1: bounded user address ranges validated' \
    'SORVETH M2-J.2: process-owned read/write page walks verified' \
    'SORVETH M2-J.3: bounded copy-in and denied buffers verified' \
    'SORVETH M2-J.4: bounded writable copy-out and denial verified' \
    'Sorveth ring-3 isolation: process-owned CR3 armed' \
    'SORVETH ISOLATION: own process memory read in ring 3' \
    'SORVETH EXCEPTION: PAGE FAULT' \
    'Sorveth page fault IST1: active' \
    'Page fault error code: 0x0000000000000004' \
    "$isolation_marker"; do
    if ! grep -Fq "$marker" "$TMP/isolation-$side-serial.log"; then
      echo "QEMU process $side isolation failed: missing marker: $marker" >&2
      exit 1
    fi
  done
  echo "PASS: process $side read its own page and CPU denied cross-process ring-3 read."
done


# M2-J.5: ring-3 under each process CR3 with capability-checked INT80.
for side in a b; do
  cargo build -p sorveth-boot --release --target x86_64-unknown-uefi \
    --features "qemu-transfer-$side"
  cp target/x86_64-unknown-uefi/release/sorveth-boot.efi "$TMP/esp/EFI/BOOT/BOOTX64.EFI"
  cp "$VARS" "$TMP/OVMF_VARS.fd"
  set +e
  timeout --signal=TERM --kill-after=5s 55s qemu-system-x86_64 \
    -machine q35 -m 512M -no-reboot -display none \
    -drive "if=pflash,format=raw,readonly=on,file=$CODE" \
    -drive "if=pflash,format=raw,file=$TMP/OVMF_VARS.fd" \
    -drive "if=ide,format=raw,file=fat:rw:$TMP/esp" \
    -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
    -serial "file:$TMP/transfer-$side-serial.log" -monitor none -net none \
    >"$TMP/transfer-$side-qemu.out" 2>"$TMP/transfer-$side-qemu.err"
  TRANSFER_STATUS=$?
  set -e
  cat "$TMP/transfer-$side-serial.log" 2>/dev/null || true
  if [[ "$TRANSFER_STATUS" -ne 33 ]]; then
    echo "QEMU process $side syscall test failed: expected exit 33, got $TRANSFER_STATUS" >&2
    cat "$TMP/transfer-$side-qemu.err" >&2 || true
    exit 1
  fi
  for marker in \
    'SORVETH M2-J.3: bounded copy-in and denied buffers verified' \
    'SORVETH M2-J.4: bounded writable copy-out and denial verified' \
    'Sorveth ring-3 memory gateway: process CR3 armed' \
    'Sorveth ring-3 probe: user mappings and trap ready' \
    'SORVETH M2-J.5: ring-3 memory syscalls authorized and denied'; do
    if ! grep -Fq "$marker" "$TMP/transfer-$side-serial.log"; then
      echo "QEMU process $side syscall test failed: missing marker: $marker" >&2
      exit 1
    fi
  done
  echo "PASS: process $side issued capability-checked CPL3 copy syscalls and denied forged/foreign buffers."
done
