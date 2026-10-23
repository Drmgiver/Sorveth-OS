#!/usr/bin/env python3
"""Drive Sorveth's UART monitor over QEMU's Unix-domain serial socket."""
import socket
import sys
import time

SOCKET_PATH, TRANSCRIPT_PATH = sys.argv[1:]
PROMPT = b"sorveth> "
deadline = time.monotonic() + 45.0
connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
connection.settimeout(0.5)

while True:
    try:
        connection.connect(SOCKET_PATH)
        break
    except (FileNotFoundError, ConnectionRefusedError):
        if time.monotonic() >= deadline:
            raise TimeoutError("QEMU serial socket did not appear")
        time.sleep(0.1)

transcript = bytearray()
with connection, open(TRANSCRIPT_PATH, "wb") as evidence:
    def expect_prompt(required=b""):
        response = bytearray()
        while PROMPT not in response:
            if time.monotonic() >= deadline:
                raise TimeoutError(
                    "Timed out waiting for monitor response: "
                    + repr(required)
                    + "\n"
                    + response[-4000:].decode("latin-1", errors="replace")
                )
            try:
                data = connection.recv(4096)
            except socket.timeout:
                continue
            if not data:
                raise RuntimeError("QEMU closed serial input unexpectedly")
            response.extend(data)
            transcript.extend(data)
            evidence.write(data)
            evidence.flush()
        if required not in response:
            raise AssertionError(
                "Missing response " + repr(required) + " in " + repr(response[-4000:])
            )

    expect_prompt(b"Sorveth bootstrap monitor v0.1")
    if b"Inherited x86 paging: validated (read-only)" not in transcript:
        raise AssertionError("Inherited paging audit did not pass")
    if b"Persistent physical frame ledger: installed (unmapped)" not in transcript:
        raise AssertionError("Persistent physical frame ledger did not initialize")
    if b"Sorveth PML4 root: active (firmware lower levels shared)" not in transcript:
        raise AssertionError("Kernel did not continue after switching its PML4 root")
    if b"Sorveth private supervisor NX mapping: verified" not in transcript:
        raise AssertionError("Private high-half mapping was not verified")
    if b"Sorveth IDT: installed; breakpoint roundtrip verified" not in transcript:
        raise AssertionError("Breakpoint handler did not return correctly")
    if b"Sorveth emergency fault stacks: TSS loaded; IST1/IST2 armed" not in transcript:
        raise AssertionError("TSS/IST emergency fault stacks did not initialize")
    if b"Sorveth dynamic private pages: 2 additional mappings verified" not in transcript:
        raise AssertionError("Dynamic supervisor page mapper did not complete")
    if b"Sorveth dedicated kernel stack: active" not in transcript:
        raise AssertionError("Kernel did not transfer to its own stack")
    if b"Sorveth IPC: capability-checked mailbox and revocation validated" not in transcript:
        raise AssertionError("Kernel IPC capability and mailbox test did not complete")
    tests = [
        (b"help\r", b"Commands: help status memory paging caps halt"),
        (b"statuz\x08s\r", b"Kernel: bootstrap monitor; no userspace or scheduler"),
        (b"memory\r", b"Claims remain unmapped; lower page tables are inherited"),
        (b"paging\r", b"Sorveth private mapped pages: 3"),
        (b"caps\r", b"Capability table: initialized; no isolated tasks yet"),
        (b"not-a-command\r", b"Unknown command; enter help"),
    ]
    for request, response in tests:
        connection.sendall(request)
        expect_prompt(response)

print("PASS: Sorveth serial monitor accepted commands and produced verified replies.")
