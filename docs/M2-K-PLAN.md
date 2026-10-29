# M2-K — Managed kernel memory and process lifetime

This is the implementation plan after the **CI-verified M2-J.6** controlled
ring-3 memory-copy proof. Milestones are only complete when both host tests
and all QEMU security/monitor gates pass on the accepted commit.

## K.1: Replace firmware-provided physical-memory access

- K.1a: implement a kernel-owned high-half *temporary frame window* used by
  two early scratch-page claims; preserve existing boot tests.
- K.1b: migrate bounded process-frame reads/writes and owned paging-table
  access to explicit trusted high-half mappings, without relying on direct
  physical pointer dereferences.
- K.1c: build and validate Sorveth-owned supervisor mapping ancestry for
  active kernel execution, rejecting accidental user exposure and unsafe
  physical aliases. Audit critical code, stacks, kernel data and framebuffer
  requirements before discontinuing inherited firmware mappings.
- K.1d: remove inherited mappings in a dedicated QEMU verification mode;
  check working monitor, exceptions, independent process roots, copy tests
  and all existing ring-3 negative cases before enabling broadly.

## K.2: Physical frame allocation and reclamation

Add explicit reference/owner records, zero-on-reuse, quarantine for active
CPU mappings, transactional allocation and no premature reclamation.
Validation includes exhaustion, double release, stale generation, and frame
alias/reuse tests. Never release runtime/loader or active paging frames.

## K.3: Process address-space lifecycle

Implement creation, owned mapping installation, guarded stacks and teardown,
with rollback on partial failure. Reject stale identities and foreign roots.
No process may retain a mapping to a reclaimed frame.

## K.4: Generalized bounded copy-in/copy-out

Replace the current fixed eight-byte ring-3 test-only transfer with a
documented bounded buffer ABI, stable mapping lifetimes, full preflight of
all pages and recoverable faults. Preserve capability/task authorization.

## K.5: Full security/regression acceptance

Run deterministic QEMU negative and forced-failure tests in both A/B process
directions, plus normal boot, deliberate faults, ring-3 protection, IPC,
monitor interaction and host tests. Refuse to claim SMP, physical hardware,
or an arbitrary-user-program ABI without separate acceptance evidence.

## Current implementation status

**K.1a candidate:** the final PT slot of the Sorveth-owned private high-half
subtree is reserved for a temporary RW/NX physical frame alias. The scoped
guard requires kernel CR3 and interrupts disabled, rejects invalid and
nested use, invalidates the TLB before access, then unmaps on return.
Two early scratch claims no longer dereference their physical frame
addresses through firmware's identity map.

**Still pending:** K.1b–d, all of K.2–K.5, production process scheduling,
page reclamation, and safe arbitrary user mappings. The root's initial
PML4 setup, existing page-table pointers and other kernel accesses still
rely on inherited OVMF identity mappings. This is not an independent
kernel memory subsystem yet.


### K.1b intermediate checkpoint: user-copy frame access

The M2-J.3/J.4 kernel copy helpers now map the specific process-owned data
frame through the scoped high-half window for both directions, rather than
casting the PTE-resolved physical data address into a kernel pointer.
Existing full-range page-walk/ownership preflight remains before any writes;
only the current one-frame permanent process pages are supported. QEMU must
check the new marker in every ordinary boot and the existing A/B ring-3
memory-syscall and denial runs. This does **not** yet migrate page-table
walking, process creation or test setup off inherited firmware mappings.
