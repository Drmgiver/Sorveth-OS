# Security invariants and threat model (draft)

## Trusted computing base

Sorveth Core must eventually own process address spaces and mediate all privileged
operations. User processes and generated code must be unable to map arbitrary
physical memory or call privileged CPU instructions. Kernel code should remain
small enough to audit. No peripheral driver, GUI service or AI agent gets implicit
access to every process or the entire user's Vault.

## Capability model

- Root grants are a kernel-only operation.
- Untrusted code holds opaque handles, not hardware addresses or unrestricted IDs.
- An operation checks the relevant rights and object before it executes.
- Derivation requires the DERIVE right and can never add rights.
- Revocation invalidates the targeted capability and every descendant.
- Stale handles cannot be reused as valid authority after a slot is released.
- Transferring a handle across address spaces will require explicit IPC mediation.

The fixed-capacity `sorveth-cap` implementation currently handles derivation,
attenuation and transitive revocation **within a single trusted table only**.
It is not concurrency-safe; it does not yet implement cross-process transfer or
object lifetime management, and 32-bit generations could theoretically wrap
under extreme repeated reuse. Nothing executes in untrusted user mode today.

## AI and generated software

Sorveth Mind is always opt-in and interchangeable. The OS works with no model
installed. A generated application has no special authority; it is reviewed,
compiled and exercised in an isolated environment before being authorized to
read or change real user data. Sensitive operations require user approval and
are mediated by a broker. Cloud-model access, if enabled, is separately granted
and visibly scoped. Source, resource bundles and data remain exportable and
user-owned. No hidden backdoors or blanket administrator access are acceptable.

## Supply chain and persistence

Source and resource changes must be inspectable. Package signatures establish
publisher provenance, never that code is safe; sandboxing remains mandatory.
Persistent settings and resources use documented portable formats. A future OS
resource editor will manipulate non-executable resources consistently across the
system and compliant apps. Editing is an ownership feature, not a reason to
silently add privileged abilities.

## Threat model gaps / explicit nonclaims

No secure boot chain, driver sandboxing, process isolation, verified memory safety
of all hardware interfaces, privilege separation, update integrity, disk
cryptography or IPC enforcement has yet been implemented. The UEFI bootstrap
handles raw pointers in `unsafe` code and needs dynamic testing. This is a
prototype; it is not safe for production workloads or confidential data.
