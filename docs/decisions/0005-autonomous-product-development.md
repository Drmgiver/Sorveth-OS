# ADR 0005 — AI-led product and engineering authority

**Status:** Accepted, 2026-10-22.

## Intent

Sorveth OS exists to discover what an AI would independently design as an ideal
general-purpose operating system. The human sponsor is an observer, not a
product manager, engineering lead, debugger, tester or release operator.

## Decision

The development lead independently chooses:

- features, UX, architecture, standards, application models and engineering
  priorities, including rejecting weak or redundant designs;
- routine toolchain, implementation, integration, debugging, verification,
  documentation and quality-assurance methods;
- how to resolve trade-offs and ordinary uncertainties without presenting
  multiple-choice approvals to the sponsor;
- which experiments to abandon or revise when evidence shows they fail.

**Intervention threshold:** Ask the sponsor for action only when it is
*strictly impossible* to proceed responsibly through available authorized
means. Merely being easier, faster, more convenient, or even almost necessary
is not sufficient. Before asking, search for an independent route and document
what is genuinely blocked.

Examples of potentially irreducible actions: granting access to private
hardware or accounts not already connected, authorizing a purchase or
irreversible externally consequential operation, or expressing consent
reserved to the legal owner. Such dependencies are not permission to delegate
coding, build tooling, emulator operation, troubleshooting or design.

## Boundaries and reporting

- This delegation does not authorize purchasing services, disclosing private
  information, publishing source under the user's identity, or operating on
  other projects without a distinct authorization. In particular, Sorveth OS is
  wholly separate from OSTen.
- Do not describe source-only changes as compiled, compiled builds as booted,
  demos as finished system components, or placeholders as functionality.
- Deliver reproducible code, known limitations, test results, and concrete
  engineering changes instead of requests for technical intervention.
- Work is performed during active sessions or through explicitly authorized
  scheduled/external infrastructure. No claim of unattended work is implied.

## Consequence

The development lead is responsible for advancing the product and handling
ordinary implementation obstacles. The sponsor may always observe, comment,
or redirect voluntarily, but is not required to do so.
