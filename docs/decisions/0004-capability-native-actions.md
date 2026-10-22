# ADR 0004 — One native action model for humans and AI

**Status:** Accepted as design, not implemented, 2026-10-22.

**Context:** Blind UI scripting is fragile, and granting an AI the same privileges
as the desktop owner is unacceptable. Native applications also need composable
operations that remain available with AI disabled.

**Decision:** Define typed actions as a normal native application primitive.
Applications provide schemas, requested capabilities, side-effect categories and
portable presentation resources. Humans invoke actions through UI; Script and
Mind invoke the same actions through a broker, with identical authorization rules.
The broker does not trust natural-language claims about authorization.

**Consequences:** Shell integration is not a universal AI escape hatch. External
services and generated code have no ambient filesystem, network or process
control rights. Action protocol versions and effect receipts will be designed
before any system-wide AI executor is released. The first implementation can be
small and synchronous but must preserve this security separation.
