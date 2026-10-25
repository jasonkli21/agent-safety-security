# Documentation Map

- `prd.md` — long-term product requirements and roadmap.
- `architecture.md` — enduring technical architecture and invariants.
- `plans/` — detailed phase implementation plans.
- `prompts/` — handoff prompts for implementation/review sessions.
- `reports/` — implementation and review reports produced after work is completed.
- `decisions/` — architecture decision records when a decision is important enough to preserve separately.

## Keeping docs aligned

The PRD should remain relatively stable. Architecture changes only for enduring technical decisions. Phase plans can be more operational and detailed. Reports describe reality after implementation.

- [Identity and delegation](identity-delegation.md) — Phase 6 authority, verifier, operational trust and replay.
- [Phase 6 implementation report](reports/phase-6-implementation-report.md) — verification and limitations.

- [Adapters and isolation](adapters-isolation.md) — Phase 7 native/provider/framework/HTTP/process boundaries.
- [Phase 7 implementation report](reports/phase-7-implementation-report.md) — verification and review readiness.

- [Supply-chain trust](supply-chain-trust.md) — Phase 8 offline inventory, pins, signatures and runtime admission.
- [Phase 8 implementation report](reports/phase-8-implementation-report.md) — verification and pending independent review.


Phase 9 local multi-agent security: [guide](multi-agent-security.md),
[implementation report](reports/phase-9-implementation-report.md),
[review-fixes report](reports/phase-9-review-fixes-report.md).
Run `.venv/bin/python examples/multi_agent/local_session.py` for the credential-free three-agent
slice. Independent Phase 7–8 acceptance remains open; fresh Phase 9 review is pending.


## Phase 10 team reference slice

- [Managed control-plane boundaries and design](managed-control-plane.md)
- [Phase 10 plan](plans/phase-10-implementation-plan.md)
- [Implementation and verification report](reports/phase-10-implementation-report.md)
- [Two-tenant demo and API/CLI contract](../examples/team/README.md)

The optional loopback-only service supplies governance and minimized, unverified posture. The
first independent review's four findings have fixes; fresh Phase 10 review is pending. Local
Phase 0–9 enforcement remains offline-capable; independent acceptance gates remain open.
