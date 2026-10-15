# Contributing

This project is in an early architecture-first stage. Contributions should preserve the security model rather than maximize feature count.

## Before opening a change

Read `AGENTS.md`, `docs/architecture.md`, and the active phase plan.

## Pull-request expectations

- keep changes inside the active phase unless explicitly proposing a roadmap change;
- include tests, especially negative/security validation tests;
- update focused documentation when serialized semantics change;
- avoid new dependencies without justification;
- do not weaken strict validation or fail-closed semantics for convenience;
- call out compatibility or schema-version implications explicitly.

## Security issues

Do not open a public issue containing exploitable secrets or an unpatched vulnerability. Use GitHub's private vulnerability reporting/security advisory mechanism when available. See `SECURITY.md`.
