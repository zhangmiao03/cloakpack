# Changelog

## 0.2.0 — 2026-09-07

One product, one vault, two gates: dsh-cloak merged into the cloakpack monorepo.

- **Monorepo**: `@cloakpack/core` (engine), `cloakpack` (CLI), `dsh-cloak` (DSH plugin) — single engine source, no more drift.
- **+13 signatures** (36 total): Anthropic admin, Twilio, SendGrid, Mailgun, Telegram bot, Airtable, Atlassian, DigitalOcean, GitLab scoped tokens, Notion, Figma, Google OAuth refresh, Tencent Cloud.
- **Inline allowlist** `cloakpack:allow` (gitleaks parity) and **config allowlist** (`allow.paths` globs / `allow.values`).
- **Baseline workflow** (detect-secrets parity): `scan --update-baseline` — existing findings are recorded as fingerprints (no plaintext) and stop blocking; new secrets still block.
- **Entropy gate**: Shannon-entropy secondary filter on generic formats (gitleaks parity).
- 71 tests (was 38): engine + real-git E2E + DSH plugin suites all run from the monorepo root.

## 0.1.0 — 2026-09-04

Initial release (CLI only): pre-push guard, pack/unpack, encrypted vault.
