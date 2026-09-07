# Changelog

## 0.1.0 — 2026-09-04

Initial release.

- `cloakpack init` — installs a git pre-push guard (refuses to overwrite a foreign hook), gitignores `.cloakpack/`, initializes the vault key.
- Pre-push guard (`cloakpack guard --pre-push`) — scans the exact tree of each ref being pushed (respects symlinks/submodules, skips binaries and >2MB files), blocks the push on credential hits with actionable next steps; fail-open with a loud warning if the CLI is missing or the tree can't be read.
- `cloakpack scan` — scan tracked files, exit 1 on hits.
- `cloakpack pack [--dry-run]` — moves secrets into a local AES-256-GCM encrypted vault (key in `~/.cloakpack/keys/`, 0600), replaces in-file values with stable placeholders, stages the result; history check warns (without failing) when a secret also lives in past commits.
- `cloakpack unpack` — restores originals from the vault.
- Detection engine shared with dsh-cloak: 24 signature families + sensitive-key-name rules + custom regex rules; own placeholders are exempt (pack is idempotent).
- 38 tests, including a real-git E2E: blocked push → pack → clean push → unpack restore, plus the `--no-verify` escape hatch. Zero runtime dependencies.
