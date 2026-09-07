# dsh-cloak

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![DSH plugin](https://img.shields.io/badge/dsh-plugin-✅-green)](https://github.com/topics/dsh-plugin)
[![Node](https://img.shields.io/badge/node-%5E22.19%20%7C%7C%20%3E%3D24-brightgreen.svg)](#)
[![Release](https://img.shields.io/github/v/tag/zhangmiao03/dsh-cloak?label=release)](https://github.com/zhangmiao03/dsh-cloak/releases)
[![CI](https://img.shields.io/github/actions/workflow/status/zhangmiao03/dsh-cloak/ci.yml?branch=main&label=CI)](https://github.com/zhangmiao03/dsh-cloak/actions/workflows/ci.yml)

**A context firewall for [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness): credentials in tool results are replaced with opaque placeholders before they reach the model. The secret never enters context — the task keeps going.**

[中文文档](README.zh.md)

```
$ cat .env                          ← the agent reads a config file
DEEPSEEK_API_KEY=sk-0123…cdef

→ what the model actually sees:
DEEPSEEK_API_KEY=⟦cloak:deepseek-api-key:1⟧
```

## Why

Your agent reads `.env` files, config dumps, cloud CLI output, and log tails. Every credential in those results flows into the conversation — and from there into **every request sent to your model provider**. Export-time redaction (sharing, handoff) is too late: the secret already left your machine while the agent was working.

`dsh-cloak` guards the boundary where tool results enter model context:

- **Detect** — 24 built-in high-precision signatures (AWS/Aliyun/GCP keys, DeepSeek/OpenAI/Anthropic/OpenRouter keys, GitHub/GitLab/npm tokens, Slack/Discord/飞书/企业微信 webhooks, Stripe/Shopify/Linear, JWTs, PEM private-key blocks, credentialed DB URLs, `Authorization: Bearer …`), plus key-name rules (`password`/`secret`/`api_key`/…) that catch unknown formats in `.env`, JSON, and YAML shapes. Custom regex rules via a JSON file.
- **Replace** — matches become stable placeholders `⟦cloak:<category>:<n>⟧`. The original values live only in a process-memory, agent-scoped vault. They never enter session logs, audit events, or model requests.
- **Inform** — a system-prompt note and a per-result context message tell the model what placeholders mean: don't guess, don't reconstruct, don't re-read the source to recover them; ask the user when a real value is genuinely needed.

Pagination cursors (`next_token`, `page_token`, …) and placeholder values (`${VAR}`, `changeme`, …) are deliberately excluded, so paging and templates keep working.

## Install

```sh
# GitHub channel (latest main):
dsh plugin --profile web add "github:zhangmiao03/dsh-cloak#main"
# GitHub channel (pinned release, recommended for stability):
dsh plugin --profile web add "github:zhangmiao03/dsh-cloak#v0.1.0"
# npm channel (after npm publish):
dsh plugin --profile web add dsh-cloak
# local development:
dsh plugin --profile web add /path/to/dsh-cloak
```

Uninstall: `dsh plugin --profile web remove cloak`.

Verify the mount, then restart dsh:

```sh
dsh --profile web --dump-config | grep -A2 'id: cloak'
```

## Config

Per-row config in the profile `cordis.patch.yml`:

```yaml
- id: cloak
  config:
    enabled: true
    dryRun: false          # audit-only mode: report what would be redacted
    builtins:
      enabled: true
    rulesFile: ~/.dsh/cloak-rules.json
    note: true             # attach the placeholder-semantics note for the model
    audit:
      maxEntries: 200
      logFile:             # optional JSONL audit trail
```

Custom rules file format:

```json
[
  { "id": "internal-prefix", "pattern": "mycorp-[a-z0-9]{32}", "flags": "g" }
]
```

## Surfaces

| Surface | Kind | Notes |
|---|---|---|
| `tools/post-execute` | listener | Redacts successful plain-text tool results (content projection) |
| `systemPrompt` context | injection | Placeholder semantics for the model, before it ever sees one |
| `/cloak` | command | `/cloak` stats · `/cloak scan <text>` dry-scan |
| `/cloak/api/*` | HTTP | `GET stats` · `GET recent` · `POST test {text}` |

## Security properties

- Original values never appear in audit events, logs, or API responses — categories and counts only.
- The vault is agent-scoped and in-memory only; a restart makes old placeholders intentionally unrestorable.
- Fail-open on scanner faults (a broken rule file or a scanner bug never turns a successful tool call into an error). Every fault is audited.
- Zero runtime dependencies — Node builtins and the DSH host packages only.

## Deliberate exclusions (v0.1)

Honest scope, same spirit as the host's own `spill-policy`:

- Successful plain-text results only. Failed tool results and non-text blocks pass through untouched (replacing error text would corrupt error semantics).
- The model cannot *use* a redacted credential: restoring secrets into tool arguments is impossible by platform design (`PreToolDecision` excludes input rewriting). When a task needs a real value, the model is instructed to ask the user. An approval-gated reveal (riding the host's `ask`/authorization seams) is planned.
- User messages are not rewritten; outbound request bodies are not separately scanned (tool results are the dominant leak channel and are covered at the source). Both are candidate follow-ups.
- `dryRun` audits without replacing; it is the recommended first rollout step.

## Compatibility

Built and verified against DeepSeek Harness `0.1.2-rc.1` (developer-preview host; expect to re-pin on breaking host changes). Node `^22.19 || >=24`.

## Development

```sh
npm install --legacy-peer-deps
npm test            # 51 unit tests
npm run build       # links @deepseek-ai/* peers from the global dsh install, then tsc
```

## License

[MIT](LICENSE)
