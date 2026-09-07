# cloakpack

**One product, one vault, two gates.** 密钥安全包：一个本地加密保险库，守两道门——出机门（git push 阻断）与入模门（DeepSeek Harness 上下文防火墙）。共享同一套检测引擎。

[中文说明](#中文) · Monorepo: `packages/core`(引擎) · `packages/cli`(cloakpack CLI) · `packages/dsh-cloak`(DSH 插件)

## Gates

| Gate | Package | Install | What it blocks |
|---|---|---|---|
| 出机门 | `cloakpack` (CLI) | `npm i -g cloakpack` → `cloakpack init` | `git push` with credentials in the pushed tree — **blocks, then one-command `pack`** (vault + placeholders) fixes it; `unpack` restores locally |
| 入模门 | `dsh-cloak` (DSH plugin) | `dsh plugin --profile web add dsh-cloak` | credentials in tool results **before they enter model context** (placeholders + system-prompt guidance) |

Both share: 36 high-precision signature families (incl. 飞书/企微/腾讯云 for the CN ecosystem), sensitive-key-name rules, custom regex, `⟦cloak:category:n⟧` stable placeholders, AES-256-GCM local vault (`~/.cloakpack/keys/`, 0600).

## Engine (best practices from the field)

- **Inline allowlist** — a `cloakpack:allow` comment suppresses that line (gitleaks parity)
- **Config allowlist** — `.cloakpack/rules.json` → `allow.paths` (globs) / `allow.values`
- **Baseline** — `cloakpack scan --update-baseline`: 存量入册不拦、新密钥必拦 (detect-secrets parity); fingerprints only, no plaintext
- **Entropy gate** — Shannon-entropy secondary filter on generic formats (gitleaks parity)
- Honest limits: secrets already pushed must be **rotated**; packing can't save history

## Threat model

Protects the project directory leaving your machine (sharing, judges, USB, demos). Does not protect against same-user malware on the same machine. Vault + key never committed.

## Development

```sh
npm install --legacy-peer-deps && npm run build && npm test   # 71 tests incl. real-git E2E
```

License: MIT. Roadmap: opt-in live verification (truffleHog-style), base64/URL decoders, `scan --history` full-blob sweep, DSH approval-gated reveal sharing this vault.

## 中文

一个产品、一个保险库、两道门：`cloakpack`（CLI，npm 包）在 `git push` 时阻断密钥出机，`dsh-cloak`（DSH 插件）在密钥进入模型上下文前打码；引擎同源（36 签名族+键名规则+自定义正则），占位符与保险库格式互通。行内 `cloakpack:allow` 豁免、配置豁免、基线（存量不拦新增拦）、熵过滤均已内置；已出过门的密钥必须轮换——工具会直说。
