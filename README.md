# cloakpack

**Safety-pack your secrets before they leave the machine.** A git pre-push guard that blocks credential leaks, plus one-command `pack` (vault + placeholders) / `unpack` — built for hackathon deadlines, when the secrets are already in the project and the demo is tomorrow.

[中文文档](README.zh.md)

```
$ git push
[cloakpack] ✋ Push blocked: credentials found in the tree that is about to leave this machine.
  .env:2  deepseek-api-key（signature）
  config/app.yaml:2  sensitive-value（key-assignment）

$ cloakpack pack          # secrets → local encrypted vault, files → placeholders
$ git commit -m "cloak: pack secrets" && git push   # ✅ passes, remote stays clean

$ cloakpack unpack        # restore on your own machine anytime
```

## Why

gitleaks and friends **warn** — and at 3 a.m. before the deadline, people `--no-verify` past the warning. sops and git-crypt assume you adopted them on day one; hackathon reality is a messy repo full of secrets **today**. cloakpack closes that gap: when a leak is about to happen, the fix is one command, and the fix is **easier than the bypass**.

- **Block, don't warn** — the pre-push hook scans the exact tree that is about to be pushed and refuses to let credentials out (the explicit escape hatch is `git push --no-verify`, by design).
- **Pack, don't panic** — `cloakpack pack` moves every detected secret into a local AES-256-GCM encrypted vault (`.cloakpack/vault.bin`, key never leaves `~/.cloakpack/keys/`), replaces the in-file values with stable placeholders like `⟦cloak:deepseek-api-key:1⟧`, and stages the result. Push again and the remote is clean.
- **Reversible on your machine** — `cloakpack unpack` restores the originals, so your demo keeps running locally.
- **Honest about history** — if a secret already exists in past commits, cloakpack tells you the truth: *packing cannot save it; rotate the key.*

## Detection

Same engine as [dsh-cloak](https://github.com/zhangmiao03/dsh-cloak): 24 high-precision signature families (AWS / Aliyun / GCP, DeepSeek / OpenAI / Anthropic / OpenRouter, GitHub / GitLab / npm, Slack / Discord / Feishu / WeCom webhooks, Stripe / Shopify / Linear, JWT, PEM private keys, credentialed DB URLs, `Authorization: Bearer`), sensitive-key-name rules for `.env` / JSON / YAML shapes, and your own regex rules in `.cloakpack/rules.json`. Pagination cursors (`next_token`…) and placeholder values (`${VAR}`, `changeme`…) are deliberately excluded.

## Install

```sh
npm i -g cloakpack
cd your-project
cloakpack init      # installs the pre-push guard, gitignores the vault
```

Zero runtime dependencies. Node ≥ 22. macOS / Linux / Windows(git-bash).

## Commands

| Command | What it does |
|---|---|
| `cloakpack init` | Install the pre-push guard (refuses to overwrite a foreign hook), gitignore `.cloakpack/`, initialize the key |
| `cloakpack scan` | Scan tracked files; exit code 1 on hits |
| `cloakpack pack [--dry-run]` | Vault + placeholders + `git add`; warns (does not fail) if secrets also live in history |
| `cloakpack unpack` | Restore originals from the vault |
| `cloakpack unhook` | Remove the guard |

Custom rules (`.cloakpack/rules.json`):

```json
[
  { "id": "internal-prefix", "pattern": "mycorp-[a-z0-9]{32}", "flags": "g" }
]
```

## Threat model — read this

- Protects against: the project directory leaving your machine (sharing, zip-and-send, USB loss, judges cloning your repo, public demos).
- Does **not** protect against: malware running as the same user on the same machine (it can read the keyfile, same class as password managers' local mode).
- The vault and key are **never committed**: `.cloakpack/` is gitignored by `init`; losing `~/.cloakpack/keys/` means the pack is unrecoverable by design.
- A secret that has already reached a remote must be **rotated** — packing only cleans the current tree.

## Development

```sh
npm install
npm test          # 38 tests incl. a real-git E2E: blocked push → pack → clean push → unpack
npm run build
```

## License

[MIT](LICENSE)
