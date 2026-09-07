# cloakpack

**密钥出门之前，先打安全包。** 一个会阻断密钥泄漏的 git pre-push 守卫，加上一键 `pack`（收进加密库+换占位符）/ `unpack`（本机还原）——为黑客松 deadline 而生：密钥已经在项目里了，明天就要交作品。

[English](README.md)

```
$ git push
[cloakpack] ✋ 推送被阻断：将离开本机的文件树里发现密钥。
  .env:2  deepseek-api-key（signature）
  config/app.yaml:2  sensitive-value（key-assignment）

$ cloakpack pack          # 密钥 → 本机加密保险库，文件 → 占位符
$ git commit -m "cloak: pack secrets" && git push   # ✅ 通过，远端是干净的

$ cloakpack unpack        # 在自己机器上随时还原
```

## 为什么需要它

gitleaks 们只会**提醒**——凌晨三点赶 deadline 的人会 `--no-verify` 强推过去。sops、git-crypt 假设你第一天就用上了它们；黑客松的真实状态是**今天**仓库里已经躺满密钥。cloakpack 补的就是这个缺口：泄漏即将发生时，修复只有一条命令，而且修复**比绕过更省事**。

- **阻断，不是提醒** —— pre-push 钩子扫描的正是"即将离开本机的那棵文件树"，命中密钥就不放行（显式逃生门是 `git push --no-verify`，这是有意设计）。
- **一键收纳，不用慌** —— `cloakpack pack` 把命中的密钥搬进本机 AES-256-GCM 加密保险库（`.cloakpack/vault.bin`，密钥只存在 `~/.cloakpack/keys/`），文件里的原位替换成 `⟦cloak:deepseek-api-key:1⟧` 稳定占位符并自动暂存。再推一次，远端就是干净的。
- **本机可逆** —— `cloakpack unpack` 还原原值，你的演示在本机照常满血运行。
- **对历史诚实** —— 密钥若已存在于历史提交，cloakpack 会说真话：*打包救不了它，去轮换。*

## 检测能力

与 [dsh-cloak](https://github.com/zhangmiao03/dsh-cloak) 同源引擎：24 个高查准签名族（AWS / 阿里云 / GCP，DeepSeek / OpenAI / Anthropic / OpenRouter，GitHub / GitLab / npm，Slack / Discord / 飞书 / 企微 webhook，Stripe / Shopify / Linear，JWT、PEM 私钥、带密码的数据库连接串、`Authorization: Bearer`），外加覆盖 `.env` / JSON / YAML 形态的敏感键名规则，以及 `.cloakpack/rules.json` 自定义正则。分页游标（`next_token`…）和占位值（`${VAR}`、`changeme`…）被有意排除。

## 安装

```sh
npm i -g cloakpack
cd your-project
cloakpack init      # 安装 pre-push 守卫，gitignore 保险库
```

零运行时依赖。Node ≥ 22。macOS / Linux / Windows(git-bash)。

## 命令

| 命令 | 作用 |
|---|---|
| `cloakpack init` | 安装 pre-push 守卫（拒绝覆盖他人钩子）、gitignore `.cloakpack/`、初始化密钥 |
| `cloakpack scan` | 扫描已跟踪文件，命中退出码 1 |
| `cloakpack pack [--dry-run]` | 收纳+占位符+`git add`；密钥也在历史里时警告（不置失败码） |
| `cloakpack unpack` | 从保险库还原原值 |
| `cloakpack unhook` | 移除守卫 |

自定义规则（`.cloakpack/rules.json`）：

```json
[
  { "id": "internal-prefix", "pattern": "mycorp-[a-z0-9]{32}", "flags": "g" }
]
```

## 威胁模型——请读

- 防的是：项目目录离开本机（分享、打包发送、U 盘丢失、评委 clone、公开演示）。
- **不防**：同机同用户下的恶意软件（它能读密钥文件，与密码管理器本地模式同级）。
- 保险库与密钥**永不入库**：`init` 已 gitignore `.cloakpack/`；丢失 `~/.cloakpack/keys/` 意味着打包不可还原——这是设计。
- 已经到过远端的密钥必须**轮换**——打包只清理当前文件树。

## 开发

```sh
npm install
npm test          # 38 个测试，含真实 git E2E：阻断→pack→干净推送→unpack 还原
npm run build
```

## 许可

[MIT](LICENSE)
