# dsh-cloak

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![DSH plugin](https://img.shields.io/badge/dsh-plugin-✅-green)](https://github.com/topics/dsh-plugin)
[![Node](https://img.shields.io/badge/node-%5E22.19%20%7C%7C%20%3E%3D24-brightgreen.svg)](#)
[![Release](https://img.shields.io/github/v/tag/zhangmiao03/dsh-cloak?label=release)](https://github.com/zhangmiao03/dsh-cloak/releases)
[![CI](https://img.shields.io/github/actions/workflow/status/zhangmiao03/dsh-cloak/ci.yml?branch=main&label=CI)](https://github.com/zhangmiao03/dsh-cloak/actions/workflows/ci.yml)

**[DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) 的上下文防火墙：工具结果里的凭证在进入模型之前被替换为不透明占位符。密钥永远不进上下文——任务照常进行。**

[English](README.md)

```
$ cat .env                          ← agent 读了一个配置文件
DEEPSEEK_API_KEY=sk-0123…cdef

→ 模型实际看到的：
DEEPSEEK_API_KEY=⟦cloak:deepseek-api-key:1⟧
```

## 为什么需要它

你的 agent 会读 `.env`、配置导出、云 CLI 输出、日志尾部。这些结果里的每一个凭证都会流入对话——并从那里**随每一次请求发给你的模型供应商**。导出时才脱敏（分享/交接）已经太晚：agent 干活的时候密钥就已经离开你的机器了。

`dsh-cloak` 守在「工具结果进入模型上下文」的边界上：

- **检测** — 24 条高查准内置签名（AWS/阿里云/GCP 密钥、DeepSeek/OpenAI/Anthropic/OpenRouter 密钥、GitHub/GitLab/npm token、Slack/Discord/飞书/企业微信 webhook、Stripe/Shopify/Linear、JWT、PEM 私钥块、带密码的数据库连接串、`Authorization: Bearer …`），外加键名规则（`password`/`secret`/`api_key`/…）兜底未知格式，覆盖 `.env`、JSON、YAML 形态。支持 JSON 文件加载自定义正则。
- **替换** — 命中变成稳定占位符 `⟦cloak:<类别>:<序号>⟧`。原值只存在于进程内存的 agent 级保险库，绝不进入会话日志、审计事件或模型请求。
- **告知** — 系统提示注入 + 每条结果的附加说明告诉模型占位符的语义：不要猜、不要重构、不要重读源文件试图找回；确实需要真值时问用户。

分页游标（`next_token`、`page_token` 等）与占位值（`${VAR}`、`changeme` 等）被有意排除，翻页和模板不受影响。

## 安装

```sh
# GitHub 渠道（最新 main）：
dsh plugin --profile web add "github:zhangmiao03/dsh-cloak#main"
# GitHub 渠道（锁定版本，正式环境推荐）：
dsh plugin --profile web add "github:zhangmiao03/dsh-cloak#v0.1.0"
# npm 渠道（npm publish 后）：
dsh plugin --profile web add dsh-cloak
# 本地开发：
dsh plugin --profile web add /path/to/dsh-cloak
```

卸载：`dsh plugin --profile web remove cloak`。

验证挂载后重启 dsh：

```sh
dsh --profile web --dump-config | grep -A2 'id: cloak'
```

## 配置

profile `cordis.patch.yml` 中按行配置：

```yaml
- id: cloak
  config:
    enabled: true
    dryRun: false          # 只审计不替换（灰度观察模式）
    builtins:
      enabled: true
    rulesFile: ~/.dsh/cloak-rules.json
    note: true             # 给模型附占位符语义说明
    audit:
      maxEntries: 200
      logFile:             # 可选 JSONL 审计落盘
```

自定义规则文件格式：

```json
[
  { "id": "internal-prefix", "pattern": "mycorp-[a-z0-9]{32}", "flags": "g" }
]
```

## 暴露面

| 面 | 类型 | 说明 |
|---|---|---|
| `tools/post-execute` | 监听器 | 打码成功的纯文本工具结果（content 投影） |
| `systemPrompt` 注入 | 注入 | 模型见到占位符之前就知道其语义 |
| `/cloak` | 命令 | `/cloak` 统计 · `/cloak scan <文本>` 试扫 |
| `/cloak/api/*` | HTTP | `GET stats` · `GET recent` · `POST test {text}` |

## 安全性质

- 审计事件、日志、API 响应中绝不出现原值——只有类别与计数。
- 保险库按 agent 隔离、仅存内存；重启后旧占位符有意不可还原。
- 扫描器故障 fail-open（坏规则文件或扫描器 bug 绝不会把成功的工具调用变成错误），每次故障都有审计。
- 零运行时依赖——只用 Node 内置模块与 DSH 宿主包。

## 有意排除（v0.1）

诚实圈定范围，与宿主自带 `spill-policy` 同一立场：

- 只处理成功的纯文本结果。失败结果与非文本块原样放行（替换错误文本会破坏错误语义）。
- 模型不能「使用」被打码的凭证：把密钥还原进工具参数是平台设计上不可能的（`PreToolDecision` 明确排除输入改写）。任务需要真值时，模型被指示询问用户。骑在宿主 `ask`/authorization 缝上的「审批后揭示」在规划中。
- 不改写用户消息；不额外扫描出站请求体（工具结果是主要泄漏通道且已在源头覆盖）。两者都是后续候选。
- `dryRun` 只审计不替换，推荐作为上线第一步。

## 兼容性

基于 DeepSeek Harness `0.1.2-rc.1` 构建并验证（developer-preview 宿主，破坏性变更时需重新适配）。Node `^22.19 || >=24`。

## 开发

```sh
npm install --legacy-peer-deps
npm test            # 51 个单测
npm run build       # 从全局 dsh 安装链接 @deepseek-ai/* 依赖，然后 tsc
```

## 许可

[MIT](LICENSE)
