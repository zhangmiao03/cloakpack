/**
 * cloakpack — 内置机密签名库（与 dsh-cloak 共享同源引擎）。
 *
 * 设计原则：查准优先于查全（false positive 会让用户直接卸载）。
 * 每条签名必须是「几乎不可能在正常文本里出现」的格式。结构化键名
 * 赋值（password=…、api_key: …）由 SENSITIVE_KEY 规则兜底，覆盖未知格式。
 */

export interface Signature {
  /** 稳定 id，进入占位符类别名与审计事件。 */
  id: string
  description: string
  /** 全局正则。捕获组 0 = 要打码的整体 span。必须无 sticky/y 标志。 */
  regex: RegExp
  /** 可选：对候选 span 做进一步校验（如长度、字符集），返回 false 则放弃。 */
  validate?: (match: string) => boolean
  /** 可选：候选 span 的最小香农熵（gitleaks 同型反误报闸，作用于字母数字部分）。 */
  entropyMin?: number
}

/** 香农熵（按字符计，gitleaks entropy 同思路）。 */
export function shannonEntropy(s: string): number {
  if (s.length === 0) return 0
  const freq = new Map<string, number>()
  for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1)
  let h = 0
  for (const n of freq.values()) {
    const p = n / s.length
    h -= p * Math.log2(p)
  }
  return h
}

/** 通用 token 校验：至少 8 个字符且同时含字母与数字类字符，排除占位符样子。 */
function looksLikeCredential(token: string): boolean {
  if (token.length < 8) return false
  if (/^\d+$/.test(token)) return false // 纯数字（订单号/时间戳）不打码
  return /[A-Za-z]/.test(token) && /[0-9]/.test(token)
}

/** 长十六进制串（DeepSeek/许多国产 API key 的形态）。 */
const isHex32 = (t: string): boolean => /^[0-9a-f]{32}$/i.test(t)

export const SIGNATURES: Signature[] = [
  // ── 云厂商 AccessKey ──
  {
    id: 'aws-access-key',
    description: 'AWS access key id (AKIA/ASIA/…)',
    regex: /\b(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ABIA|ACCA|ASIA)[A-Z0-9]{16}\b/g,
    validate: (t) => /^[A-Z0-9]{20}$/.test(t),
  },
  {
    id: 'aliyun-access-key',
    description: 'Aliyun access key id (LTAI…)',
    regex: /\bLTAI[A-Za-z0-9]{12,20}\b/g,
  },
  {
    id: 'google-api-key',
    description: 'Google/Gemini API key (AIza…)',
    regex: /\bAIza[0-9A-Za-z_\-]{35}\b/g,
  },

  // ── 模型厂商 ──
  {
    id: 'deepseek-api-key',
    description: 'DeepSeek API key (sk- + 32 hex)',
    regex: /\bsk-[0-9a-f]{32}\b/g,
    validate: (t) => isHex32(t.slice(3)),
  },
  {
    id: 'anthropic-api-key',
    description: 'Anthropic API key (sk-ant-…)',
    regex: /\bsk-ant-[A-Za-z0-9_\-]{24,}\b/g,
  },
  {
    id: 'openai-api-key',
    description: 'OpenAI-style API key (sk-proj-… / sk-…)',
    // 放在 deepseek/anthropic 之后靠最长匹配去重兜底
    regex: /\bsk-(?:proj-)?[A-Za-z0-9_\-]{32,}\b/g,
    validate: looksLikeCredential,
    entropyMin: 3.2,
  },
  {
    id: 'openrouter-api-key',
    description: 'OpenRouter API key (sk-or-v1-…)',
    regex: /\bsk-or-v1-[0-9a-f]{48,64}\b/g,
  },

  // ── 代码托管 / 包管理 ──
  {
    id: 'github-token',
    description: 'GitHub token (ghp_/gho_/ghu_/ghs_/ghr_…)',
    regex: /\bgh[pousr]_[A-Za-z0-9]{36,255}\b/g,
  },
  {
    id: 'gitlab-token',
    description: 'GitLab personal access token (glpat-…)',
    regex: /\bglpat-[A-Za-z0-9_\-]{20,}\b/g,
  },
  {
    id: 'npm-token',
    description: 'npm access token (npm_…)',
    regex: /\bnpm_[A-Za-z0-9]{36}\b/g,
  },

  // ── IM / 协作 ──
  {
    id: 'slack-token',
    description: 'Slack token (xox[baprs]-…)',
    regex: /\bxox[baprs]-[A-Za-z0-9\-]{10,}\b/g,
  },
  {
    id: 'discord-webhook',
    description: 'Discord webhook URL',
    regex: /https:\/\/discord(?:app)?\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_\-]{40,}/g,
  },
  {
    id: 'slack-webhook',
    description: 'Slack incoming webhook URL',
    regex: /https:\/\/hooks\.slack\.com\/services\/T[A-Za-z0-9]+\/B[A-Za-z0-9]+\/[A-Za-z0-9]{16,}/g,
  },
  {
    id: 'feishu-webhook',
    description: '飞书自定义机器人 webhook',
    regex: /https:\/\/open\.feishu\.cn\/open-apis\/bot\/v2\/hook\/[0-9a-f\-]{30,}/g,
  },
  {
    id: 'wecom-webhook',
    description: '企业微信群机器人 webhook',
    regex: /https:\/\/qyapi\.weixin\.qq\.com\/cgi-bin\/webhook\/send\?key=[A-Za-z0-9\-]{30,}/g,
  },

  // ── 支付 / 商业 SaaS ──
  {
    id: 'stripe-key',
    description: 'Stripe secret/restricted key (sk_live_… / rk_live_…)',
    regex: /\b[sr]k_(?:live|test)_[A-Za-z0-9]{20,}\b/g,
  },
  {
    id: 'shopify-token',
    description: 'Shopify access token (shpat_/shpss_/shpca_…)',
    regex: /\bshp[a-z]{2,3}_[a-fA-F0-9]{32}\b/g,
  },
  {
    id: 'linear-api-key',
    description: 'Linear API key (lin_api_…)',
    regex: /\blin_api_[A-Za-z0-9]{40}\b/g,
  },
  {
    id: 'sentry-dsn',
    description: 'Sentry DSN',
    regex: /https:\/\/[0-9a-f]{32}@[a-z0-9.\-]+\.ingest\.sentry\.io[^\s"']*/g,
  },

  // ── 通用形态 ──
  {
    id: 'jwt',
    description: 'JWT (eyJ…, 三段式)',
    regex: /\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b/g,
  },
  {
    id: 'private-key-block',
    description: 'PEM 私钥块（RSA/EC/OpenSSH/PGP）',
    regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/g,
  },
  {
    id: 'db-connection-url',
    description: '带密码的数据库/消息队列连接串（postgres://user:pass@… 等）',
    regex: /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?|ftp):\/\/[^\s:@/"']+:[^\s@/"']+@[^\s"'<>]*/g,
  },
  {
    id: 'bearer-header',
    description: 'Authorization: Bearer … 凭证',
    regex: /\bauthorization["']?\s*[:=]\s*["']?bearer\s+[A-Za-z0-9._\-+/=]{20,}/gi,
  },

  // ── 第二批（取自 gitleaks 规则库的高精度前缀格式，2026-09 增补）──
  {
    id: 'anthropic-admin-api-key',
    description: 'Anthropic admin API key (sk-ant-admin01-…)',
    regex: /\bsk-ant-admin01-[A-Za-z0-9_\-]{16,}/g,
  },
  {
    id: 'twilio-api-key',
    description: 'Twilio API key (SK + 32 hex)',
    regex: /\bSK[0-9a-f]{32}\b/g,
  },
  {
    id: 'sendgrid-api-key',
    description: 'SendGrid API key (SG.x.y)',
    regex: /\bSG\.[A-Za-z0-9_\-]{16,32}\.[A-Za-z0-9_\-]{16,64}\b/g,
  },
  {
    id: 'mailgun-api-key',
    description: 'Mailgun API key (key- + 32 hex)',
    regex: /\bkey-[0-9a-z]{32}\b/g,
  },
  {
    id: 'telegram-bot-token',
    description: 'Telegram bot token (123456789:AA…)',
    regex: /\b[0-9]{8,10}:AA[A-Za-z0-9_\-]{30,40}\b/g,
  },
  {
    id: 'airtable-pat',
    description: 'Airtable personal access token (patXX.YY)',
    regex: /\bpat[A-Za-z0-9]{14,24}\.[a-z0-9]{24,40}\b/g,
  },
  {
    id: 'atlassian-api-token',
    description: 'Atlassian API token (ATATT3…)',
    regex: /\bATATT3[A-Za-z0-9_\-=]{60,}/g,
  },
  {
    id: 'digitalocean-token',
    description: 'DigitalOcean token (dop_/dor_/doc_ v1 + 64 hex)',
    regex: /\bdo[prc]_v1_[a-f0-9]{64}\b/g,
  },
  {
    id: 'gitlab-scoped-token',
    description: 'GitLab deploy/routable/CI token (gldt-/glrt-/glcbt-/glptt-…)',
    regex: /\bgl(?:dt|rt|cbt|ptt)-[A-Za-z0-9_\-]{20,}/g,
  },
  {
    id: 'notion-token',
    description: 'Notion integration token (secret_ + 43)',
    regex: /\bsecret_[A-Za-z0-9]{40,48}\b/g,
  },
  {
    id: 'figma-token',
    description: 'Figma token (figd_/figu_…)',
    regex: /\bfig[du]_[A-Za-z0-9_\-]{25,}/g,
  },
  {
    id: 'google-oauth-refresh',
    description: 'Google OAuth refresh token (1//…)',
    regex: /\b1\/\/[0-9A-Za-z_\-]{40,}/g,
  },
  {
    id: 'tencent-cloud-secretid',
    description: '腾讯云 SecretId (AKID…)',
    regex: /\bAKID[A-Za-z0-9]{32,48}\b/g,
  },
]

/**
 * 结构化键名规则：`"api_key": "…"` / `password = …` / `SECRET_TOKEN=…`。
 * 键名包含敏感词（子串，忽略大小写与 -/_ 差异）即命中，值打码。
 */
export const SENSITIVE_KEY_PATTERN =
  /(?:password|passwd|pwd|secret|token|api[_\-]?key|apikey|access[_\-]?key|private[_\-]?key|credential|appsecret|app[_\-]?secret|client[_\-]?secret|smtp[_\-]?pass)/i

/**
 * 排除键名：命中敏感词但值实际是「游标/分页」类无凭证语义的键。
 * 分页 token 打码会直接破坏模型的翻页能力，代价高于收益。
 */
export const EXCLUDED_KEY_PATTERN =
  /(?:next[_\-]?token|page[_\-]?token|pagetoken|continuation[_\-]?token|cursor|since[_\-]?id|max[_\-]?id|token[_\-]?type|format)/i

/**
 * 结构化赋值匹配（文本级兜底，覆盖 JSON / YAML / .env / ini）：
 * 捕获组 1 = 键名（用于键名过滤），组 2 = 值。
 */
export const ASSIGNMENT_REGEX =
  /["']?([A-Za-z_][A-Za-z0-9_\-]*)["']?\s*[:=]\s*["']?([^\s"'&,;}]{8,256})/g

/**
 * 值的「免打码」形态：占位符、插值、枚举值。值本身无凭证语义时跳过。
 */
export function isPlaceholderValue(value: string): boolean {
  if (/^⟦cloak:[^⟧]+:\d+⟧$/.test(value)) return true // 自家占位符（幂等：打包后的文件不再命中）
  if (/^\$\{/.test(value)) return true // ${ENV_VAR}（赋值捕获可能截掉右花括号，按前缀豁免）
  if (/^%[A-Za-z0-9_]+%$/.test(value)) return true // %VAR%
  if (/^(?:true|false|null|none|nil|undefined|changeme|example|placeholder|sample|redacted|xxx+|\*+|<[^>]+>|\$\w+)$/i.test(value)) return true
  if (/^https?:\/\//i.test(value)) return true // URL 由专门签名处理
  if (/^[0-9.]+$/.test(value)) return true // 数值
  if (value.length < 8) return true
  return false
}
