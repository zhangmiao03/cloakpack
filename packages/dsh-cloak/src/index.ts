/**
 * dsh-cloak — 上下文防火墙（host 侧入口）。
 *
 * 监听 tools/post-execute（waterfall）：成功的纯文本工具结果在进入模型
 * 上下文之前，命中机密签名的部分被替换为稳定占位符 ⟦cloak:<category>:<n>⟧。
 * 原值只存在于进程内存的 agent 级保险库，绝不进入会话日志、审计事件或模型请求。
 */
import type { Context } from '@deepseek-ai/cordis'
import type {} from '@deepseek-ai/dsh-commands'
import type {} from '@deepseek-ai/dsh-host-webserver'
import z from '@deepseek-ai/schemastery'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { homedir } from 'node:os'
import { Audit } from './audit.js'
import { createApiHandler } from './api.js'
import { createPostExecuteHandler } from './handlers.js'
import { createRedactor } from './redact.js'
import { scan } from '@cloakpack/core'
import { SecretVault } from './vault.js'

export const name = 'cloak'
export const inject = ['tools', 'webServer']

export interface CustomRule {
  id: string
  pattern: string
  flags?: string
}

export interface Config {
  enabled: boolean
  /** 只记审计不替换（灰度观察模式）。 */
  dryRun: boolean
  builtins: { enabled: boolean }
  /** 自定义规则 JSON：[{id, pattern, flags?}]。 */
  rulesFile: string
  /** 是否给模型附占位符行为约束说明。 */
  note: boolean
  audit: { maxEntries: number; logFile?: string }
}

export const Config: z<Config> = z.object({
  enabled: z.boolean().default(true),
  dryRun: z.boolean().default(false),
  builtins: z.object({ enabled: z.boolean().default(true) }),
  rulesFile: z.string().default(join(homedir(), '.dsh', 'cloak-rules.json')),
  note: z.boolean().default(true),
  audit: z.object({
    maxEntries: z.number().min(10).max(10000).default(200),
    logFile: z.string(),
  }),
})

/** 读用户自定义规则（坏文件不阻断启动，记日志后忽略）。 */
function loadCustomRules(file: string, log: (msg: string) => void): { id: string; regex: RegExp }[] {
  try {
    const raw = readFileSync(file, 'utf8') as string
    const parsed = JSON.parse(raw) as CustomRule[]
    if (!Array.isArray(parsed)) return []
    const out: { id: string; regex: RegExp }[] = []
    for (const r of parsed) {
      if (!r?.id || !r?.pattern) continue
      out.push({ id: r.id, regex: new RegExp(r.pattern, r.flags ?? 'g') })
    }
    return out
  } catch {
    log(`cloak: no custom rules loaded from ${file}`)
    return []
  }
}

export function apply(ctx: Context, config?: Config): void {
  const cfg: Config = {
    enabled: config?.enabled ?? true,
    dryRun: config?.dryRun ?? false,
    builtins: { enabled: config?.builtins?.enabled ?? true },
    rulesFile: config?.rulesFile ?? join(homedir(), '.dsh', 'cloak-rules.json'),
    note: config?.note ?? true,
    audit: { maxEntries: config?.audit?.maxEntries ?? 200, logFile: config?.audit?.logFile },
  }
  const log = (msg: string): void => { ctx.logger?.info?.(msg) }

  const customRules = loadCustomRules(cfg.rulesFile, log)
  const vault = new SecretVault()
  const redactor = createRedactor(vault, {
    builtinsEnabled: cfg.builtins.enabled,
    customRules,
  })
  const audit = new Audit(cfg.audit.maxEntries, cfg.audit.logFile)

  ctx.effect(() => ctx.on(
    'tools/post-execute',
    createPostExecuteHandler({
      redactor,
      audit,
      enabled: () => cfg.enabled,
      dryRun: () => cfg.dryRun,
      note: () => cfg.note,
    }),
  ), 'cloak: post-execute')

  ctx.effect(() => ctx.webServer.register({
    kind: 'prefix',
    path: '/cloak/api',
    handler: createApiHandler({ audit, redactor, vault }),
  }), 'cloak: api')

  // 系统提示注入：让模型在见到占位符之前就知道其语义（与 permission-rules 同一缝）。
  ctx.inject(['systemPrompt'], (scope) => {
    const systemPrompt = scope.get('systemPrompt') as
      | { context?: (entry: { name: string; order?: number; text: string }) => void }
      | undefined
    if (systemPrompt?.context === undefined) return
    systemPrompt.context({
      name: 'cloak:policy',
      order: 110,
      text: 'Secret policy (cloak): credentials in tool results are replaced with opaque placeholders like ⟦cloak:category:n⟧. '
        + 'They are irrecoverable from your side. Do not guess or reconstruct them, do not re-read sources to recover them; '
        + 'when a task genuinely needs a real credential, ask the user.',
    })
  })

  // 命令子作用域：仅当宿主组装了命令注册表时激活（官方 plan-mode 同款模式）。
  ctx.inject(['commands'], (commandCtx) => {
    const commands = commandCtx.commands as unknown as {
      register: (cmd: {
        name: string
        description: string
        input?: { hint?: string }
        handler: (invocation: { rawInput?: string }) => { kind: 'success' | 'error'; text: string }
      }) => void
    }
    commands.register({
      name: 'cloak',
      description: 'show cloak redaction stats, or dry-scan a text sample',
      input: { hint: '[stats | scan <text>]' },
      handler: ({ rawInput }) => {
        const input = (rawInput ?? '').trim()
        if (input.startsWith('scan ')) {
          const findings = scan(input.slice(5), { builtinsEnabled: cfg.builtins.enabled, customRules })
          if (findings.length === 0) return { kind: 'success', text: '[cloak] no findings' }
          return {
            kind: 'success',
            text: `[cloak] ${findings.length} finding(s): ${findings.map((f) => f.category).join(', ')}`,
          }
        }
        const s = audit.stats()
        const v = vault.stats()
        return {
          kind: 'success',
          text: `[cloak] audits=${s.total} categories=${JSON.stringify(s.byCategory)} live-vault=agents:${v.agents}/secrets:${v.secrets} mode=${cfg.dryRun ? 'dry-run' : 'enforce'}`,
        }
      },
    })
  })
}
