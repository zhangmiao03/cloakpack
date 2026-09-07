/**
 * dsh-cloak — tools/post-execute 结果变换器。
 *
 * 对「成功的纯文本工具结果」做机密扫描：命中则以等量占位符替换 content，
 * 并附 additionalContexts 告知模型占位符语义（不猜、不重构、需要真值时问用户）。
 * 非文本块、失败结果、无命中一律原样放行（next()）。遵循 spill-policy 的
 * best-effort 立场：扫描器异常绝不把成功调用变成错误，只记审计并放行。
 */
import { createUserMessage } from '@deepseek-ai/dsh-llm'
import type { ContentBlock } from '@deepseek-ai/dsh-llm'
import type { PostToolDecision, ToolExecution } from '@deepseek-ai/dsh-tools'
import type { Audit } from './audit.js'
import type { Redactor } from './redact.js'

export interface CloakDeps {
  redactor: Redactor
  audit: Audit
  enabled: () => boolean
  dryRun: () => boolean
  /** 是否附加给模型的占位符说明上下文。 */
  note: () => boolean
}

function flattenPlainText(content: ContentBlock[]): string | undefined {
  let text = ''
  for (const block of content) {
    if (block.type !== 'text') return undefined
    text += block.text
  }
  return text
}

function agentId(exec: ToolExecution): string {
  return exec.agent?.id ?? 'no-agent'
}

/** 打码说明：模型看到占位符后的行为约束。 */
export function noticeText(categories: string[], count: number): string {
  const cat = categories.join(', ')
  return `[cloak] ${count} credential(s) were redacted from this tool result (categories: ${cat}). `
    + 'Placeholders look like ⟦cloak:<category>:<n>⟧. They are opaque and map to the real values only inside the local vault. '
    + 'Do not guess, reconstruct, or brute-force them, and do not ask other tools to read the original source again to recover them. '
    + 'If completing the task genuinely requires a real value, stop and ask the user.'
}

export function createPostExecuteHandler(deps: CloakDeps) {
  return async (
    exec: ToolExecution,
    result: Readonly<unknown>,
    next: () => Promise<PostToolDecision>,
  ): Promise<PostToolDecision> => {
    try {
      if (!deps.enabled()) return next()
      // 失败结果不打码（错误文本同样可能含密钥，但替换会破坏错误语义；
      // v0.1 立场：只处理成功投影，见 README 排除清单）。
      const r = result as { isError?: boolean; content?: ContentBlock[] }
      if (r?.isError || !Array.isArray(r?.content)) return next()
      const text = flattenPlainText(r.content)
      if (text === undefined || text.length === 0) return next()

      const agent = agentId(exec)
      const outcome = deps.redactor.redact(agent, text)
      if (!outcome.changed) return next()

      const categories = [...new Set(outcome.findings.map((f) => f.category))].sort()
      const dryRun = deps.dryRun()
      deps.audit.push({
        ts: Date.now(),
        agent: exec.agent?.id,
        tool: exec.name,
        action: dryRun ? 'dry-run' : 'redact',
        count: outcome.findings.length,
        categories,
      })

      if (dryRun) return next()

      const additionalContexts = deps.note()
        ? [createUserMessage({
          content: [{ type: 'text', text: noticeText(categories, outcome.findings.length) }],
          source: { kind: 'plugin', plugin: 'cloak' },
        })]
        : undefined

      return {
        kind: 'accept',
        content: [{ type: 'text', text: outcome.text }],
        ...(additionalContexts ? { additionalContexts } : {}),
      }
    } catch (error) {
      deps.audit.push({
        ts: Date.now(),
        agent: exec.agent?.id,
        tool: exec.name,
        action: 'error',
        count: 0,
        categories: [error instanceof Error ? error.message.slice(0, 120) : 'unknown'],
      })
      return next()
    }
  }
}
