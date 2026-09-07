import { describe, expect, it, vi } from 'vitest'
import type { ToolExecution } from '@deepseek-ai/dsh-tools'
import { Audit } from './audit.js'
import { createPostExecuteHandler, type CloakDeps } from './handlers.js'
import { createRedactor } from './redact.js'
import { SecretVault } from './vault.js'

const makeExec = (patch: Partial<ToolExecution> = {}): ToolExecution => ({
  callId: 'call-1',
  rootCallId: 'call-1',
  name: 'bash',
  arguments: { command: 'cat .env' },
  signal: new AbortController().signal,
  ...patch,
} as ToolExecution)

const makeDeps = (over: Partial<CloakDeps> = {}): CloakDeps => ({
  redactor: createRedactor(new SecretVault(), {}),
  audit: new Audit(50),
  enabled: () => true,
  dryRun: () => false,
  note: () => true,
  ...over,
})

const okResult = (text: string): unknown => ({
  isError: false,
  value: text,
  content: [{ type: 'text', text }],
})

describe('createPostExecuteHandler', () => {
  it('命中：content 被替换为占位符文本 + 附加模型说明', async () => {
    const deps = makeDeps()
    const secret = 'AKIAIOSFODNN7EXAMPLE'
    const decision = await createPostExecuteHandler(deps)(
      makeExec(), okResult(`aws key: ${secret}`), async () => ({ kind: 'accept' }),
    )
    expect(decision.kind).toBe('accept')
    if (decision.kind !== 'accept') return
    expect(decision.content).toBeDefined()
    const text = (decision.content ?? []).map((b) => (b as { text?: string }).text ?? '').join('')
    expect(text).not.toContain(secret)
    expect(text).toContain('⟦cloak:aws-access-key:1⟧')
    expect(decision.additionalContexts).toBeDefined()
    const note = JSON.stringify(decision.additionalContexts ?? [])
    expect(note).toContain('[cloak]')
    expect(note).not.toContain(secret)
  })

  it('无命中：委托 next()，决策不变', async () => {
    const deps = makeDeps()
    const next = vi.fn(async () => ({ kind: 'accept' as const }))
    const decision = await createPostExecuteHandler(deps)(makeExec(), okResult('all clean'), next)
    expect(decision).toEqual({ kind: 'accept' })
    expect(next).toHaveBeenCalledTimes(1)
  })

  it('失败结果：原样放行', async () => {
    const deps = makeDeps()
    const next = vi.fn(async () => ({ kind: 'accept' as const }))
    const failed = { isError: true, error: new Error('boom'), content: [{ type: 'text', text: 'AWS_KEY=AKIAIOSFODNN7EXAMPLE' }] }
    await createPostExecuteHandler(deps)(makeExec(), failed, next)
    expect(next).toHaveBeenCalledTimes(1)
  })

  it('非文本块（图片等）：原样放行', async () => {
    const deps = makeDeps()
    const next = vi.fn(async () => ({ kind: 'accept' as const }))
    const mixed = { isError: false, content: [{ type: 'image', url: 'x' }, { type: 'text', text: 'AKIAIOSFODNN7EXAMPLE' }] }
    await createPostExecuteHandler(deps)(makeExec(), mixed, next)
    expect(next).toHaveBeenCalledTimes(1)
  })

  it('dry-run：记审计但不替换', async () => {
    const deps = makeDeps({ dryRun: () => true })
    const next = vi.fn(async () => ({ kind: 'accept' as const }))
    await createPostExecuteHandler(deps)(makeExec(), okResult('k=AKIAIOSFODNN7EXAMPLE'), next)
    expect(next).toHaveBeenCalledTimes(1)
    expect(deps.audit.list()[0]).toMatchObject({ action: 'dry-run', count: 1 })
  })

  it('enabled=false：直接放行', async () => {
    const deps = makeDeps({ enabled: () => false })
    const next = vi.fn(async () => ({ kind: 'accept' as const }))
    await createPostExecuteHandler(deps)(makeExec(), okResult('k=AKIAIOSFODNN7EXAMPLE'), next)
    expect(next).toHaveBeenCalledTimes(1)
  })

  it('note=false：不附加说明上下文', async () => {
    const deps = makeDeps({ note: () => false })
    const decision = await createPostExecuteHandler(deps)(
      makeExec(), okResult('k=AKIAIOSFODNN7EXAMPLE'), async () => ({ kind: 'accept' }),
    )
    expect(decision.kind).toBe('accept')
    if (decision.kind === 'accept') expect(decision.additionalContexts).toBeUndefined()
  })

  it('扫描器异常：fail-open 放行并记 error 审计', async () => {
    const redactor = createRedactor(new SecretVault(), {})
    const broken = { ...redactor, redact: () => { throw new Error('boom') } }
    const deps = makeDeps({ redactor })
    ;(deps as { redactor: typeof redactor }).redactor = broken
    const next = vi.fn(async () => ({ kind: 'accept' as const }))
    await createPostExecuteHandler(deps)(makeExec(), okResult('k=AKIAIOSFODNN7EXAMPLE'), next)
    expect(next).toHaveBeenCalledTimes(1)
    expect(deps.audit.list()[0].action).toBe('error')
  })

  it('审计铁律：事件不含密钥原值', async () => {
    const deps = makeDeps()
    const secret = 'ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    await createPostExecuteHandler(deps)(
      makeExec(), okResult(`gh=${secret}`), async () => ({ kind: 'accept' }),
    )
    const serialized = JSON.stringify(deps.audit.list())
    expect(serialized).not.toContain(secret)
    expect(serialized).not.toContain('⟦cloak:')
  })
})
