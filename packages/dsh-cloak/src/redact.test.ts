import { describe, expect, it } from 'vitest'
import { SecretVault } from './vault.js'
import { deepseekKey } from '@cloakpack/core'
import { createRedactor } from './redact.js'

describe('SecretVault', () => {
  it('同一 secret → 同一占位符；不同 secret → 不同序号', () => {
    const vault = new SecretVault()
    const a1 = vault.placeholderFor('agent-1', 'AKIAIOSFODNN7EXAMPLE', 'aws-access-key')
    const a2 = vault.placeholderFor('agent-1', 'AKIAIOSFODNN7EXAMPLE', 'aws-access-key')
    expect(a1).toBe(a2)
    expect(a1).toBe('⟦cloak:aws-access-key:1⟧')
    const b = vault.placeholderFor('agent-1', 'AKIAIOSFODNN7EXAMPLF', 'aws-access-key')
    expect(b).toBe('⟦cloak:aws-access-key:2⟧')
  })

  it('agent 隔离：不同 agent 的同一 secret 各自独立', () => {
    const vault = new SecretVault()
    const a = vault.placeholderFor('agent-1', deepseekKey, 'deepseek-api-key')
    const b = vault.placeholderFor('agent-2', deepseekKey, 'deepseek-api-key')
    expect(a).toBe('⟦cloak:deepseek-api-key:1⟧')
    expect(b).toBe('⟦cloak:deepseek-api-key:1⟧') // 各自从 1 开始，但映射互不可见
    vault.forget('agent-2')
    const c = vault.placeholderFor('agent-2', deepseekKey, 'deepseek-api-key')
    expect(c).toBe('⟦cloak:deepseek-api-key:1⟧')
    expect(vault.stats()).toEqual({ agents: 2, secrets: 2 })
  })
})

describe('createRedactor.redact', () => {
  it('多命中全部替换且原文不再出现', () => {
    const vault = new SecretVault()
    const redactor = createRedactor(vault, {})
    const text = 'aws=AKIAIOSFODNN7EXAMPLE and gh=ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA end'
    const out = redactor.redact('agent-1', text)
    expect(out.changed).toBe(true)
    expect(out.findings).toHaveLength(2)
    expect(out.text).not.toContain('AKIAIOSFODNN7EXAMPLE')
    expect(out.text).not.toContain('ghp_')
    expect(out.text).toContain('⟦cloak:aws-access-key:1⟧')
    expect(out.text).toContain('⟦cloak:github-token:1⟧')
    expect(out.text.startsWith('aws=')).toBe(true)
    expect(out.text.endsWith(' end')).toBe(true)
  })

  it('同一 secret 二次出现复用占位符（稳定）', () => {
    const vault = new SecretVault()
    const redactor = createRedactor(vault, {})
    const secret = 'AKIAIOSFODNN7EXAMPLE'
    const first = redactor.redact('a', `x ${secret} y`)
    const second = redactor.redact('a', `z ${secret} w`)
    expect(first.findings[0].placeholder).toBe(second.findings[0].placeholder)
  })

  it('无命中原样返回', () => {
    const vault = new SecretVault()
    const redactor = createRedactor(vault, {})
    const out = redactor.redact('a', 'plain text 123')
    expect(out.changed).toBe(false)
    expect(out.text).toBe('plain text 123')
    expect(out.findings).toHaveLength(0)
  })

  it('占位符文本再打码不叠加（幂等安全）', () => {
    const vault = new SecretVault()
    const redactor = createRedactor(vault, {})
    const once = redactor.redact('a', 'key AKIAIOSFODNN7EXAMPLE')
    const twice = redactor.redact('a', once.text)
    expect(twice.changed).toBe(false)
  })
})
