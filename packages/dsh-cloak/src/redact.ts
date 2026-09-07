/**
 * dsh-cloak — 打码组合层：scan() 的 findings 交给 vault 换占位符，
 * 从后往前替换保证偏移稳定。
 */
import { scan, type Finding, type ScanOptions } from '@cloakpack/core'
import type { SecretVault } from './vault.js'

export interface RedactionResult {
  text: string
  /** 实际发生的替换（按出现顺序）。 */
  findings: Array<Finding & { placeholder: string }>
  /** 是否发生了任何替换。 */
  readonly changed: boolean
}

export interface Redactor {
  scan: (text: string) => Finding[]
  redact: (agentId: string, text: string) => RedactionResult
}

export function createRedactor(vault: SecretVault, options: ScanOptions): Redactor {
  return {
    scan: (text) => scan(text, options),
    redact(agentId: string, text: string): RedactionResult {
      const findings = scan(text, options)
      if (findings.length === 0) {
        return { text, findings: [], changed: false } as RedactionResult
      }
      // 占位符稳定：同一 secret → 同一序号；从后往前替换。
      const enriched: Array<Finding & { placeholder: string }> = findings.map((f) => {
        const secret = text.slice(f.start, f.start + f.length)  // cloakpack:allow
        return { ...f, placeholder: vault.placeholderFor(agentId, secret, f.category) }
      })
      let out = text
      for (let i = enriched.length - 1; i >= 0; i -= 1) {
        const f = enriched[i]
        out = out.slice(0, f.start) + f.placeholder + out.slice(f.start + f.length)
      }
      return { text: out, findings: enriched, changed: true } as RedactionResult
    },
  }
}
