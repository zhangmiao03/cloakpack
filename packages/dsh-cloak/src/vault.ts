/**
 * dsh-cloak — 会话保险库：secret ↔ 占位符 的稳定映射。
 *
 * 仅存在于进程内存；按 agent 隔离（不同 agent 永不共享映射）；
 * 重启后旧占位符有意不可还原（与 dsh-redact 同一安全立场）。
 * 原值绝不进入审计事件与日志。
 */
import { createHash } from 'node:crypto'

export interface VaultEntry {
  /** 占位符全文，形如 ⟦cloak:aws-access-key:1⟧。 */
  placeholder: string
  category: string
  /** 命中次数（同一 secret 再次出现时累加）。 */
  hits: number
  firstSeen: number
}

function fingerprint(secret: string): string {  // cloakpack:allow
  return createHash('sha256').update(secret).digest('hex')
}

export class SecretVault {
  private readonly agents = new Map<string, {
    byFingerprint: Map<string, VaultEntry>
    counters: Map<string, number>
  }>()

  private scope(agentId: string) {
    let scope = this.agents.get(agentId)
    if (!scope) {
      scope = { byFingerprint: new Map(), counters: new Map() }
      this.agents.set(agentId, scope)
    }
    return scope
  }

  /**
   * 为 secret 取（或建）占位符。同一 agent 内同一 secret 稳定复用同一占位符。
   * agent 生命周期结束时应调用 forget()（host 侧由 dispose 驱动）。
   */
  placeholderFor(agentId: string, secret: string, category: string): string {
    const scope = this.scope(agentId)
    const key = fingerprint(secret)
    const existing = scope.byFingerprint.get(key)
    if (existing) {
      existing.hits += 1
      return existing.placeholder
    }
    const n = (scope.counters.get(category) ?? 0) + 1
    scope.counters.set(category, n)
    const entry: VaultEntry = {
      placeholder: `⟦cloak:${category}:${n}⟧`,
      category,
      hits: 1,
      firstSeen: Date.now(),
    }
    scope.byFingerprint.set(key, entry)
    return entry.placeholder
  }

  /** 丢弃某个 agent 的全部映射（不返回任何原值）。 */
  forget(agentId: string): void {
    this.agents.delete(agentId)
  }

  /** 统计（不含任何原值）。 */
  stats(): { agents: number; secrets: number } {
    let secrets = 0
    for (const scope of this.agents.values()) secrets += scope.byFingerprint.size
    return { agents: this.agents.size, secrets }
  }
}
