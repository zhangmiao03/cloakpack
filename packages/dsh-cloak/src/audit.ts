/**
 * dsh-cloak — 审计：内存环形缓冲 + 可选 JSONL 文件 + 会话事件。
 * 铁律：任何字段不得包含密钥原值或占位符，只记类别与计数。
 */
import { appendFileSync } from 'node:fs'

export interface AuditEntry {
  ts: number
  agent?: string
  tool: string
  action: 'redact' | 'dry-run' | 'error'
  count: number
  categories: string[]
}

export class Audit {
  private readonly buffer: AuditEntry[] = []

  constructor(
    private readonly maxEntries: number,
    private readonly logFile?: string,
  ) {}

  push(entry: AuditEntry): void {
    this.buffer.push(entry)
    if (this.buffer.length > this.maxEntries) {
      this.buffer.splice(0, this.buffer.length - this.maxEntries)
    }
    if (this.logFile) {
      try {
        appendFileSync(this.logFile, `${JSON.stringify(entry)}\n`)
      } catch {
        // 审计写盘失败不阻断打码链路
      }
    }
  }

  list(limit = 50): AuditEntry[] {
    return this.buffer.slice(-limit).reverse()
  }

  stats(): { total: number; byCategory: Record<string, number> } {
    const byCategory: Record<string, number> = {}
    for (const e of this.buffer) {
      for (const c of e.categories) byCategory[c] = (byCategory[c] ?? 0) + 1
    }
    return { total: this.buffer.length, byCategory }
  }
}
