/**
 * cloakpack — 扫描器（与 dsh-cloak 共享同源引擎）：在纯文本上收集所有命中 span，去重叠（最长优先），
 * 输出有序 findings。替换动作由 redact.ts 配合 vault 完成。
 */
import {
  ASSIGNMENT_REGEX,
  EXCLUDED_KEY_PATTERN,
  SENSITIVE_KEY_PATTERN,
  SIGNATURES,
  isPlaceholderValue,
  shannonEntropy,
  type Signature,
} from './patterns.js'

export interface Finding {
  /** span 在原文中的起始偏移。 */
  start: number
  /** span 长度。 */
  length: number
  /** 类别：签名 id 或 'sensitive-value'。 */
  category: string
  /** 命中来源。 */
  source: 'signature' | 'key-assignment' | 'custom'
}

export interface CompiledCustomRule {
  id: string
  regex: RegExp
}

export interface ScanOptions {
  builtinsEnabled?: boolean
  customRules?: CompiledCustomRule[]
  /** 值级豁免（来自 rules.json allow.values / 基线外的精确豁免）。返回 true 则丢弃该命中。 */
  isAllowed?: (secret: string) => boolean
}

interface RawHit {
  start: number
  end: number
  category: string
  source: Finding['source']
  /** 同长度时的排序权重：签名 > 键名。 */
  priority: number
}

function* signatureHits(text: string, sigs: Signature[], options_: ScanOptions): Generator<RawHit> {
  for (const sig of sigs) {
    sig.regex.lastIndex = 0
    for (const m of text.matchAll(sig.regex)) {
      const span = m[0]
      if (span.length === 0) continue
      if (sig.validate && !sig.validate(span)) continue
      if (sig.entropyMin !== undefined && shannonEntropy(span) < sig.entropyMin) continue
      if (options_.isAllowed?.(span)) continue
      yield { start: m.index, end: m.index + span.length, category: sig.id, source: 'signature', priority: 2 }
    }
  }
}

function* assignmentHits(text: string, options: ScanOptions): Generator<RawHit> {
  for (const m of text.matchAll(ASSIGNMENT_REGEX)) {
    const key = m[1]
    const value = m[2]
    if (!SENSITIVE_KEY_PATTERN.test(key)) continue
    if (EXCLUDED_KEY_PATTERN.test(key)) continue
    if (isPlaceholderValue(value)) continue
    if (options.isAllowed?.(value)) continue
    const valueStart = m.index + m[0].length - value.length
    yield {
      start: valueStart,
      end: valueStart + value.length,
      category: 'sensitive-value',
      source: 'key-assignment',
      priority: 1,
    }
  }
}

function* customHits(text: string, rules: CompiledCustomRule[]): Generator<RawHit> {
  for (const rule of rules) {
    rule.regex.lastIndex = 0
    for (const m of text.matchAll(rule.regex)) {
      if (m[0].length === 0) continue
      yield { start: m.index, end: m.index + m[0].length, category: `custom:${rule.id}`, source: 'custom', priority: 3 }
    }
  }
}

/** 去重叠：按 start 升序、end 降序、priority 降序排，贪心保留互不重叠的最长 span。 */
function dedupe(hits: RawHit[]): RawHit[] {
  const sorted = [...hits].sort((a, b) =>
    a.start - b.start || b.end - a.end || b.priority - a.priority)
  const kept: RawHit[] = []
  let lastEnd = -1
  for (const hit of sorted) {
    if (hit.start >= lastEnd) {
      kept.push(hit)
      lastEnd = hit.end
    }
  }
  return kept
}

/** 扫描一段文本，返回按出现顺序排列的 findings（可能为空）。 */
export function scan(text: string, options: ScanOptions = {}): Finding[] {
  const { builtinsEnabled = true, customRules = [] } = options
  const hits: RawHit[] = []
  for (const hit of customHits(text, customRules)) hits.push(hit)
  if (builtinsEnabled) {
    for (const hit of signatureHits(text, SIGNATURES, options)) hits.push(hit)
    for (const hit of assignmentHits(text, options)) hits.push(hit)
  }
  return dedupe(hits).map((h) => ({
    start: h.start, length: h.end - h.start, category: h.category, source: h.source,
  }))
}
