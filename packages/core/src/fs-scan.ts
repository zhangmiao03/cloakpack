/**
 * cloakpack — 文件系统扫描与替换：把 scan() 的 findings 映射到
 * 文件:行号，以及在文件内容上执行「原值 → 占位符」/ 反向替换。
 */
import { readFileSync, writeFileSync } from 'node:fs'
import { INLINE_MARKER } from './allowlist.js'
import { scan, type Finding, type ScanOptions } from './scan.js'

/** 单文件内的一条命中（带 1-based 行号）。 */
export interface FileFinding extends Finding {
  file: string
  line: number
}

/** 扫一段文本，返回带行号的命中（行号按 finding.start 计算，1-based）。 */
export function scanText(text: string, options?: ScanOptions): Array<Finding & { line: number }> {
  const findings = scan(text, options)
  if (findings.length === 0) return []
  // 行号：统计每个 start 前的换行数（findings 已按 start 升序，可增量推进）。
  const out: Array<Finding & { line: number }> = []
  let idx = 0
  let line = 1
  let lineStart = 0
  let lineText = ''
  for (const f of findings) {
    while (idx < f.start) {
      if (text.charCodeAt(idx) === 10 /* \n */) {
        line += 1
        idx += 1
        lineStart = idx
        lineText = ''
      } else {
        idx += 1
      }
    }
    // 行内豁免：该行包含 cloakpack:allow 标记（gitleaks:allow 同型）
    if (lineText === '') lineText = text.slice(lineStart, text.indexOf('\n', lineStart) === -1 ? undefined : text.indexOf('\n', lineStart))
    if (lineText.includes(INLINE_MARKER)) continue
    out.push({ ...f, line })
  }
  return out
}

/** 判断内容是否疑似二进制（前 8KB 含 NUL）。 */
export function looksBinary(buf: Buffer): boolean {
  return buf.subarray(0, 8192).includes(0)
}

/** 扫一个文件（utf8 文本，二进制跳过）。返回命中或 null。 */
export function scanFile(path: string, options?: ScanOptions, maxBytes = 2 * 1024 * 1024): FileFinding[] | null {
  let buf: Buffer
  try {
    buf = readFileSync(path)
  } catch {
    return null
  }
  if (buf.length === 0 || buf.length > maxBytes || looksBinary(buf)) return null
  const text = buf.toString('utf8')
  return scanText(text, options).map((f) => ({ ...f, file: path }))
}

/** 打码一个文件：命中原值 → vault 占位符，从后往前替换。返回 (file, finding, placeholder) 列表。 */
export function packText(
  text: string,
  file: string,
  placeholderFor: (secret: string, category: string, file: string) => string,
  options?: ScanOptions,
): { text: string; changes: Array<Finding & { line: number; placeholder: string }> } {
  const findings = scanText(text, options)
  if (findings.length === 0) return { text, changes: [] }
  const enriched = findings.map((f) => ({
    ...f,
    placeholder: placeholderFor(text.slice(f.start, f.start + f.length), f.category, file),
  }))
  let out = text
  for (let i = enriched.length - 1; i >= 0; i -= 1) {
    const f = enriched[i]
    out = out.slice(0, f.start) + f.placeholder + out.slice(f.start + f.length)
  }
  return { text: out, changes: enriched }
}

/** 还原一个文本：占位符 → 原值。未知占位符原样保留。 */
export function unpackText(
  text: string,
  reveal: (placeholder: string) => string | undefined,
): { text: string; count: number } {
  let count = 0
  const out = text.replace(/⟦cloak:[^⟧:]+:\d+⟧/g, (ph) => {
    const secret = reveal(ph)
    if (secret === undefined) return ph
    count += 1
    return secret
  })
  return { text: out, count }
}
