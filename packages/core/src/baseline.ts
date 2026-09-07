/**
 * cloakpack core — 基线（detect-secrets 同型工作流）：
 * 「存量入册不再拦，新密钥必须拦」。基线只存指纹（sha256(file+category+secret)），
 * 不存明文。`cloakpack scan --update-baseline` 重建。
 */
import { createHash } from 'node:crypto'
import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs'
import { join } from 'node:path'

export const BASELINE_FILE = join('.cloakpack', 'baseline.json')

const sha = (s: string): string => createHash('sha256').update(s).digest('hex')

/** 一条命中的不可逆指纹（不含明文）。 */
export function baselineKey(file: string, category: string, secret: string): string {
  return sha(`${file}\0${category}\0${sha(secret)}`)
}

export function loadBaseline(root: string): Set<string> {
  const file = join(root, BASELINE_FILE)
  if (!existsSync(file)) return new Set()
  try {
    const parsed = JSON.parse(readFileSync(file, 'utf8')) as { findings?: string[] }
    return new Set(Array.isArray(parsed.findings) ? parsed.findings : [])
  } catch {
    return new Set()
  }
}

export function saveBaseline(root: string, keys: Iterable<string>): number {
  const arr = [...new Set(keys)]
  mkdirSync(join(root, '.cloakpack'), { recursive: true })
  writeFileSync(join(root, BASELINE_FILE), `${JSON.stringify({ version: 1, findings: arr }, null, 2)}\n`)
  return arr.length
}
