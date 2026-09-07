/**
 * cloakpack core — 豁免机制（gitleaks:allow 同型）。
 *
 * 三层：行内标记（`cloakpack:allow` 注释豁免该行）、路径 glob、精确值。
 * 路径与值来自项目 .cloakpack/rules.json 的 allow 段。
 */

/** 行内豁免标记：该行包含此串时，整行命中被抑制。 */
export const INLINE_MARKER = 'cloakpack:allow'

/** 极简 glob → RegExp：仅支持 `*`（段内任意）与 `**`（跨段任意）。 */
export function globToRegExp(glob: string): RegExp {
  const escaped = glob.replace(/[.+?^${}()|[\]\\]/g, '\\$&')
    .replace(/\*\*/g, '\u0000')
    .replace(/\*/g, '[^/]*')
    .replace(/\u0000/g, '.*')
  return new RegExp(`^${escaped}$`)
}

export interface AllowConfig {
  /** 相对仓库根的路径 glob（支持 * 与 ** 段通配），如测试目录、文档示例文件。 */
  paths?: string[]
  /** 精确原值豁免（如示例密钥 AKIAIOSFODNN7EXAMPLE）。 */
  values?: string[]
}

export function makePathAllower(paths: string[] | undefined): (relPath: string) => boolean {
  if (!paths || paths.length === 0) return () => false
  const regexes = paths.map(globToRegExp)
  return (rel: string) => regexes.some((re) => re.test(rel))
}

export function makeValueAllower(values: string[] | undefined): (secret: string) => boolean {
  if (!values || values.length === 0) return () => false
  const set = new Set(values)
  return (secret: string) => set.has(secret)
}
