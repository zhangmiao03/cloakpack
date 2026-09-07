/**
 * cloakpack — git 子进程封装（零依赖，全部走 spawnSync）。
 */
import { spawnSync } from 'node:child_process'
import { chmodSync, existsSync, readFileSync, unlinkSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

export interface GitResult {
  ok: boolean
  stdout: string
  stderr: string
}

export function git(args: string[], cwd: string): GitResult {
  const r = spawnSync('git', args, { cwd, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 })
  return { ok: r.status === 0, stdout: r.stdout ?? '', stderr: r.stderr ?? '' }
}

/** 是否在 git 仓库内（git rev-parse --show-toplevel 成功即返回根，否则 null）。 */
export function repoRoot(cwd: string): string | null {
  const r = git(['rev-parse', '--show-toplevel'], cwd)
  return r.ok ? r.stdout.trim() : null
}

/** git 跟踪的文件列表（工作区视角）。 */
export function trackedFiles(cwd: string): string[] {
  const r = git(['ls-files', '-z'], cwd)
  if (!r.ok) throw new Error(`git ls-files 失败: ${r.stderr}`)
  return r.stdout.split('\0').filter(Boolean)
}

/**
 * 某个 commit 树里的文件内容（git cat-file --batch 不便按路径取，
 * 这里用 show）。返回 Buffer 或 null（文件不存在/过大由调用方限制）。
 */
export function blobAt(cwd: string, sha: string, path: string): Buffer | null {
  const r = spawnSync('git', ['show', `${sha}:${path}`], { cwd, encoding: 'buffer', maxBuffer: 16 * 1024 * 1024 })
  return r.status === 0 ? r.stdout : null
}

/** 某个 commit 树的文件列表（默认输出 `mode type object TAB path`，全版本兼容）。 */
export function treeFiles(cwd: string, sha: string): Array<{ path: string; mode: string }> {
  const r = git(['ls-tree', '-r', '-z', sha], cwd)
  if (!r.ok) throw new Error(`git ls-tree 失败: ${r.stderr}`)
  return r.stdout.split('\0').filter(Boolean).map((line) => {
    const tab = line.indexOf('\t')
    if (tab < 0) return null
    const mode = line.slice(0, tab).split(/\s+/)[0]
    return { mode, path: line.slice(tab + 1) }
  }).filter((x): x is { path: string; mode: string } => x !== null)
}

/** pre-push 钩子 stdin 行：local_ref local_sha remote_ref remote_sha。 */
export interface PushLine {
  localRef: string
  localSha: string
  remoteRef: string
  remoteSha: string
}

export function parsePushStdin(input: string): PushLine[] {
  return input
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean)
    .map((line) => {
      const [localRef, localSha, remoteRef, remoteSha] = line.split(/\s+/)
      return { localRef, localSha, remoteRef, remoteSha }
    })
    .filter((l) => l.localRef && l.localSha)
}

/** 某密钥是否出现在当前分支历史（git log --all -S，限定数量防慢）。 */
export function secretInHistory(cwd: string, secret: string, limitSeconds = 10): { found: boolean; commits: string[] } {
  const r = spawnSync(
    'git',
    ['log', '--all', '--oneline', '-S', secret, '--', '.'],
    { cwd, encoding: 'utf8', timeout: limitSeconds * 1000, maxBuffer: 8 * 1024 * 1024 },
  )
  if (r.status !== 0 || !r.stdout) return { found: false, commits: [] }
  const commits = r.stdout.split('\n').filter(Boolean)
  return { found: commits.length > 0, commits }
}

export const HOOK_PATH = '.git/hooks/pre-push'
export const HOOK_MARKER = '# cloakpack-managed'

/** 安装 pre-push 钩子（保留已有内容：有则拒绝并提示手动合并）。返回状态说明。 */
export function installHook(cwd: string): 'installed' | 'exists-managed' | 'exists-foreign' {
  const r = git(['rev-parse', '--git-path', 'hooks'], cwd)
  if (!r.ok) return 'exists-foreign'
  const hookFile = join(cwd, r.stdout.trim(), 'pre-push')
  if (existsSync(hookFile)) {
    const current = readFileSync(hookFile, 'utf8')
    if (current.includes(HOOK_MARKER)) return 'exists-managed'
    return 'exists-foreign'
  }
  writeFileSync(hookFile, `#!/bin/sh
${HOOK_MARKER}
# 由 cloakpack init 写入：推送前扫描将离开本机的文件树，命中密钥即阻断。
# 跳过本次检查：git push --no-verify（请确认你知道自己在做什么）。
command -v cloakpack >/dev/null 2>&1 || {
  echo "[cloakpack] 未找到 cloakpack 命令，跳过检查（fail-open）。npm i -g cloakpack 恢复。" >&2
  exit 0
}
exec cloakpack guard --pre-push
`)
  chmodSync(hookFile, 0o755)
  return 'installed'
}

export function removeHook(cwd: string): boolean {
  const r = git(['rev-parse', '--git-path', 'hooks'], cwd)
  if (!r.ok) return false
  const hookFile = join(cwd, r.stdout.trim(), 'pre-push')
  if (!existsSync(hookFile)) return false
  if (!readFileSync(hookFile, 'utf8').includes(HOOK_MARKER)) return false
  unlinkSync(hookFile)
  return true
}
