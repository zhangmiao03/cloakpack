#!/usr/bin/env node
/**
 * cloakpack CLI — 密钥安全包。
 *
 * 用法：
 *   cloakpack init              安装 git pre-push 守卫（并 gitignore 保险库）
 *   cloakpack scan              扫描工作区已跟踪文件，命中即退出码 1
 *   cloakpack pack [--dry-run]  密钥 → 本机加密保险库，文件替换占位符，git add
 *   cloakpack unpack            占位符 → 原值（本机还原）
 *   cloakpack guard --pre-push  pre-push 钩子内部入口：扫将离开本机的树
 *   cloakpack unhook            移除钩子
 */
import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import {
  packText, scanFile, scanText, unpackText, type FileFinding, type ScanOptions,
  Vault, git, repoRoot, trackedFiles, treeFiles, blobAt, parsePushStdin, installHook, removeHook, secretInHistory,
  makePathAllower, makeValueAllower, type AllowConfig,
  baselineKey, loadBaseline, saveBaseline,
} from '@cloakpack/core'

function die(msg: string, code = 1): never {
  console.error(`[cloakpack] ${msg}`)
  process.exit(code)
}

function info(msg: string): void {
  console.log(`[cloakpack] ${msg}`)
}

const RULES_FILE = '.cloakpack/rules.json'

interface EffectiveOptions {
  scan: ScanOptions
  pathAllowed: (rel: string) => boolean
}

function loadScanOptions(root: string): EffectiveOptions {
  const file = join(root, RULES_FILE)
  const customRules: Array<{ id: string; regex: RegExp }> = []
  let allow: AllowConfig = {}
  if (existsSync(file)) {
    try {
      const raw = JSON.parse(readFileSync(file, 'utf8')) as unknown
      const parsed = (Array.isArray(raw) ? { rules: raw } : raw) as {
        rules?: Array<{ id: string; pattern: string; flags?: string }>
        allow?: AllowConfig
      }
      for (const r of parsed.rules ?? []) {
        if (r?.id && r?.pattern) customRules.push({ id: r.id, regex: new RegExp(r.pattern, r.flags ?? 'g') })
      }
      allow = parsed.allow ?? {}
    } catch (e) {
      die(`配置文件 ${RULES_FILE} 解析失败: ${e instanceof Error ? e.message : String(e)}`)
    }
  }
  return {
    scan: { builtinsEnabled: true, customRules, isAllowed: makeValueAllower(allow.values) },
    pathAllowed: makePathAllower(allow.paths),
  }
}

/** 基线过滤：命中指纹已入册的（文件,类别,原值）不拦。 */
function notInBaseline(baseline: Set<string>): (file: string, category: string, secret: string) => boolean {
  return (file, category, secret) => !baseline.has(baselineKey(file, category, secret))
}

function ensureGitignore(root: string): void {
  const file = join(root, '.gitignore')
  let current = ''
  if (existsSync(file)) current = readFileSync(file, 'utf8')
  if (!current.split('\n').some((l) => l.trim() === '.cloakpack/')) {
    writeFileSync(file, current.endsWith('\n') || current === '' ? `${current}.cloakpack/\n` : `${current}\n.cloakpack/\n`)
    info('已将 .cloakpack/ 加入 .gitignore')
  }
}

function fmtFinding(f: FileFinding, root: string): string {
  const rel = f.file.startsWith(root) ? f.file.slice(root.length + 1) : f.file
  return `  ${rel}:${f.line}  ${f.category}（${f.source}）`
}

// ── init ──
function cmdInit(cwd: string): void {
  const root = repoRoot(cwd)
  if (!root) die('当前目录不在 git 仓库内')
  const state = installHook(root)
  if (state === 'exists-foreign') {
    die('已存在非 cloakpack 管理的 pre-push 钩子，为避免覆盖请手动合并（见 README）')
  }
  ensureGitignore(root)
  Vault.open(root) // 初始化密钥与 .cloakpack/config.json
  if (state === 'installed') info(`pre-push 守卫已安装（${join('.git', 'hooks', 'pre-push')}）`)
  else info('pre-push 守卫已是最新')
  info('完成。现在 git push 会先扫描将离开本机的文件树。')
}

// ── scan ──
function cmdScan(cwd: string, updateBaseline: boolean): void {
  const root = repoRoot(cwd)
  if (!root) die('当前目录不在 git 仓库内')
  const { scan: options, pathAllowed } = loadScanOptions(root)
  const baseline = loadBaseline(root)
  let total = 0
  const newKeys: string[] = []
  for (const rel of trackedFiles(root)) {
    if (rel.startsWith('.cloakpack/') || pathAllowed(rel)) continue
    const abs = join(root, rel)
    const findings = scanFile(abs, options)
    if (!findings) continue
    for (const f of findings) {
      const secret = readFileSync(abs, 'utf8').slice(f.start, f.start + f.length)
      const key = baselineKey(rel, f.category, secret)
      newKeys.push(key)
      if (baseline.has(key)) {
        console.log(`${fmtFinding(f, root)}  [baseline 已入册]`)
        continue
      }
      console.log(fmtFinding(f, root))
      total += 1
    }
  }
  if (updateBaseline) {
    const n = saveBaseline(root, newKeys)
    info(`基线已更新：${n} 条指纹入册（.cloakpack/baseline.json，不存明文）。入册项不再拦截，新密钥照拦。`)
    return
  }
  if (total === 0) {
    info(baseline.size > 0 ? '未发现新密钥（基线内命中不拦）。' : '未发现密钥。')
    return
  }
  console.error(`[cloakpack] 共 ${total} 处新命中。运行 cloakpack pack 一键收纳。`)
  process.exit(1)
}

// ── pack ──
function cmdPack(cwd: string, dryRun: boolean): void {
  const root = repoRoot(cwd)
  if (!root) die('当前目录不在 git 仓库内')
  const { scan: options, pathAllowed } = loadScanOptions(root)
  const baseline = loadBaseline(root)
  const vault = Vault.open(root)
  const changedFiles: string[] = []
  let total = 0
  for (const rel of trackedFiles(root)) {
    if (rel.startsWith('.cloakpack/') || pathAllowed(rel)) continue
    const abs = join(root, rel)
    const findings = scanFile(abs, options)
    if (!findings || findings.length === 0) continue
    const original = readFileSync(abs, 'utf8')
    const fresh = findings.filter((f) => !baseline.has(baselineKey(rel, f.category, original.slice(f.start, f.start + f.length))))
    if (fresh.length !== findings.length) info(`  ${rel}: ${findings.length - fresh.length} 处已入基线，跳过`)
    if (fresh.length === 0) continue
    const { text, changes } = packText(original, rel, (secret, category, file) => vault.placeholderFor(secret, category, file), options)
    if (changes.length === 0) continue
    total += changes.length
    changedFiles.push(rel)
    for (const c of changes) console.log(fmtFinding({ ...c, file: abs }, root) + `  → ${c.placeholder}`)
    if (!dryRun) {
      writeFileSync(abs, text)
      git(['add', '--', rel], root)
    }
  }
  if (total === 0) {
    info('无需打包：未发现密钥。')
    return
  }
  if (!dryRun) vault.save(root)
  const verb = dryRun ? '（dry-run，未写盘）' : ''
  info(`已收纳 ${total} 处密钥进本机加密保险库（.cloakpack/vault.bin）${verb}`)
  if (!dryRun) {
    info(`已暂存 ${changedFiles.length} 个文件。下一步：git commit -m "cloak: pack secrets" && git push`)
    checkHistoryWarning(root, vault)
  }
}

function checkHistoryWarning(root: string, vault: Vault): void {
  // 仅对每个唯一原值查一次 git log -S；数量多时只查前 5 个防慢。
  // 只警告不改退出码：警告是"必须轮换"的告知，打包本身已成功，
  // 置非零码会打断 `pack && git commit && git push` 链。
  const seen = new Set<string>()
  for (const entry of vault.list()) {
    const secret = vault.reveal(entry.placeholder)
    if (!secret || seen.has(secret)) continue
    seen.add(secret)
    if (seen.size > 5) break
    const h = secretInHistory(root, secret)
    if (h.found) {
      console.error(`[cloakpack] ⚠️  该密钥出现在历史提交（${h.commits.slice(0, 3).join(', ')}${h.commits.length > 3 ? '…' : ''}）。打包只清理当前文件——已出过门的密钥必须轮换！`)
    }
  }
}

// ── unpack ──
function cmdUnpack(cwd: string): void {
  const root = repoRoot(cwd)
  if (!root) die('当前目录不在 git 仓库内')
  const vaultFile = join(root, '.cloakpack', 'vault.bin')
  if (!existsSync(vaultFile)) die('没有可还原的保险库（.cloakpack/vault.bin 不存在）')
  const vault = Vault.open(root)
  let restored = 0
  const changedFiles: string[] = []
  for (const rel of trackedFiles(root)) {
    const abs = join(root, rel)
    let text: string
    try {
      text = readFileSync(abs, 'utf8')
    } catch {
      continue
    }
    if (!text.includes('⟦cloak:')) continue
    const { text: out, count } = unpackText(text, (ph) => vault.reveal(ph))
    if (count === 0) continue
    writeFileSync(abs, out)
    git(['add', '--', rel], root)
    changedFiles.push(rel)
    restored += count
  }
  if (restored === 0) die('未找到可还原的占位符')
  info(`已还原 ${restored} 处密钥（${changedFiles.length} 个文件，已暂存）。记得别把还原版推出去。`)
}

// ── guard --pre-push ──
function cmdGuardPrePush(cwd: string): void {
  const root = repoRoot(cwd)
  if (!root) process.exit(0) // 不在仓库里，无事可做
  const input = readFileSync(0, 'utf8')
  const lines = parsePushStdin(input)
  if (lines.length === 0) process.exit(0)
  const { scan: options, pathAllowed } = loadScanOptions(root)
  const baseline = loadBaseline(root)
  const hits: FileFinding[] = []
  for (const line of lines) {
    if (/^0+$/.test(line.localSha)) continue // 删除远端分支
    let files: Array<{ path: string; mode: string }>
    try {
      files = treeFiles(root, line.localSha)
    } catch (e) {
      // fail-open 但必须喊出来：取不到树就无法保证干净
      console.error(`[cloakpack] ⚠️ 无法读取 ${line.localRef} 的文件树（${e instanceof Error ? e.message : String(e)}），本次跳过该 ref 的检查。`)
      continue
    }
    for (const { path, mode } of files) {
      if (mode === '120000' || mode === '160000') continue // symlink / submodule
      if (path.startsWith('.cloakpack/') || pathAllowed(path)) continue
      const blob = blobAt(root, line.localSha, path)
      if (!blob || blob.length === 0 || blob.length > 2 * 1024 * 1024) continue
      if (blob.subarray(0, 8192).includes(0)) continue // 二进制
      const text = blob.toString('utf8')
      for (const f of scanText(text, options)) {
        const secret = text.slice(f.start, f.start + f.length)
        if (baseline.has(baselineKey(path, f.category, secret))) continue
        hits.push({ ...f, file: path })
      }
    }
  }
  if (hits.length === 0) process.exit(0)
  console.error('[cloakpack] ✋ 推送被阻断：将离开本机的文件树里发现密钥。')
  for (const f of hits.slice(0, 20)) console.error(fmtFinding(f, root))
  if (hits.length > 20) console.error(`  …另有 ${hits.length - 20} 处`)
  console.error('')
  console.error('[cloakpack] 一键收纳（密钥进本机加密库，文件换占位符，随后重新提交再推）：')
  console.error('    cloakpack pack && git commit -m "cloak: pack secrets" && git push')
  console.error('[cloakpack] 确认无风险强行推送（请真的知道自己在做什么）：')
  console.error('    git push --no-verify')
  // 额外：密钥若已在历史/远端，提示轮换
  const vaultExists = existsSync(join(root, '.cloakpack', 'vault.bin'))
  if (vaultExists) {
    const vault = Vault.open(root)
    checkHistoryWarning(root, vault)
  }
  process.exit(1)
}

// ── main ──
function main(argv: string[]): void {
  const [cmd, ...rest] = argv
  const cwd = process.cwd()
  switch (cmd) {
    case 'init': return cmdInit(cwd)
    case 'scan': return cmdScan(cwd, process.argv.includes('--update-baseline'))
    case 'pack': return cmdPack(cwd, rest.includes('--dry-run'))
    case 'unpack': return cmdUnpack(cwd)
    case 'guard':
      if (rest.includes('--pre-push')) return cmdGuardPrePush(cwd)
      die('guard 仅支持 --pre-push（内部入口）')
      break
    case 'unhook': {
      const root = repoRoot(cwd)
      if (!root) die('当前目录不在 git 仓库内')
      info(removeHook(root) ? 'pre-push 守卫已移除。' : '没有 cloakpack 管理的钩子。')
      return
    }
    case '--help':
    case '-h':
    case undefined:
      console.log('用法: cloakpack <init|scan|pack|unpack|unhook> [选项]\n  pack --dry-run  只报告不写盘')
      return
    default:
      die(`未知命令 ${cmd}（--help 查看用法）`, 2)
  }
}

main(process.argv.slice(2))
