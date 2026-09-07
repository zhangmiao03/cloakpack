import { describe, expect, it, beforeAll } from 'vitest'
import { execFileSync, spawnSync } from 'node:child_process'
import { mkdtempSync, rmSync, mkdirSync, writeFileSync, readFileSync, existsSync, chmodSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const cliJs = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..', 'packages', 'cli', 'lib', 'cli.js')

let home = ''
let binDir = ''

/** 直接调 CLI（绕过钩子场景）。 */
function cli(args: string[], cwd: string) {
  return spawnSync('node', [cliJs, ...args], { cwd, encoding: 'utf8', env: { ...process.env, HOME: home } })
}

beforeAll(() => {
  home = mkdtempSync(join(tmpdir(), 'cloakpack-e2e-home-'))
  binDir = mkdtempSync(join(tmpdir(), 'cloakpack-e2e-bin-'))
  // 真实钩子脚本里调用的是 `cloakpack` 命令：临时 bin 做个转发，PATH 前置
  const shim = join(binDir, 'cloakpack')
  writeFileSync(shim, `#!/bin/sh\nexec node "${cliJs}" "$@"\n`)
  chmodSync(shim, 0o755)
})

function sh(cmd: string, cwd: string, extraEnv: Record<string, string> = {}) {
  return execFileSync('sh', ['-c', cmd], {
    cwd, encoding: 'utf8',
    env: { ...process.env, HOME: home, PATH: `${binDir}:${process.env.PATH}`, ...extraEnv },
  })
}

describe('E2E：pre-push 阻断 → pack → 再推过 → unpack 还原', () => {
  it('完整流程（本地裸远端）', () => {
    const dir = mkdtempSync(join(tmpdir(), 'cloakpack-e2e-'))
    const remote = `${dir}/remote.git`
    const repo = `${dir}/work`
    try {
      execFileSync('git', ['init', '--bare', '-b', 'main', remote])
      execFileSync('git', ['init', '-b', 'main', repo], { env: { ...process.env, HOME: home } })
      sh('git config user.email t@example.com && git config user.name t', repo)

      // 1) 植入密钥
      writeFileSync(join(repo, 'README.md'), '# demo project\n')
      writeFileSync(join(repo, '.env'), [
        'PORT=3000',
        `DEEPSEEK_API_KEY=${['sk-0123456789abcdef', '0123456789abcdef'].join('')}`,
        'DATABASE_URL=postgres://admin:S3cretPass@db.example.com:5432/prod',
      ].join('\n'))
      mkdirSync(join(repo, 'config'))
      writeFileSync(join(repo, 'config', 'app.yaml'), 'name: demo\npassword: Sup3rS3cretValue\n')
      sh('git add -A && git commit -m init', repo)

      // 2) init：装钩子 + gitignore 保险库
      const init = cli(['init'], repo)
      expect(init.status, init.stderr).toBe(0)
      expect(existsSync(join(repo, '.git', 'hooks', 'pre-push'))).toBe(true)
      expect(readFileSync(join(repo, '.gitignore'), 'utf8')).toContain('.cloakpack/')

      // 3) 推送 → 被阻断
      const push1 = spawnSync('git', ['push', remote, 'main'], {
        cwd: repo, encoding: 'utf8',
        env: { ...process.env, HOME: home, PATH: `${binDir}:${process.env.PATH}` },
      })
      expect(push1.status, `应被阻断，实际输出: ${push1.stdout}${push1.stderr}`).not.toBe(0)
      expect(push1.stderr).toContain('阻断')
      expect(push1.stderr).toContain('.env')

      // 4) pack：文件换占位符、密钥进加密库、自动暂存（密钥在历史里 → 有警告但不影响退出码）
      const pack = cli(['pack'], repo)
      expect(pack.status, pack.stderr).toBe(0)
      expect(pack.stderr).toContain('轮换')
      const envPacked = readFileSync(join(repo, '.env'), 'utf8')
      expect(envPacked).toContain('⟦cloak:deepseek-api-key:1⟧')
      expect(envPacked).not.toContain('0123456789abcdef0123456789abcdef')
      expect(readFileSync(join(repo, 'config', 'app.yaml'), 'utf8')).toContain('⟦cloak:sensitive-value:1⟧')
      expect(existsSync(join(repo, '.cloakpack', 'vault.bin'))).toBe(true)

      // 5) 提交并再推 → 通过；远端树确实干净
      sh('git add -A && git commit -m "cloak: pack secrets"', repo)
      const push2 = spawnSync('git', ['push', remote, 'main'], {
        cwd: repo, encoding: 'utf8',
        env: { ...process.env, HOME: home, PATH: `${binDir}:${process.env.PATH}` },
      })
      expect(push2.status, `应放行，实际: ${push2.stdout}${push2.stderr}`).toBe(0)
      const remoteEnv = sh(`git --git-dir=${remote} show HEAD:.env`, repo)
      expect(remoteEnv).toContain('⟦cloak:deepseek-api-key:1⟧')
      expect(remoteEnv).not.toContain('0123456789abcdef0123456789abcdef')

      // 6) unpack：本机还原
      const unpack = cli(['unpack'], repo)
      expect(unpack.status, unpack.stderr).toBe(0)
      expect(readFileSync(join(repo, '.env'), 'utf8')).toContain('0123456789abcdef0123456789abcdef')
      expect(readFileSync(join(repo, 'config', 'app.yaml'), 'utf8')).toContain('Sup3rS3cretValue')
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  it('--no-verify 是显式逃生门', () => {
    const dir = mkdtempSync(join(tmpdir(), 'cloakpack-e2e-'))
    const remote = `${dir}/remote.git`
    const repo = `${dir}/work`
    try {
      execFileSync('git', ['init', '--bare', '-b', 'main', remote])
      execFileSync('git', ['init', '-b', 'main', repo], { env: { ...process.env, HOME: home } })
      sh('git config user.email t@example.com && git config user.name t', repo)
      writeFileSync(join(repo, 'a.env'), `KEY=${['sk-0123456789abcdef', '0123456789abcdef'].join('')}\n`)
      sh('git add -A && git commit -m init', repo)
      expect(cli(['init'], repo).status).toBe(0)
      const push = spawnSync('git', ['push', '--no-verify', remote, 'main'], {
        cwd: repo, encoding: 'utf8',
        env: { ...process.env, HOME: home, PATH: `${binDir}:${process.env.PATH}` },
      })
      expect(push.status, push.stderr).toBe(0)
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  it('scan：命中退出码 1，干净仓库退出码 0', () => {
    const dirty = mkdtempSync(join(tmpdir(), 'cloakpack-e2e-'))
    try {
      execFileSync('git', ['init', '-b', 'main', dirty], { env: { ...process.env, HOME: home } })
      sh('git config user.email t@example.com && git config user.name t', dirty)
      writeFileSync(join(dirty, 'k.env'), `KEY=${['sk-0123456789abcdef', '0123456789abcdef'].join('')}\n`)
      sh('git add -A && git commit -m init', dirty)
      expect(cli(['scan'], dirty).status).toBe(1)

      const clean = mkdtempSync(join(tmpdir(), 'cloakpack-e2e-'))
      execFileSync('git', ['init', '-b', 'main', clean], { env: { ...process.env, HOME: home } })
      sh('git config user.email t@example.com && git config user.name t', clean)
      writeFileSync(join(clean, 'README.md'), 'hello\n')
      sh('git add -A && git commit -m init', clean)
      expect(cli(['scan'], clean).status).toBe(0)
      rmSync(clean, { recursive: true, force: true })
    } finally {
      rmSync(dirty, { recursive: true, force: true })
    }
  })
})
