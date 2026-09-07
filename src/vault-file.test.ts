import { describe, expect, it, beforeAll } from 'vitest'
import { mkdtempSync, rmSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Vault, keysRoot } from './vault-file.js'

// 测试隔离：HOME 指到临时目录（keysRoot() 惰性求值，会跟随 env.HOME）
const fakeHome = mkdtempSync(join(tmpdir(), 'cloakpack-home-'))
beforeAll(() => {
  process.env.HOME = fakeHome
})

describe('Vault（文件型加密保险库）', () => {
  it('open → placeholderFor → save → 重新 open 能还原', () => {
    const root = mkdtempSync(join(tmpdir(), 'cloakpack-repo-'))
    try {
      const v1 = Vault.open(root)
      const ph = v1.placeholderFor('AKIAIOSFODNN7EXAMPLE', 'aws-access-key', 'config/.env')
      expect(ph).toBe('⟦cloak:aws-access-key:1⟧')
      v1.save(root)

      const v2 = Vault.open(root)
      expect(v2.reveal(ph)).toBe('AKIAIOSFODNN7EXAMPLE')
      expect(v2.size).toBe(1)

      // 落盘的是密文：vault.bin 不含原值明文
      const raw = readFileSync(join(root, '.cloakpack', 'vault.bin'))
      expect(raw.includes('AKIAIOSFODNN7EXAMPLE')).toBe(false)
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  it('同一密钥稳定复用同一占位符；跨类别计数独立', () => {
    const root = mkdtempSync(join(tmpdir(), 'cloakpack-repo-'))
    try {
      const v = Vault.open(root)
      const a = v.placeholderFor('sk-0123456789abcdef0123456789abcdef', 'deepseek-api-key', 'a')
      const b = v.placeholderFor('sk-0123456789abcdef0123456789abcdef', 'deepseek-api-key', 'b')
      const c = v.placeholderFor('ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', 'github-token', 'b')
      expect(a).toBe(b)
      expect(a).toBe('⟦cloak:deepseek-api-key:1⟧')
      expect(c).toBe('⟦cloak:github-token:1⟧')
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  it('keyfile 落在 HOME/.cloakpack/keys 且权限 0600', () => {
    const root = mkdtempSync(join(tmpdir(), 'cloakpack-repo-'))
    try {
      Vault.open(root)
      const keysDir = keysRoot()
      const files = readdirSync(keysDir)
      expect(files.length).toBeGreaterThanOrEqual(1)
      const mode = statSync(join(keysDir, files[0])).mode & 0o777
      expect(mode).toBe(0o600)
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  it('密文被篡改（翻转一字节）→ 解密失败而非静默给错值', () => {
    const root = mkdtempSync(join(tmpdir(), 'cloakpack-repo-'))
    try {
      const v1 = Vault.open(root)
      v1.placeholderFor('ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', 'github-token', 'x')
      v1.save(root)
      const vaultPath = join(root, '.cloakpack', 'vault.bin')
      const raw = readFileSync(vaultPath)
      raw[raw.length - 5] ^= 0xff
      writeFileSync(vaultPath, raw)
      expect(() => Vault.open(root)).toThrow()
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })
})
