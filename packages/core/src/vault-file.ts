/**
 * cloakpack — 文件型加密保险库：placeholder ↔ 密钥原值 的持久映射。
 *
 * 整库 AES-256-GCM 加密落盘（.cloakpack/vault.bin），密钥是 32 字节随机
 * keyfile 存 ~/.cloakpack/keys/（0600，仅本机本用户）。路径引用写在项目
 * .cloakpack/config.json（明文，只含 key id，不含密钥）。
 *
 * 威胁模型（诚实声明）：防的是项目目录离开本机（分享/拷贝/丢失/U盘），
 * 不防同机同用户下的恶意软件（它能读 keyfile，与 1Password 本地模型同级）。
 */
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, writeFileSync, chmodSync, readlinkSync, statSync, unlinkSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'

export const PROJECT_DIR = '.cloakpack'
export const VAULT_FILE = join(PROJECT_DIR, 'vault.bin')
export const CONFIG_FILE = join(PROJECT_DIR, 'config.json')

/** 惰性求值：homedir() 跟随 env.HOME，测试可隔离。 */
export const keysRoot = (): string => join(homedir(), '.cloakpack', 'keys')

export interface VaultEntry {
  placeholder: string
  category: string
  /** 密钥原值（只存在于加密库中）。 */
  secret: string
  /** 打包时该密钥出现的相对文件路径列表（审计线索，可选）。 */
  files: string[]
  createdAt: number
}

interface VaultPayload {
  version: 1
  entries: VaultEntry[]
}

const keyfilePath = (keyId: string): string => join(keysRoot(), `${keyId}.key`)

function loadOrCreateKey(keyId: string): Buffer {
  mkdirSync(keysRoot(), { recursive: true })
  const file = keyfilePath(keyId)
  if (existsSync(file)) {
    const key = readFileSync(file)
    if (key.length === 32) return key
    throw new Error(`keyfile ${file} 损坏（长度 ${key.length}，应为 32）`)
  }
  const key = randomBytes(32)
  writeFileSync(file, key)
  chmodSync(file, 0o600)
  return key
}

function encrypt(plain: string, key: Buffer): Buffer {
  const iv = randomBytes(12)
  const cipher = createCipheriv('aes-256-gcm', key, iv)
  const body = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()])
  return Buffer.concat([iv, cipher.getAuthTag(), body])
}

function decrypt(blob: Buffer, key: Buffer): string {
  const iv = blob.subarray(0, 12)
  const tag = blob.subarray(12, 28)
  const body = blob.subarray(28)
  const decipher = createDecipheriv('aes-256-gcm', key, iv)
  decipher.setAuthTag(tag)
  return Buffer.concat([decipher.update(body), decipher.final()]).toString('utf8')
}

/** 读项目 .cloakpack/config.json（仓库根为 cwd）。不存在返回 undefined。 */
export function loadProjectConfig(root: string): { keyId: string } | undefined {
  const file = join(root, CONFIG_FILE)
  if (!existsSync(file)) return undefined
  const parsed = JSON.parse(readFileSync(file, 'utf8')) as { keyId?: string }
  if (!parsed.keyId) throw new Error(`${CONFIG_FILE} 缺少 keyId`)
  return { keyId: parsed.keyId }
}

export class Vault {
  private entries = new Map<string, VaultEntry>()
  private key: Buffer
  private keyId: string

  private constructor(keyId: string, key: Buffer, payload?: VaultPayload) {
    this.keyId = keyId
    this.key = key
    for (const e of payload?.entries ?? []) this.entries.set(e.placeholder, e)
  }

  /** 打开（或初始化）项目保险库。root = 仓库根。 */
  static open(root: string): Vault {
    const config = loadProjectConfig(root)
    const keyId = config?.keyId ?? randomBytes(8).toString('hex')
    const key = loadOrCreateKey(keyId)
    const vaultFile = join(root, VAULT_FILE)
    let payload: VaultPayload | undefined
    if (existsSync(vaultFile)) {
      payload = JSON.parse(decrypt(readFileSync(vaultFile), key)) as VaultPayload
    } else {
      mkdirSync(join(root, PROJECT_DIR), { recursive: true })
      if (!config) writeFileSync(join(root, CONFIG_FILE), `${JSON.stringify({ keyId }, null, 2)}\n`)
    }
    return new Vault(keyId, key, payload)
  }

  /** 同一密钥稳定复用同一占位符（与 dsh-cloak vault 语义一致）。 */
  placeholderFor(secret: string, category: string, file: string): string {
    for (const e of this.entries.values()) {
      if (e.secret === secret) {
        if (!e.files.includes(file)) e.files.push(file)
        return e.placeholder
      }
    }
    const n = [...this.entries.values()].filter((e) => e.category === category).length + 1
    const placeholder = `⟦cloak:${category}:${n}⟧`
    this.entries.set(placeholder, { placeholder, category, secret, files: [file], createdAt: Date.now() })
    return placeholder
  }

  /** 占位符 → 原值。未知占位符返回 undefined。 */
  reveal(placeholder: string): string | undefined {
    return this.entries.get(placeholder)?.secret
  }

  list(): Array<{ placeholder: string; category: string; files: string[] }> {
    return [...this.entries.values()].map((e) => ({ placeholder: e.placeholder, category: e.category, files: e.files }))
  }

  get size(): number {
    return this.entries.size
  }

  save(root: string): void {
    const payload: VaultPayload = { version: 1, entries: [...this.entries.values()] }
    writeFileSync(join(root, VAULT_FILE), encrypt(JSON.stringify(payload), this.key))
  }
}

/** 定位仓库根（向上找 .git），找不到抛错。跟随 symlink 但防循环。 */
export function findRepoRoot(start: string): string {
  const seen = new Set<string>()
  let dir = start
  while (true) {
    const real = realpathSafe(dir)
    if (seen.has(real)) throw new Error('目录遍历检测到循环，放弃查找 .git')
    seen.add(real)
    const gitPath = join(dir, '.git')
    if (existsSync(gitPath)) {
      const st = statSync(gitPath)
      if (st.isDirectory() || st.isFile()) return dir // 子模块的 .git 是文件
    }
    const parent = join(dir, '..')
    if (parent === dir) throw new Error(`未找到 git 仓库根（从 ${start} 向上）`)
    dir = parent
  }
}

function realpathSafe(p: string): string {
  try {
    return readlinkSync(p)
  } catch {
    return p
  }
}

/** 危险兜底：销毁 keyfile 与库文件（不可逆，只在用户显式要求时调用）。 */
export function destroyAll(root: string): void {
  const config = loadProjectConfig(root)
  if (config?.keyId) {
    const kf = keyfilePath(config.keyId)
    if (existsSync(kf)) unlinkSync(kf)
  }
  const vaultFile = join(root, VAULT_FILE)
  if (existsSync(vaultFile)) unlinkSync(vaultFile)
  if (existsSync(join(root, CONFIG_FILE))) unlinkSync(join(root, CONFIG_FILE))
}
