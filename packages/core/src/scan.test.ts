import { describe, expect, it } from 'vitest'
import { scan } from './scan.js'
import { deepseekKey } from './fixtures.js'

describe('scan：组合扫描', () => {
  it('.env 文件：敏感变量值被打码，普通变量保留', () => {
    const env = [
      '# project config',
      'export DATABASE_URL="postgres://admin:S3cretPass@db.io/x"',
      `DEEPSEEK_API_KEY=${deepseekKey}`,
      'GITHUB_TOKEN=ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      'PORT=3000',
      'LOG_LEVEL=info',
    ].join('\n')
    const findings = scan(env)
    const cats = findings.map((f) => f.category)
    expect(cats).toContain('db-connection-url')
    expect(cats).toContain('deepseek-api-key')
    expect(cats).toContain('github-token')
    // PORT / LOG_LEVEL 不命中
    expect(findings.filter((f) => env.slice(f.start, f.start + f.length).includes('3000'))).toHaveLength(0)
  })

  it('JSON：敏感键值命中，分页 token 保留', () => {
    const json = JSON.stringify({
      api_key: 'fakekey_abc123XYZ456',
      next_token: 'eyJwYWdlIjoxfQ.fake.sig1234',
      data: [{ access_key: 'AKIAIOSFODNN7EXAMPLE' }],
    })
    const findings = scan(json)
    const cats = findings.map((f) => f.category)
    expect(cats).toContain('sensitive-value') // api_key
    expect(cats).toContain('aws-access-key')
    // next_token 被排除键规则豁免
    expect(json.includes('next_token') && !cats.includes('jwt')).toBe(true)
  })

  it('占位值不打码：${VAR} / changeme / true / 短值', () => {
    const text = [
      'password: ${DB_PASSWORD}',
      'secret: changeme',
      'api_key: "xxxxxxxx"',
      'token: true',
      'pwd: abc123',
    ].join('\n')
    expect(scan(text)).toHaveLength(0)
  })

  it('重叠时最长匹配胜出：Bearer 头内的 JWT 只报一次', () => {
    const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c'
    const text = `Authorization: Bearer ${jwt}`
    const findings = scan(text)
    // bearer-header span 覆盖了 jwt span：保留更长者
    const cats = findings.map((f) => f.category)
    expect(cats).toContain('bearer-header')
    expect(cats).not.toContain('jwt')
  })

  it('findings 按 start 升序且互不重叠', () => {
    const text = [
      'key=AKIAIOSFODNN7EXAMPLE',
      '中间普通文本',
      'token ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA tail',
      'postgres://u:S3cretPw@host/db',
    ].join('\n')
    const findings = scan(text)
    expect(findings.length).toBeGreaterThanOrEqual(3)
    let prevEnd = -1
    for (const f of findings) {
      expect(f.start).toBeGreaterThan(prevEnd)
      prevEnd = f.start + f.length
    }
  })

  it('空文本与无命中文本返回空', () => {
    expect(scan('')).toHaveLength(0)
    expect(scan('hello world, nothing secret here')).toHaveLength(0)
  })

  it('builtinsEnabled=false 时仅自定义规则生效', () => {
    const text = 'AKIAIOSFODNN7EXAMPLE zzz-inner-secret-zzz'
    const none = scan(text, { builtinsEnabled: false })
    expect(none).toHaveLength(0)
    const custom = scan(text, {
      builtinsEnabled: false,
      customRules: [{ id: 'inner', regex: /zzz-[a-z]+-secret-zzz/g }],
    })
    expect(custom.map((f) => f.category)).toEqual(['custom:inner'])
  })
})
