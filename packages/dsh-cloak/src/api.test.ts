import { describe, expect, it } from 'vitest'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { EventEmitter } from 'node:events'
import { Audit } from './audit.js'
import { createApiHandler } from './api.js'
import { createRedactor } from './redact.js'
import { SecretVault } from './vault.js'

class FakeReq extends EventEmitter {
  constructor(readonly method: string, readonly url: string, body?: string) {
    super()
    if (body !== undefined) {
      Promise.resolve().then(() => {
        this.emit('data', Buffer.from(body))
        this.emit('end')
      })
    } else {
      Promise.resolve().then(() => this.emit('end'))
    }
  }
}

class FakeRes {
  status = 0
  body = ''
  writeHead(status: number): void { this.status = status }
  end(data: string): void { this.body = data }
}

const makeHandler = () => {
  const audit = new Audit(50)
  audit.push({ ts: 1, tool: 'bash', action: 'redact', count: 2, categories: ['github-token'] })
  return createApiHandler({
    audit,
    redactor: createRedactor(new SecretVault(), {}),
    vault: new SecretVault(),
  })
}

const call = async (method: string, url: string, body?: string): Promise<FakeRes> => {
  const res = new FakeRes()
  await makeHandler()(new FakeReq(method, url, body) as unknown as IncomingMessage, res as unknown as ServerResponse)
  return res
}

describe('/cloak/api', () => {
  it('GET /stats 返回审计与 vault 统计', async () => {
    const res = await call('GET', '/cloak/api/stats')
    expect(res.status).toBe(200)
    const data = JSON.parse(res.body)
    expect(data.audit.total).toBe(1)
    expect(data.audit.byCategory['github-token']).toBe(1)
    expect(data.vault).toEqual({ agents: 0, secrets: 0 })
  })

  it('GET /recent 返回最近条目', async () => {
    const res = await call('GET', '/cloak/api/recent?limit=10')
    expect(res.status).toBe(200)
    expect(JSON.parse(res.body).entries).toHaveLength(1)
  })

  it('POST /test 试扫：报告类别与上下文预览，不泄漏完整原值', async () => {
    const secret = 'AKIAIOSFODNN7EXAMPLE'
    const res = await call('POST', '/cloak/api/test', JSON.stringify({ text: `prefix ${secret} suffix` }))
    expect(res.status).toBe(200)
    const data = JSON.parse(res.body)
    expect(data.count).toBe(1)
    expect(data.findings[0].category).toBe('aws-access-key')
    expect(data.findings[0].preview).toContain('███')
    expect(data.findings[0].preview).not.toContain(secret)
  })

  it('POST /test 缺 text → 400', async () => {
    const res = await call('POST', '/cloak/api/test', '{}')
    expect(res.status).toBe(400)
  })

  it('未知路由 → 404', async () => {
    const res = await call('GET', '/cloak/api/nope')
    expect(res.status).toBe(404)
  })
})
