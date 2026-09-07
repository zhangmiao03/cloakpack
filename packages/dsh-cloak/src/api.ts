/**
 * dsh-cloak — webServer 前缀路由 /cloak/api/*。
 *
 * GET  /stats   总量统计（按类别）
 * GET  /recent  最近审计条目
 * POST /test    试扫一段样例文本（不落库，便于面板/演示）
 */
import type { IncomingMessage, ServerResponse } from 'node:http'
import type { Audit } from './audit.js'
import type { Redactor } from './redact.js'
import type { SecretVault } from './vault.js'

export interface ApiDeps {
  audit: Audit
  redactor: Redactor
  vault: SecretVault
}

const json = (res: ServerResponse, status: number, data: unknown): void => {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' })
  res.end(JSON.stringify(data))
}

const readBody = (req: IncomingMessage): Promise<string> =>
  new Promise((resolve, reject) => {
    let raw = ''
    req.on('data', (chunk: Buffer) => { raw += chunk.toString('utf8') })
    req.on('end', () => resolve(raw))
    req.on('error', reject)
  })

export function createApiHandler(deps: ApiDeps) {
  return async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    try {
      const url = new URL(req.url ?? '/', 'http://cloak.local')
      const rest = url.pathname.replace(/^\/cloak\/api/, '').replace(/\/+$/, '') || '/'

      if (req.method === 'GET' && rest === '/stats') {
        json(res, 200, { audit: deps.audit.stats(), vault: deps.vault.stats() })
        return
      }
      if (req.method === 'GET' && rest === '/recent') {
        const limit = Number(url.searchParams.get('limit') ?? 50)
        json(res, 200, { entries: deps.audit.list(Number.isFinite(limit) ? Math.min(Math.max(limit, 1), 200) : 50) })
        return
      }
      if (req.method === 'POST' && rest === '/test') {
        const body = JSON.parse(await readBody(req)) as { text?: unknown }
        if (typeof body.text !== 'string' || body.text.length === 0) {
          json(res, 400, { error: 'text required' })
          return
        }
        const text: string = body.text
        // 试扫不进 vault（不产生占位符副作用），只报告 findings。
        const findings = deps.redactor.scan(text)
        json(res, 200, {
          count: findings.length,
          findings: findings.map((f) => ({
            category: f.category,
            source: f.source,
            preview: `${text.slice(Math.max(f.start - 10, 0), f.start)}███${text.slice(f.start + f.length, f.start + f.length + 10)}`,
          })),
        })
        return
      }
      json(res, 404, { error: 'not found' })
    } catch (error) {
      json(res, 400, { error: error instanceof Error ? error.message : String(error) })
    }
  }
}
