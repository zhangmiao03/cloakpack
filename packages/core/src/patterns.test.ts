import { describe, expect, it } from 'vitest'
import { SIGNATURES } from './patterns.js'

import { deepseekKey, slackToken, stripeKey } from './fixtures.js'

/** 每条签名的「应命中」样例（全部为伪造值）。 */
const POSITIVE_SAMPLES: Record<string, string[]> = {
  'aws-access-key': ['AKIAIOSFODNN7EXAMPLE', 'ASIA3EXAMPLEKEY12345'],
  'aliyun-access-key': ['LTAI5tFakeExample12345'],
  'google-api-key': ['AIzaSyA1234567890abcdefghijklmnopqrstuv'],
  'deepseek-api-key': [deepseekKey],
  'anthropic-api-key': ['sk-ant-api03-fake-example-token-1234567890'],
  'openai-api-key': ['sk-proj-fakeexampletoken1234567890abcdefghij'],
  'openrouter-api-key': ['sk-or-v1-' + 'a'.repeat(48)],
  'github-token': ['ghp_' + 'A'.repeat(36), 'gho_' + 'b'.repeat(40)],
  'gitlab-token': ['glpat-fakeExampleToken1234567890'],
  'npm-token': ['npm_' + 'c'.repeat(36)],
  'slack-token': [slackToken],
  'discord-webhook': ['https://discord.com/api/webhooks/123456789012345678/' + 'd'.repeat(45)],
  'slack-webhook': ['https://hooks.slack.com/services/T00000000/B00000000/fakeExampleHookToken12'],
  'feishu-webhook': ['https://open.feishu.cn/open-apis/bot/v2/hook/' + '1a2b3c4d-'.repeat(4) + '1a2b3c4d'],
  'wecom-webhook': ['https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=fake-webhook-key-1234567890abcd'],
  'stripe-key': [stripeKey],
  'shopify-token': ['shpat_' + 'a1b2c3d4'.repeat(4)],
  'linear-api-key': ['lin_api_' + 'e'.repeat(40)],
  'sentry-dsn': ['https://0123456789abcdef0123456789abcdef@o123456.ingest.sentry.io/7890123'],
  'jwt': [
    // header.payload.signature（均为 base64 假数据）
    'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c',
  ],
  'private-key-block': ['-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA7fake\n-----END RSA PRIVATE KEY-----'],
  'db-connection-url': [
    'postgres://admin:hunter2secret@db.example.com:5432/prod',
    'mongodb+srv://user:p@ssw0rdX@cluster0.example.net/db',
  ],
  'bearer-header': ['Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.fakefakefake'],

  // 第二批（扫描器形态的运行时拼接，源码不出现完整字面量）
  'anthropic-admin-api-key': [['sk-ant-admin01-', 'fakeExampleToken123456'].join('')],
  'twilio-api-key': [['SK', '0123456789abcdef0123456789abcdef'].join('')],
  'sendgrid-api-key': [['SG.', 'FakeExampleToken12345678', '.', 'FakeExampleToken1234567890abcdefXYZ'].join('')],
  'mailgun-api-key': [['key-', '0123456789abcdef0123456789abcdef'].join('')],
  'telegram-bot-token': [['123456789', ':AA', 'FakeExampleTelegramBotToken1234567890x'].join('')],
  'airtable-pat': [['patFakeExample1234', '.0123456789abcdef0123456789abcdef'].join('')],
  'atlassian-api-token': [['ATATT3', 'x' + 'FakeExampleToken'.repeat(6)].join('')],
  'digitalocean-token': [['dop_v1_', 'a1b2c3d4'.repeat(8)].join('')],
  'gitlab-scoped-token': [['gldt-', 'FakeExampleDeployToken1234567890'].join('')],
  'notion-token': [['secret_', 'FakeExampleNotionIntegrationToken1234567890123'].join('')],
  'figma-token': [['figd_', 'FakeExampleFigmaPersonalToken1234567890'].join('')],
  'google-oauth-refresh': [['1//', '0gFakeExampleGoogleOAuthRefreshToken1234567890abcdefXY'].join('')],
  'tencent-cloud-secretid': [['AKID', 'FakeExampleTencentSecretId1234567890abcdefXYZ1'].join('')],
}

describe('内置签名', () => {
  for (const sig of SIGNATURES) {
    it(`${sig.id}：命中伪造样例`, () => {
      const samples = POSITIVE_SAMPLES[sig.id]
      expect(samples, `缺少 ${sig.id} 的测试样例`).toBeDefined()
      for (const sample of samples) {
        sig.regex.lastIndex = 0
        const m = sample.match(sig.regex)
        expect(m, `${sig.id} 应命中 ${sample.slice(0, 24)}…`).not.toBeNull()
        expect(m![0].length).toBeGreaterThan(0)
        if (sig.validate) expect(sig.validate(m![0]), `${sig.id} validate 应通过`).toBe(true)
      }
    })
  }

  it('近形误报不命中：短 AKIA / 普通 sk- 前缀 / 普通词', () => {
    const text = [
      'AKIA tooshort', // 长度不足
      'sk-abc', // 太短
      'the token is gh Programmer', // 普通词
      'postgres://localhost:5432/db', // 无密码的连接串不打码
      'postgresql://user@db.example.com/mydb', // 无密码
    ].join('\n')
    for (const sig of SIGNATURES) {
      sig.regex.lastIndex = 0
      expect(text.match(sig.regex), `${sig.id} 不应命中`).toBeNull()
    }
  })
})
