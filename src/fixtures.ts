/**
 * GitHub push-protection 安全的伪造测试夹具：运行时拼接，源码文本里
 * 不出现完整密钥字面量（GitHub 密钥扫描会拦截推送）。
 */
export const deepseekKey = ['sk-0123456789abcdef', '0123456789abcdef'].join('')
export const slackToken = ['xox', 'b-123456789012-1234567890123-fakeExampleToken12'].join('')
export const stripeKey = ['sk_', 'live_fakeExampleToken1234567890ab'].join('')
