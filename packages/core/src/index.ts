/**
 * @cloakpack/core — 密钥检测引擎（cloakpack CLI 与 dsh-cloak 插件共享）。
 */
export { SIGNATURES, SENSITIVE_KEY_PATTERN, EXCLUDED_KEY_PATTERN, ASSIGNMENT_REGEX, isPlaceholderValue, shannonEntropy, type Signature } from './patterns.js'
export { scan, type Finding, type ScanOptions, type CompiledCustomRule } from './scan.js'
export { scanText, scanFile, packText, unpackText, looksBinary, type FileFinding } from './fs-scan.js'
export { INLINE_MARKER, globToRegExp, makePathAllower, makeValueAllower, type AllowConfig } from './allowlist.js'
export { BASELINE_FILE, baselineKey, loadBaseline, saveBaseline } from './baseline.js'
export { Vault, findRepoRoot, loadProjectConfig, destroyAll, keysRoot, PROJECT_DIR, VAULT_FILE, CONFIG_FILE } from './vault-file.js'
export {
  git, repoRoot, trackedFiles, treeFiles, blobAt, parsePushStdin,
  installHook, removeHook, secretInHistory, type PushLine, type GitResult,
} from './git.js'
export { deepseekKey, slackToken, stripeKey } from './fixtures.js'
