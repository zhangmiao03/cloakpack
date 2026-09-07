/**
 * cloakpack — 库入口：检测引擎（与 dsh-cloak 同源）+ 文件扫描/替换 + 保险库 + git 封装。
 */
export { SIGNATURES, SENSITIVE_KEY_PATTERN, EXCLUDED_KEY_PATTERN, ASSIGNMENT_REGEX, isPlaceholderValue, type Signature } from './patterns.js'
export { scan, type Finding, type ScanOptions, type CompiledCustomRule } from './scan.js'
export { scanText, scanFile, packText, unpackText, looksBinary, type FileFinding } from './fs-scan.js'
export { Vault, findRepoRoot, loadProjectConfig, destroyAll, PROJECT_DIR, VAULT_FILE, CONFIG_FILE } from './vault-file.js'
export {
  git, repoRoot, trackedFiles, treeFiles, blobAt, parsePushStdin,
  installHook, removeHook, secretInHistory, type PushLine, type GitResult,
} from './git.js'
