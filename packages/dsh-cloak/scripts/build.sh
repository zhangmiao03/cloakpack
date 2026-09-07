#!/bin/bash
# dsh-cloak build: junction-link @deepseek-ai/* peer deps from a DSH install, then tsc.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MONO_ROOT="$(cd "$ROOT/../.." && pwd)"
cd "$ROOT"

# ── checkout 探测：env → 全局 npm 安装 → 常见源码路径 ──
CHECKOUT="${DSH_CHECKOUT:-}"
if [ -z "$CHECKOUT" ] || { [ ! -d "$CHECKOUT/packages" ] && [ ! -d "$CHECKOUT/node_modules/@deepseek-ai/dsh-tools" ]; }; then
  CHECKOUT=""
  GLOBAL_ROOT="$(npm root -g 2>/dev/null || true)"
  if [ -n "$GLOBAL_ROOT" ] && [ -d "$GLOBAL_ROOT/@deepseek-ai/dsh" ]; then
    CHECKOUT="$GLOBAL_ROOT/@deepseek-ai/dsh"
  fi
  for c in "$HOME/dsh-harness" "$HOME/dsh" "$HOME/.dsh/dsh-harness"; do
    if [ -z "$CHECKOUT" ] && [ -d "$c/packages" ]; then CHECKOUT="$c"; fi
  done
fi
if [ -z "$CHECKOUT" ]; then
  echo "build: cannot locate a DSH install (npm i -g @deepseek-ai/dsh, or set DSH_CHECKOUT)" >&2
  exit 1
fi
echo "=== DSH install: $CHECKOUT ==="

# ── tsc 探测：本地 devDeps → checkout ──
TSC=""
for t in "$MONO_ROOT/node_modules/.bin/tsc" "$ROOT/node_modules/.bin/tsc" "$CHECKOUT/node_modules/.bin/tsc" "$HOME/.dsh/profiles/web/node_modules/.bin/tsc"; do
  if [ -x "$t" ] || [ -f "$t.cmd" ]; then TSC="$t"; break; fi
done
if [ -z "$TSC" ]; then echo "build: tsc not found (npm install first)" >&2; exit 1; fi

# ── junction link 构建期类型依赖（scoped，来自 DSH 安装）──
link_pkg() {
  local link="node_modules/$1" target="$2"
  node -e "
    const fs = require('fs'); const path = require('path');
    const link = path.resolve(process.argv[1]); const target = path.resolve(process.argv[2]);
    fs.rmSync(link, { recursive: true, force: true });
    fs.mkdirSync(path.dirname(link), { recursive: true });
    fs.symlinkSync(target, link, process.platform === 'win32' ? 'junction' : 'dir');
  " "$link" "$target"
}
mkdir -p node_modules/@deepseek-ai
for pkg in cordis schemastery dsh-tools dsh-llm dsh-host-webserver dsh-session dsh-scope dsh-agent dsh-commands; do
  if [ -d "$CHECKOUT/node_modules/@deepseek-ai/$pkg" ]; then
    link_pkg "@deepseek-ai/$pkg" "$CHECKOUT/node_modules/@deepseek-ai/$pkg"
  fi
done

echo "=== Compiling host (tsc) ==="
"$TSC" -p tsconfig.json
echo "=== build OK ==="
