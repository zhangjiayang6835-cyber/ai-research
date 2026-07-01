#!/bin/bash
set -euo pipefail

# ============================================================
# 墨子 Harness · 环境锁定脚本
# 项目: ai-research
# 生成: 2026-07-02
# ============================================================

echo "🔍 检查环境..."

REQUIRED_NODE_MAJOR="22"
CURRENT_NODE=$(node -v 2>/dev/null || echo "not-installed")

if [ "$CURRENT_NODE" = "not-installed" ]; then
  echo "❌ Node.js 未安装"
  exit 1
fi

CURRENT_MAJOR=$(echo "$CURRENT_NODE" | sed 's/v//' | cut -d. -f1)
if [ "$CURRENT_MAJOR" != "$REQUIRED_NODE_MAJOR" ]; then
  echo "❌ 需要 Node v${REQUIRED_NODE_MAJOR}.x，当前 $CURRENT_NODE"
  echo "   建议: nvm install $REQUIRED_NODE_MAJOR && nvm use $REQUIRED_NODE_MAJOR"
  exit 1
fi
echo "  ✅ Node: $CURRENT_NODE"

PACKAGE_MANAGER="pnpm"

echo "📦 安装依赖..."
if ! command -v pnpm &>/dev/null; then
  echo "  安装 pnpm..."
  npm install -g pnpm
fi

echo "  pnpm: $(pnpm --version)"
if [ -f "pnpm-lock.yaml" ]; then
  pnpm install --frozen-lockfile
else
  echo "  ⚠️ 未找到 pnpm-lock.yaml，生成中..."
  pnpm install
fi

echo ""
echo "✅ 环境准备完成"
echo ""
echo "下一步:"
echo "  1. 确认 AGENTS.md 已配置"
echo "  2. 在 feature 分支开发"
echo "  3. 跑 Harness: pnpm type-check && pnpm test && pnpm lint && pnpm build"
echo "  4. 全绿后 git commit && git push origin <branch>"
