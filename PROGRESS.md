# PROGRESS.md — ai-research

> 墨子 Harness · Bounty #95

---

## ✅ 已完成

- 筛选并锁定 bounty issue: https://github.com/zhangjiayang6835-cyber/ai-research/issues/95
- 基于 `upstream/master` 创建独立 worktree 和分支 `fix/buffer-overflow-native-95`
- 初始化 Harness，定制 AGENTS.md / PROGRESS.md / setup.sh
- 补齐四条命令：`pnpm type-check` / `pnpm test` / `pnpm lint` / `pnpm build`
- 新增 `fixes/native_buffer_overflow_fix.py`：在 native 边界执行编码后字节长度校验、NUL 字节拒绝、固定缓冲区安全拷贝
- 新增回归测试覆盖超长 payload、多字节 UTF-8、NUL 字节、固定缓冲区不截断和安全填充
- Ralph 循环四条命令已全绿：type-check / test / lint / build

---

## 🔄 进行中

- 准备提交 PR

---

## 📋 待办

- commit / push / PR

---

## ⚠️ 已知问题

- 无
