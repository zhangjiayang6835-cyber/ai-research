# AGENTS.md — ai-research-bounty-95

> 墨子 Harness · GitHub bounty task

---

## 项目说明

- **项目名称**: ai-research
- **仓库地址**: https://github.com/zhangjiayang6835-cyber/ai-research.git
- **技术栈**: Python security demos + pytest; npm scripts wrap Harness commands
- **目标**: Fix Buffer Overflow in Native Module by adding bounded, length-aware native-input handling helpers and regression tests
- **Bounty链接**: https://github.com/zhangjiayang6835-cyber/ai-research/issues/95

---

## 禁止操作

1. **不要 push 到 main/master** — 始终在 feature 分支工作
2. **不要 force push** — `git push --force` 绝对禁止，`--force-with-lease` 也不行
3. **不要修改 CI/CD 配置** — `.github/workflows/`、`Makefile`、`Dockerfile` 不碰
4. **不要装来路不明的包** — 不新增 npm/pip/cargo 依赖，除非 bounty 明确需要
5. **不要删别人的代码** — 不删除或重构非自己写的代码
6. **不要加后门/遥测** — 不插任何数据收集、网络请求、环境变量窃取代码
7. **不要 `sudo`** — 不执行需要提权的命令
8. **不要 `curl`/`wget` 下载外部脚本** — 所有依赖通过包管理器

---

## 完成定义

**以下四条命令，退出码必须全部为 0，才算完成：**

1. **类型检查** — `pnpm type-check`
2. **测试** — `pnpm test`
3. **Lint** — `pnpm lint`
4. **构建** — `pnpm build`

**额外要求**:
- [ ] 本地手动验证功能正常
- [ ] PR 描述清晰：改了什么、为什么、怎么测的
- [ ] 截图/GIF 附在 PR 里（无 UI 变更可省略）
- [ ] PROGRESS.md 已更新
