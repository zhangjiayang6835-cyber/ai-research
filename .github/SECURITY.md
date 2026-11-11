# 🔐 GitHub Actions 凭证安全指引

## 凭证使用原则

优先使用工作流的 `GITHUB_TOKEN`（表达式 `${{ github.token }}`），并在工作流或 job 级别只授予任务所需的最小权限。不要因为本文件就创建或保留 PAT：只有在确实需要跨仓库或跨工作流能力、且内置令牌无法满足时，才考虑单独的凭证，并先确认权限边界和触发流程。

仓库工作流当前多处直接使用 `github.token` / `github.token` 对应的 Actions 上下文；本文件不声称仓库必然配置了 PAT。新增或调整工作流时，请以实际 YAML、仓库设置和触发方式为准，逐项核对权限，避免把写权限授予仅需读取的任务。

## 如确需使用 PAT

- 使用 fine-grained PAT，限制到必要的仓库和权限；不要使用全仓库或组织级宽权限令牌。
- 将令牌仅存入 GitHub Actions Secrets，不写入源码、日志、Issue、PR 或提交历史。
- 设置负责人、用途、到期时间和撤销/轮换流程，并定期审计是否仍有必要。
- 对来自 fork、Issue、PR 评论等不可信事件，不要将可写凭证暴露给不可信代码或未经验证的输入。

## Secret 与审计

仅在工作流确实需要时配置 Secrets（例如通知 Webhook）；避免复制或打印 Secret。审查 workflow 的 `permissions`、事件触发器及第三方 Action 的权限后再授权。GitHub Actions 日志可用于审查运行过程，但不应记录凭证值。
