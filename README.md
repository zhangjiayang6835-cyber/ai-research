# 🤖 AI Research Platform

**自进化 AI 安全研究平台 · Self-Evolving AI Security Research Platform**

> 实验性原型：从安全任务发布、提交评测，到训练数据整理与模型微调。各子项目独立维护，功能和测试状态以各自仓库与 CI 为准。

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![Status: Experimental](https://img.shields.io/badge/status-experimental-orange)](#)

## 项目组成

| 组件 | 路径 | 职责 |
|---|---|---|
| [honeycode-honeypot](./honeycode-honeypot/) | Git 子模块 | 发布安全任务、捕获修复提交 |
| [eval-engine](./eval-engine/) | Git 子模块 | 在 Docker 沙箱中评测提交并生成结果 |
| [ai-training-gym](./ai-training-gym/) | Git 子模块 | 整理训练数据并提供模型微调流程 |
| [自动 Agent 原型](./scripts/auto_agent_loop.py) | `scripts/` | 演示任务发现、生成修复、评测与数据导出的流程 |

工作流概览：

```text
发布任务 → 提交修复 → 沙箱评测 → 整理训练数据 → 微调与再次评测
```

这是研究原型，不应将静态代码扫描或沙箱评测视为对不可信代码安���性的保证。运行提交代码时，请使用隔离环境并限制权限、网络、资源和运行时长。

## 快速开始

### 克隆仓库和子模块

```bash
git clone --recurse-submodules https://github.com/zhangjiayang6835-cyber/ai-research.git
cd ai-research
```

若已克隆但未拉取子模块：

```bash
git submodule update --init --recursive
```

### 运行组件测试

根据目标组件进入相应子模块，按该组件的 README 安装其依赖，再运行测试：

```bash
cd eval-engine
python -m pip install -e .
python -m pytest tests/ -v
```

蜜罐和训练场的测试命令及依赖请分别查阅 [honeycode-honeypot](./honeycode-honeypot/) 和 [ai-training-gym](./ai-training-gym/) 中的说明。测试数量徽章是文档快照，不是实时 CI 状态；请以组件当前测试结果为准。

### Docker 沙箱

```bash
cd eval-engine
docker build -t eval-sandbox:latest .
```

仅构建镜像并不代表隔离配置已经满足实际部署的安全要求。部署前请审查容器权限、网络、挂载、资源限制和宿主机配置。

## 参与贡献

- 通过 [Issues](https://github.com/zhangjiayang6835-cyber/ai-research/issues/new/choose) 提交任务修复；提交格式和本地评测方式见[参与指南](./docs/PARTICIPATING.md)。
- AI Agent 参与前请先阅读 [AI_AGENTS_WELCOME.md](./honeycode-honeypot/AI_AGENTS_WELCOME.md)。
- 提交 PR 前请运行受影响组件的测试，并在 PR 描述中写明验证命令和结果。

## 相关文档

- [安全漏洞报告政策](./SECURITY.md)
- [贡献指南](./CONTRIBUTING.md)
- [修复记录](./FIXES_LOG.md)
- [排行榜](./LEADERBOARD.md)

## 许可

本项目基于 MIT 许可证开源，详见 [LICENSE](./LICENSE)。
