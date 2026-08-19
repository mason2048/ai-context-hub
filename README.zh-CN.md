# AI Context Hub

[English](README.md) · [中文操作手册](docs/USER_GUIDE.zh-CN.md) · [安全策略](SECURITY.md)

AI Context Hub 是一个本地优先的 AI 上下文审查工作台。它以只读方式扫描项目中的规则、Skill、知识文件和 MCP 元数据，生成不可变快照，识别冲突与秘密风险，按实际导出正文精确计算 Token，并在人工审核后导出 Context Package v0.1 或 `AGENTS.md` 草案。

当前 `0.1.0` 是**源码预览版**，不是云服务。扫描成功或导出成功，不代表下游 AI Agent 已正确采用这些上下文。

## 快速开始

需要 Node.js 20.19+ 或 22.12+，以及 npm。

```sh
git clone https://github.com/mason2048/ai-context-hub.git
cd ai-context-hub
npm ci
npm run dev
```

打开 <http://127.0.0.1:43100>，保留页面预填的 `sample-project` 路径，点击“开始只读扫描”。开发命令会同时启动 `127.0.0.1:43101` API 与 `127.0.0.1:43100` 前端；回到终端按 `Ctrl+C` 可同时停止。

本地生产构建：

```sh
npm run build
npm start
```

随后打开 <http://127.0.0.1:43101>。

## 主要能力

- 发现 `AGENTS.md`、`CLAUDE.md`、Copilot/Cursor 规则、`SKILL.md`、Markdown 知识和安全的 MCP 服务名元数据；
- 记录相对来源、定位、SHA-256 revision、修改时间、摘要、作用域和精确 `o200k_base` Token；
- 识别重复项、结构化冲突、失效相对引用和疑似秘密，且丢弃命中的秘密原值；
- 以不可变快照管理多个本地项目，并显示刷新差异；
- 通过“检查—预览—确认”导入 Context Package v0.1，不访问或执行包中声明的来源；
- 以提醒、阻止或确定性自动裁剪策略控制 Token 预算，导出 JSON 或 `AGENTS.md` 草案；
- 可选使用本地 Ed25519 密钥为 JSON 签名。

## 隐私与安全

服务只监听本机回环地址，没有账户、遥测、自动上传或云模型硬依赖，也不会执行扫描到的脚本、Skill、提示词或 MCP 命令。扫描不会向目标项目写文件。JSON 导出可能包含绝对文件 URI，分享前必须复核。

默认状态目录：

- macOS：`~/Library/Application Support/AI Context Hub/v1`
- 其他系统：`~/.local/share/ai-context-hub/v1`

可以指定一个与待扫描项目不重叠的绝对目录：

```sh
CONTEXT_HUB_DATA_DIR=/absolute/private/context-hub-state npm start
```

扫描、筛选、预算、导入导出、备份、重置和故障处理请见[中文操作手册](docs/USER_GUIDE.zh-CN.md)。

## 本地验证

```sh
npm test
npm run build
npm audit
```

`sample-project/node_modules/ignored-rule/AGENTS.md` 是用于证明依赖目录会被排除的惰性测试夹具，不应作为普通清理对象删除。

## 当前边界

本预览版已有扫描、快照、导入、导出、签名、取消任务和 API 安全自动化覆盖，但真人首次使用和下游 Agent 是否采纳仍需外部验证。目前不包含云同步、团队协作、账户、自动写配置、自动执行命令或生产部署。

## 参与贡献与许可证

提交 Pull Request 前请阅读 [CONTRIBUTING.md](CONTRIBUTING.md)。安全问题请按 [SECURITY.md](SECURITY.md) 使用 GitHub Private Vulnerability Reporting 私下报告。

项目采用 [Apache License 2.0](LICENSE)。
