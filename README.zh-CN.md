# mcp-warden（MCP 守门员）

**在有风险的 MCP 服务器伤到你之前找到它。** 一个零依赖的 Go 单文件工具：审计 Claude Desktop、Claude Code、Cursor、VS Code、Cline、Windsurf、Gemini CLI 里配置的所有 MCP 服务器；并在服务器"审批之后偷偷变了"时报警。

## 为什么要做

MCP 服务器以你的权限运行，工具描述会被模型当作指令来读。2026 年的生态里有数万个服务器，官方目录只证明"存在"、不证明"可信"，冒名包频出，很多客户端审批一次之后就不再复查。`mcp-warden` 给个人开发者一个本地、开源、几秒钟出结果的检查，也给团队一个 CI 关卡。

## 快速开始

从 [Releases](https://github.com/ELOATS/mcp-warden/releases) 下载对应平台的预编译二进制（Linux / macOS / Windows，amd64 / arm64，附 `checksums.txt` 校验），或者用 Go 1.22+ 安装：

```sh
go install github.com/ELOATS/mcp-warden/cmd/mcp-warden@latest

mcp-warden list               # 列出所有客户端里配置的服务器
mcp-warden scan               # 静态审计（不执行任何东西）
mcp-warden scan --probe       # 真正启动/连接服务器，检查它暴露的工具
mcp-warden pin --probe        # 记录可信基线（~/.mcp-warden/lock.json）
mcp-warden diff               # 和基线比较，有变化就以退出码 1 报警
mcp-warden watch              # 每小时自动检查一次，有新变化就通知
```

## 持续监控（watch）

```sh
mcp-warden pin --probe                              # 先确认当前状态可信
mcp-warden watch --interval 30m                     # 桌面通知
mcp-warden watch --webhook "$MCP_WARDEN_WEBHOOK"    # 推送到飞书 / 钉钉 / 企业微信 / Slack / Discord
```

- 根据 webhook 地址自动识别格式，也可以用 `--webhook-format` 手动指定。webhook 地址里带有密钥，建议放在环境变量 `MCP_WARDEN_WEBHOOK` 里。
- 同一个变化只提醒一次；发送失败会在下一轮重试。审核完变化后重新执行 `pin`，就算确认接受了。
- 想交给 cron / launchd / systemd 定时调度，就用 `--once`：只检查一轮就退出，仍有未处理的变化时退出码为 1。例如 `17 * * * * mcp-warden watch --once`。

> `--probe` 会像你的 MCP 客户端一样启动每个已启用的服务器（包括 `npx`/`uvx` 下载）。`scan`、`list` 和不带 `--probe` 的 `pin` 都不会执行任何东西。

## 能发现什么

- **工具投毒**：描述里的"忽略之前的指令""不要告诉用户"、`<IMPORTANT>` 标签、读取 `~/.ssh` 等；隐藏的零宽 / 双向控制字符
- **Rug pull**：pin 之后工具描述、参数结构或配置发生变化
- **供应链**：冒名包（与知名包差 1–2 个字符）、未锁定版本的 `npx -y` / `uvx` / `:latest` 镜像、`curl | sh`
- **权限过大**：把 `/` 或家目录交给服务器、Docker `--privileged`、挂载 docker.sock
- **密钥泄露**：env / 参数 / 请求头里的明文 Token，URL 里的密钥，明文 http 远程连接
- **组合风险**：能执行命令的工具、同名工具互相遮蔽、"联网读取 + 本地数据 + 外传"的危险组合

完整规则表见 [README.md](README.md)。锁文件不保存任何密钥（env 和 header 只存哈希，参数和 URL 已打码）。

## 许可证

Apache License 2.0，详见 [LICENSE](LICENSE)。
