# local_report 部署说明

## 用途
`local_report` 用于汇总多台 VM 的任务上报，提供：
- Agent 配置管理
- 本地 Web 看板
- 企业微信超时/恢复/完成通知
- 提供给 `game_tool` 的 `bootstrap` / `control` 接口

## 发布目录内容
打包后的目录通常包含：
- `local_report_server.exe`
- `start_local_report.bat`
- `stop_local_report.bat`
- `.env.example`
- `DEPLOY_GUIDE.md`

## 部署步骤
1. 将整个发布目录复制到目标机器，例如 `D:\tools\local_report_server`。
2. 按需复制 `.env.example` 为 `.env`，并填写实际配置。
3. 如果目标机器上已有旧版服务，先在旧目录执行 `stop_local_report.bat`，确认旧进程已停止；不要让不同目录下的 `local_report_server.exe` 并行运行。
4. 确认目标机器防火墙允许 VM 访问 `18080` 端口。
5. 执行 `start_local_report.bat`，后台启动 `local_report_server.exe`。
6. 浏览器访问：
   - 首页：`http://目标IP:18080/`
   - 配置台：`http://目标IP:18080/console`

## 常用操作
- 启动服务：`start_local_report.bat`
- 停止服务：`stop_local_report.bat`（只能停止当前目录对应的 `local_report_server.exe`；如果后台跑的是旧目录版本，请去旧目录执行停止脚本，或按进程路径手动结束）
- 前台调试：直接运行 `local_report_server.exe`

## game_tool 对接
在 VM 的 `game_tool_config.json` 中配置：
- `server.base_url`：填写 report 服务器地址，例如 `http://192.168.1.50:18080`
- `server.agent_id`：填写该 VM 对应的 Agent ID

## 说明
建议将 Agent 配置、资源配置和运行目录长期固定，避免更换目录后读取到错误的 `.env` 或 `local_report.db`。
