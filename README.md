# Codex Switch

`Codex Switch` 是一个本地多账号会话管理器，用来保存、切换、检测、恢复和同步官方 Codex 本地登录态，目标是在多个账号都已经通过官方方式成功登录过一次的前提下，尽量减少重复登录。

## 当前 MVP 能力

- 发现 `CODEX_HOME` 或默认 `~/.codex` 目录里的官方本地认证文件
- 将当前官方登录态保存为命名 profile
- 列出、查看当前会话、切换、健康检查、同步、重命名、删除 profile
- `check <name>` 会同时给出切换前预检结果，说明当前机器是否具备切换这个 profile 的条件
- `check/import` 会把本机预检结果回写到 `profile.health`，让列表和桌面端状态直接反映 blocked / warning / drift 情况
- 将 profile 导出为口令加密包，并重新导入
- 在切换前自动备份当前会话，切换后做指纹校验，失败时自动回滚
- 主动判断当前 live 会话是否已经偏离 active profile，并提示是否需要执行 `sync`
- 提供 Rust CLI 和极简 Tauri 桌面端壳子，共用同一套后端服务
- `detect/current/doctor` 的对外输出默认只暴露脱敏摘要，不直接暴露原始认证内容
- 可导出脱敏诊断包，方便做三平台实机验收与问题归档

## 重要边界

- 不拦截 OAuth，不做 MITM，不劫持流量，不伪造登录
- MVP 只管理最小认证快照，当前已实现的主探测对象是 `auth.json`
- 当前 build 下最稳定的切换路径仍然是文件型凭证；系统凭证已支持基于规则的启发式发现，完整官方条目覆盖仍需继续扩展

## 仓库结构

```text
crates/
  codex-switch-domain/       领域模型、错误、trait、序列化
  codex-switch-platform/     路径发现、文件安全、检测器、vault、平台凭证适配
  codex-switch-application/  save/use/sync/export/import 等用例编排
  codex-switch-cli/          CLI 入口
apps/
  desktop/                   React + Tauri 极简桌面端
```

## CLI

```bash
cargo run -p codex-switch-cli -- detect
cargo run -p codex-switch-cli -- doctor
cargo run -p codex-switch-cli -- bundle
cargo run -p codex-switch-cli -- recover
cargo run -p codex-switch-cli -- save personal --note "Daily driver" --default
cargo run -p codex-switch-cli -- list
cargo run -p codex-switch-cli -- use personal
cargo run -p codex-switch-cli -- current
cargo run -p codex-switch-cli -- check personal
cargo run -p codex-switch-cli -- sync
cargo run -p codex-switch-cli -- rename personal work
cargo run -p codex-switch-cli -- delete work
CODEX_SWITCH_PASSPHRASE=secret cargo run -p codex-switch-cli -- export personal
CODEX_SWITCH_PASSPHRASE=secret cargo run -p codex-switch-cli -- import ./personal.cxswitch
```

### 常用参数

- `--json`：返回结构化 JSON
- `--codex-home <path>`：覆盖官方 `CODEX_HOME`
- `--data-dir <path>`：覆盖管理器数据目录
- `--local-passphrase-env <ENV>`：从环境变量读取本地 vault 加密口令

### 口令环境变量

- `CODEX_SWITCH_MASTER_PASSPHRASE`：可选，本地 vault 加密
- `CODEX_SWITCH_PASSPHRASE`：必填，`export/import` 加密包

## Desktop UI

桌面端位于 [apps/desktop](/Users/colin/Documents/codex-switch/apps/desktop)。

```bash
npm install
npm --workspace apps/desktop run tauri dev
```

当前 UI 覆盖：

- 当前账号展示
- 平台就绪度面板，显示 auth 文件、discovery rules 与系统凭证 store 状态
- 平台就绪度面板，显示 discovery trace，帮助定位规则是命中、缺少输入还是查找落空
- 平台就绪度面板，显示待恢复事务并允许手动执行恢复
- 平台就绪度面板，运行非破坏性切换探针，检查数据目录写入、全局锁和同目录原子替换
- 当前会话是否需要同步的状态提示
- profile 列表
- 保存当前账号
- 切换 profile
- 设置默认 profile
- 重命名、删除、导入、导出 profile
- 健康检查
- 同步刷新后的会话
- 导出脱敏诊断包
- 查看审计日志

## 数据布局

管理器自己的数据目录独立于官方 `CODEX_HOME`：

- macOS: `~/Library/Application Support/codex-switch`
- Windows: `%AppData%\codex-switch`
- Linux: `$XDG_DATA_HOME/codex-switch` 或 `~/.local/share/codex-switch`

目录布局：

```text
profiles/   profile 元数据
vault/      敏感快照
exports/    导出包
tx/         切换事务与备份
locks/      全局文件锁
logs/       脱敏审计日志
config.json 默认 profile 配置
```

### 自定义系统凭证发现规则

管理器会先加载内置 discovery rules，再把 `config.json` 里的自定义规则追加进去。可用于适配未来官方 `service/account` 命名变化，而不必等待发版。

示例：

```json
{
  "default_profile_id": null,
  "credential_discovery_rules": [
    {
      "name": "custom-openai",
      "source_type": "chat_gpt",
      "service": "custom-openai",
      "account": "{account_id}",
      "label": "Desktop Session"
    }
  ]
}
```

## 当前实现状态

- 已实现：`auth.json` 文件型会话检测、最小快照保存、切换回滚、显式 `sync`、导出导入、Tauri UI 壳子
- 已实现：系统凭证规则注册表，支持根据 `auth.json` 里的 `email`、`sub`、`account_id` 线索做 mixed-mode 启发式发现
- 已实现：`doctor` 平台就绪度报告，可用于实机验证 auth 文件、store 可用性与 discovery rules 配置
- 已实现：`doctor` / 桌面端会展示 discovery trace，直接说明每条规则是 matched、missing_input 还是 lookup_missed
- 已实现：`doctor` / 桌面端会运行 non-destructive switch probes，帮助确认本机是否真的具备切换所需的文件系统能力
- 已实现：`check` 会输出 per-profile preflight blocker / warning，提前暴露 system store 缺失或 probe 失败等切换阻塞因素
- 已实现：`check/import` 会把本机 preflight blocker 或 warning 同步写回 profile 健康状态，避免列表状态与实际可切换性脱节
- 已实现：profile 快照会记录保存时的来源平台与 system store 名称，`check` 会在跨平台 / 跨 store 使用时给出兼容性 warning
- 已实现：`doctor` / 桌面端会汇总所有已保存 profile 的 readiness inventory，直接区分 ready / warning / blocked
- 已实现：`doctor` / 桌面端会按依赖 store 汇总已保存 profile，直接看出哪个 store 正在挡住多少 profile
- 已实现：`bundle` 脱敏诊断包导出，适合收集平台状态、profile 元数据和审计尾部用于实机排障
- 已实现：CLI 和桌面端的当前状态传输已做脱敏，不再把 `auth.json` 原文暴露给 UI 或 `detect/current` JSON 输出
- 已实现：`recover` 显式恢复未完成切换事务，并在 `doctor` / 桌面端暴露 pending transaction 状态
- 已搭好适配层：macOS Keychain、Linux Secret Service、Windows Credential Manager
- 下一步重点：补更多官方条目规则、扩展更多本地状态源、做三平台实机验证

更多细节见：

- [ARCHITECTURE.md](/Users/colin/Documents/codex-switch/ARCHITECTURE.md)
- [RISKS.md](/Users/colin/Documents/codex-switch/RISKS.md)
- [TESTING.md](/Users/colin/Documents/codex-switch/TESTING.md)
