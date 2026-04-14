# Codex Switch

`Codex Switch` 是一个本地多账号会话管理器，用来保存、切换、检测、恢复和同步官方 Codex 本地登录态，目标是在多个账号都已经通过官方方式成功登录过一次的前提下，尽量减少重复登录。

## 当前 MVP 能力

- 发现 `CODEX_HOME` 或默认 `~/.codex` 目录里的官方本地认证文件
- 将当前官方登录态保存为命名 profile
- 列出、查看当前会话、切换、健康检查、同步、重命名、删除 profile
- 将 profile 导出为口令加密包，并重新导入
- 在切换前自动备份当前会话，切换后做指纹校验，失败时自动回滚
- 提供 Rust CLI 和极简 Tauri 桌面端壳子，共用同一套后端服务

## 重要边界

- 不拦截 OAuth，不做 MITM，不劫持流量，不伪造登录
- MVP 只管理最小认证快照，当前已实现的主探测对象是 `auth.json`
- 当前 build 下最完整的切换路径是文件型凭证；系统凭证适配层已经建好接口与平台实现入口，但探测器还没有发现官方系统凭证条目

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
- profile 列表
- 保存当前账号
- 切换 profile
- 健康检查
- 同步刷新后的会话
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

## 当前实现状态

- 已实现：`auth.json` 文件型会话检测、最小快照保存、切换回滚、显式 `sync`、导出导入、Tauri UI 壳子
- 已搭好适配层：macOS Keychain、Linux Secret Service、Windows Credential Manager
- 下一步重点：把系统凭证探测规则扩展成 registry，并补更多官方本地状态源

更多细节见：

- [ARCHITECTURE.md](/Users/colin/Documents/codex-switch/ARCHITECTURE.md)
- [RISKS.md](/Users/colin/Documents/codex-switch/RISKS.md)
- [TESTING.md](/Users/colin/Documents/codex-switch/TESTING.md)
