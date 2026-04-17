# Architecture

## 层次

### Domain

`crates/codex-switch-domain` 定义纯领域对象：

- `ProfileMeta`
- `DetectedSession`
- `SecretSnapshot`
- `CurrentBinding`
- `SwitchTransaction`
- `SessionDetector`
- `OfficialCredentialStore`
- `ProfileVault`

这一层不依赖平台 API，只提供数据结构、错误类型和 trait。

### Platform

`crates/codex-switch-platform` 负责真实系统交互：

- `PathResolver`：发现 `CODEX_HOME` 和管理器数据目录
- `FileCredentialStore`：读取与写入 `auth.json`
- `inspect`：从 `auth.json`、JWT claim、`account_id` 推断账号标识和来源
- `CredentialDiscoveryRegistry`：根据 `email`、`sub`、`account_id` 线索展开系统凭证发现规则
- `GlobalSwitchLock`：进程级文件锁
- `LocalProfileVault`：本地 vault 存储与导出加密
- `MacKeychainCredentialStore`
- `LinuxKeyringCredentialStore`
- `WindowsCredentialStore`
- `AuthJsonSessionDetector`

### Application

`crates/codex-switch-application` 负责用例编排：

- `doctor_report`
- `detect_report`
- `save_profile`
- `list_profiles`
- `current_status`
- `use_profile`
- `check_profile`
  - 当前除 drift 检查外，还会执行 profile 级 preflight
  - preflight 的 blocker / warning 会同步回写到 `profile.health`
- `sync_active_profile`
- `rename_profile`
- `delete_profile`
- `export_profile`
- `export_diagnostic_bundle`
- `recover_pending_transactions`
- `import_profile`
  - 导入后会立即按当前机器重新做一次 preflight，并写回导入 profile 的健康状态

这层同时管理：

- profile 元数据仓储
- 默认 profile 配置
- 自定义 discovery rules 配置
- 当前绑定状态
- 当前 live 会话与 active profile 的同步状态
- 平台就绪度诊断输出
- 全量 profile readiness inventory，可在 `doctor` 中汇总每个 profile 的 ready / warning / blocked 状态
- store usage summary，可在 `doctor` 中按依赖 store 汇总 profile 数量与 blocked / warning 分布
- platform validation summary，可在 `doctor` 中直接判断当前机器适合跑 blocked / file-only / mixed-mode 哪一种验收路径
- validation evidence matrix，可在 `doctor` 中按 macOS / Windows / Linux 汇总已经落盘的验收证据
- validation coverage summary，可在 `doctor` 中判断 file-backed / mixed-mode 是否已经有留痕，并给出下一轮推荐验证目标
- validation freshness，可在 `doctor` 中判断最新 evidence 是否仍然匹配当前 profile catalog
- 系统凭证 discovery trace，可见每条规则的展开和查找状态
- non-destructive switch probes，可见锁文件、数据目录和同目录 rename 的就绪度
- 未完成切换事务的可见性与显式恢复
- 对 CLI / Tauri 暴露的脱敏 live session 摘要
- 切换事务日志
- 审计日志

### Entry Points

- `crates/codex-switch-cli`：CLI
- `apps/desktop/src-tauri`：Tauri command bridge
- `apps/desktop/src`：React UI

## 切换事务

`use_profile` 的执行顺序：

1. 获取全局切换锁
2. 恢复任何未完成事务
3. 重新检测 live session
4. 读取目标 profile 的快照
5. 创建 `SwitchTransaction`
6. 备份当前认证文件到 `tx/<txn>/backup/`
7. 应用系统凭证
8. 应用文件型凭证
9. 更新 `CurrentBinding`
10. 重新 `detect`
11. 若 live 指纹不匹配目标快照，则回滚
12. 成功后删除事务文件并写审计日志

## 快照组成

当前快照只包含认证相关最小集合：

- `auth.json`
- 系统凭证引用与实际 secret 记录
- 快照来源元数据：保存时的 `operating_system` 与可用 `system_store_name`

当 detector 命中系统凭证规则时，`DetectedSession` 会被标记为 `mixed`，并把发现到的系统条目一起纳入 live fingerprint。

`CredentialDiscoveryRegistry` 的规则来源分为两层：

- 内置标准规则
- `config.json` 里的自定义 `credential_discovery_rules`

manager 启动时会先加载标准规则，再把自定义规则追加进去。

`check_profile` 的 preflight 会把 snapshot provenance 一起纳入判断：

- system store 缺失时继续作为 blocker
- profile 带系统凭证且来源平台不同，会给出 compatibility warning
- profile 带系统凭证且来源 store 与当前 store 不同，也会给出 compatibility warning

`doctor_report` 会在整机视角复用这套 preflight 逻辑，生成 profile inventory：

- `ready`：当前机器没有 blocker，也没有额外 warning
- `warning`：可以切换，但存在 drift 或平台 / store 兼容性提示
- `blocked`：当前机器存在明确切换阻塞因素

在此基础上，`doctor_report` 还会生成 store usage summary：

- 按 `source_system_store_name` 聚合所有已保存 profile
- 对没有 system store 依赖的 profile 归并到 `file_only`
- 汇总每个 store 的 ready / warning / blocked 数量
- 当某个 store 当前挡住 profile 时，recommendation 会点名该 store

`doctor_report` 还会生成 platform validation summary：

- `blocked`：当前机器还不适合进入平台验收，通常是 live session 或 switch probes 还没准备好
- `file_only`：当前机器适合先做文件型会话验收，但 mixed-mode 仍需要目标 system store 可用
- `ready`：当前机器适合做 file-backed 和 mixed-mode 验收，并会给出建议的下一步验证动作

当执行 `export_diagnostic_bundle` 时，application 层还会把本次导出的结果记录到 `validation/` 目录，形成一条本地 validation evidence：

- 记录时间
- 当前操作系统
- 当时的 validation status
- 活跃 store 名称
- 导出的 bundle 路径

后续 `doctor_report` 会把这些记录折叠成一个 3 平台 evidence matrix，帮助判断还缺哪台机器的实机结果。

`doctor_report` 还会基于这些 evidence records 再计算 coverage summary：

- `file_backed_recorded`：是否至少留过一次 file-backed 验证证据
- `mixed_mode_required`：当前已保存 profile 是否真的需要 mixed-mode 验收
- `mixed_mode_recorded`：是否已经留过至少一次 mixed-mode 验证证据
- `next_target`：当前最值得优先补的下一轮验收动作
- `stale / stale_reason`：当前 evidence 是否已经落后于最新 profile catalog

不会复制：

- `logs`
- `history`
- `sessions`
- `models_cache`
- 其他非认证工作态内容

## 导出导入

导出包格式：

- `ExportEnvelope`
  - `schema_version`
  - `profile_meta_json`
  - `snapshot_json`

导出时会再包一层加密 envelope：

- `encrypted`
- `salt_b64`
- `nonce_b64`
- `payload_b64`

当前使用 `PBKDF2-SHA256 + AES-256-GCM-SIV`。

## 脱敏输出

应用层不会把 `DetectedSession.file_entries[*].contents` 直接暴露给 CLI 的 `detect/current` 输出或桌面端 dashboard。

对外改用脱敏摘要：

- 文件条目只保留相对路径、权限和字节数
- 系统凭证条目只保留 `service`、脱敏后的 `account`、`label` 和 masked hint
- 诊断包只包含 `doctor`、脱敏后的当前状态、profile 元数据和审计日志尾部

## 当前平台差异

### macOS

- 本地路径：`~/Library/Application Support/codex-switch`
- 已实现 Keychain 读写包装
- detector 会基于 registry 用 `service/account` 模板尝试读取 Keychain 条目，不做全量扫描

### Windows

- 本地路径：`%AppData%\codex-switch`
- 已提供 `WindowsCredentialStore` 适配入口
- 当前非 Windows build 下只返回“此平台不可用”
- detector registry 已接通，但完整条目命名仍需在真实 Windows 环境补验证

### Linux

- 本地路径：`$XDG_DATA_HOME/codex-switch` 或 `~/.local/share/codex-switch`
- 优先使用 `secret-tool`
- 若无 Secret Service，可继续使用本地口令加密 vault 保存 profile
- detector 会按 registry 规则尝试 `service/account` 组合，不依赖全量 keyring 枚举
