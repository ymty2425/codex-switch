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
- `sync_active_profile`
- `rename_profile`
- `delete_profile`
- `export_profile`
- `export_diagnostic_bundle`
- `recover_pending_transactions`
- `import_profile`

这层同时管理：

- profile 元数据仓储
- 默认 profile 配置
- 自定义 discovery rules 配置
- 当前绑定状态
- 当前 live 会话与 active profile 的同步状态
- 平台就绪度诊断输出
- 全量 profile readiness inventory，可在 `doctor` 中汇总每个 profile 的 ready / warning / blocked 状态
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
