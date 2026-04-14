# Risks

## 已知风险

### 健康检查不是官方在线验证

当前 `check` 主要依赖：

- 快照结构是否可读
- live 指纹与保存指纹是否一致
- `auth.json` 里可解析到的刷新时间与账号信息

这不能证明服务端一定接受 refresh token。

### 官方客户端可能后台刷新文件

如果官方 Codex 在后台更新了 `auth.json`，管理器无法阻止它改写本地文件。MVP 通过：

- 切换时加文件锁
- 切换后立即重检 live 指纹
- `sync` 显式同步

来降低风险，但不能完全阻止外部进程竞争写入。

### 系统凭证探测仍然保守

当前已经有基于 registry 的启发式规则发现，但它仍然是保守模式，不是“全平台全条目自动枚举”。结果是：

- 文件型登录态已可用
- 常见 `service/account` 组合可进入 mixed-mode 探测
- 未被 registry 覆盖的官方条目仍可能漏检
- Windows Credential Manager 的真实命名方式仍需在 Windows 环境里补齐验证
- 自定义规则配置写错时不会命中条目，因此需要在 `detect` 或桌面端状态里验证规则是否真正生效
- `doctor` 提供的是本机可见性诊断，不等于远端服务一定接受当前 refresh token
- 当前新增的诊断包是脱敏 JSON，适合排障，但仍会暴露路径、脱敏账号标签、profile 名称和系统环境摘要，因此不应公开分享
- `recover` 只处理当前能正确解析的事务文件；如果磁盘上存在损坏的事务 JSON，仍可能需要人工清理
- discovery trace 解释的是本地规则展开和本地凭证查找路径；如果官方后续改了 service/account 命名，trace 仍可能全部是 lookup_missed
- non-destructive switch probes 只能说明当前目录和锁路径在 probe 时刻可用，不代表外部进程之后不会重新占用或改写这些位置
- profile preflight 也是本地即时判断；即使某次 `check` 显示 ready，后续环境变化仍可能让真正的 `use` 失败并进入回滚
- snapshot provenance 记录的是保存当时的来源平台与 store，可用于兼容性提醒，但不能单独证明跨平台导入后的官方会话一定可用
- `doctor` 的 profile inventory 复用的是同一套本地 preflight 规则，所以它适合做整机筛查，不应被理解成官方在线验活结果

### 安全擦除只能最佳努力

MVP 使用的是“删除文件和事务备份”的最佳努力策略。在 SSD、APFS、NTFS journaling、copy-on-write 文件系统上，不能承诺物理层彻底擦除。

### Windows 适配需在 Windows 环境验证

当前仓库里已经有 `WindowsCredentialStore` 接口实现入口，但完整行为仍需在真实 Windows 环境中编译和验证。

## 边界条件

- `auth.json` 不存在时，`detect/current/save` 会失败
- 删除当前 active profile 时会清空当前绑定
- 删除默认 profile 时会清空默认配置
- 导入包若名字冲突，会自动生成 `-imported` 后缀
- 导入包若 `profile_id` 冲突，会自动重新生成新 ID
- 系统凭证条目非空且当前平台没有可用 credential store 时，切换会被拒绝
