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
