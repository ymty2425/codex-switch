# Testing

## 已实现测试

### Domain

```bash
cargo test -p codex-switch-domain
```

覆盖：

- 账号脱敏逻辑
- live 指纹对认证文件变化的敏感性

### Platform

```bash
cargo test -p codex-switch-platform
```

覆盖：

- 路径发现覆盖逻辑
- `auth.json` 解析与账号推断
- 系统凭证 registry 模板展开与 mixed-mode 探测
- `config.json` 自定义 discovery rules 的加载与保留
- `doctor` 对缺失 auth 文件和 discovery rule 数量的诊断
- 本地 vault 的导出导入加密回环

### Application

```bash
cargo test -p codex-switch-application
```

覆盖：

- `save -> use -> current -> sync -> export -> import`
- active profile 的 drift 检测
- `current` 对 active profile 漂移后的 `needs_sync` 状态判断
- 设置默认 profile 不应隐式切换 live session
- `detect/current` 的序列化输出不应带出原始 `auth.json` 内容
- 脱敏诊断包导出不能带出 access token / refresh token
- `doctor` 应暴露待恢复事务，`recover` 应恢复备份文件并清理事务残留
- `doctor` 的 discovery trace 应正确区分 matched / missing_input / lookup_missed
- `doctor` 的 switch probes 应报告数据目录写入、锁获取与同目录原子替换能力
- `check` 应为目标 profile 输出 preflight blocker / warning，并在 system store 缺失时阻止 mixed profile 被判定为 ready
- 新保存的 snapshot 应记录来源平台 provenance；旧 snapshot 在反序列化时应默认回退到 `unknown`
- 导出再导入后的 profile 应保留 snapshot provenance，并在来源 store 与当前 store 不同时给出 warning
- `doctor` 应输出所有已保存 profile 的 readiness inventory，并在 blocked profile 存在时给出对应建议
- `doctor` 应输出 store usage summary，并在某个 store 挡住 profile 时给出点名该 store 的建议
- 与真实 `auth.json` 结构一致的探测形状

### CLI

```bash
cargo test -p codex-switch-cli
```

覆盖：

- 口令环境变量读取

## 推荐补充验证

### Workspace Rust 验证

```bash
cargo fmt --all
cargo test -p codex-switch-domain
cargo test -p codex-switch-platform
cargo test -p codex-switch-application
cargo test -p codex-switch-cli
```

### Desktop 验证

```bash
npm install
npm --workspace apps/desktop run build
cargo check -p codex-switch-desktop
```

## 手工验证场景

1. 在真实 `CODEX_HOME` 下执行 `detect`
2. 保存两个不同账号 profile
3. 在两个 profile 之间来回切换
4. 让官方客户端刷新 token 后执行 `check`
5. 运行 `sync`
6. 导出并重新导入 profile
7. 模拟切换中断后重启，再确认恢复逻辑生效
