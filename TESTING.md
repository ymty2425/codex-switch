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
