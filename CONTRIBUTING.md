# 贡献指南

感谢你考虑为 snishaper-core 贡献！

## 开发门槛

提交前以下命令必须全部通过：

```powershell
go build ./...
go vet ./...
go test ./...
```

## 库约束

snishaper-core 必须保持可嵌入性，评审将重点检查：

- **零全局可变状态**：禁止 `init()`、包级可变变量、启动期环境变量读取、`os.Exit`。
- **注入式行为**：日志经 `log.Logger` 注入（默认 `Nop`）；调试开关经 functional options 注入。
- **导出 API 需 doc 注释**：新增导出标识符必须带注释。
- **配置语义兼容**：不得破坏与 SniShaper 应用侧共享的 JSON 配置语义。

## 提交规范

- Commit message 使用**英文**，conventional-commit 风格（`feat:` / `fix:` / `refactor:` / `docs:` …）。
- 一个提交聚焦一件事；重构与功能不混提。

## 提交流程

1. Fork 本仓库并创建特性分支。
2. 提交 PR 到 `main`，描述动机与验证方式（构建 / 测试结果）。

## 许可

提交贡献即表示你同意以 **[AGPL-3.0](LICENSE)** 授权你的贡献。
