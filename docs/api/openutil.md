# openutil 包

> 导入路径：`github.com/SnishaperTeam/snishaper-core/openutil`

## 概述

`openutil` 把「用系统默认处理器打开目标」和「在文件管理器中显示文件」两个操作封装为跨平台 API：

- **Windows**：`OpenTarget` 用 `ShellExecuteW`（「用默认处理器打开」的文档化 shell 入口）；`RevealPath` 用 `SHOpenFolderAndSelectItems`（正是此任务的文档化 shell API，接受 PIDL，不存在引号转义问题）。早先的 `cmd /c start "" <target>` 形式会让目标经过 cmd.exe 的第二层解析器，`exec.Command` 不转义 shell 元字符，包含 `&`、`|`、`^` 或 `%` 的路径行为不可预测；`explorer.exe /select,<path>` 则是未文档化约定，现均已弃用。
- **macOS**：分别通过 `open` 与 `open -R` 实现。
- **其他 Unix**：`OpenTarget` 通过 `xdg-open` 实现；`RevealPath` 在 Linux 上没有可移植等价物，退化为打开所在目录（`xdg-open filepath.Dir(path)`）。

`ShellExecuteW` 返回值大于 32 才算成功，否则作为错误码上报——此处静默失败意味着用户点了「打开文件夹」却什么都没发生。PIDL 来自 shell 私有分配器，只能用 `ILFree` 释放。

## 函数

### OpenTarget

```go
func OpenTarget(target string) error
```

把文件、目录或 URL 交给 shell 的默认处理器（Windows：ShellExecuteW；macOS：`open`；Linux：`xdg-open`）。

```go
if err := openutil.OpenTarget(caCertPath); err != nil {
    return err
}
```

### RevealPath

```go
func RevealPath(path string) error
```

打开文件管理器并选中给定文件（Windows：SHOpenFolderAndSelectItems；macOS：`open -R`；Linux：打开所在目录）。路径中含空格、逗号或 shell 元字符时同样正确处理。

```go
if err := openutil.RevealPath(cm.GetCACertPath()); err != nil {
    return err
}
```
