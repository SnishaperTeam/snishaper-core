# log 包

> 导入路径：`github.com/SnishaperTeam/snishaper-core/log`

## 概述

`log` 定义 snishaper-core 全库使用的最小日志契约。库从不自行向标准 logger 写日志：每个包都通过函数式选项或 setter 接收一个 Logger，未注入时回退到 `Nop`。

## Logger

所有 snishaper-core 包接受的日志接口。实现必须并发安全。

```go
type Logger interface {
    Printf(format string, args ...any)
}
```

## 预置实现

### Nop

```go
var Nop Logger = nopLogger{}
```

静默丢弃所有输出。它是未注入 logger 时的默认值，因此未配置的库从不在任何地方自行输出。

### Std

```go
var Std Logger = stdLogger{}
```

把标准库 logger 适配为 Logger。供希望 snishaper-core 输出进入进程日志的嵌入方使用。

```go
cm, err := certmanager.InitCertManager(dir, certmanager.WithLogger(log.Std))
```

## Func

```go
func Func(fn func(format string, args ...any)) Logger
```

把一个 printf 风格的函数适配为 Logger。

```go
var l log.Logger = log.Func(func(format string, args ...any) {
    slog.Info(fmt.Sprintf(format, args...))
})
```
