# atomicfile 包

> 导入路径：`github.com/SnishaperTeam/snishaper-core/atomicfile`

## 概述

`atomicfile` 提供原子文件写入：先在目标目录写一个唯一命名的临时文件，`Sync` 落盘后 rename 到目标路径，再同步目录。崩溃或并发写入永远不会留下截断的目标文件（rename 在同一目录内、同一文件系统上，是原子的）。父目录不存在时自动以 0755 创建。

## 函数

### Write

```go
func Write(path string, data []byte, perm os.FileMode) error
```

把 data 原子写入 path（权限 perm）。流程：`MkdirAll` 父目录 → `CreateTemp` 写临时文件（`<base>.tmp*` 命名）→ `Write` + `Sync` → `Close` → `Chmod(perm)` → `Rename` 到 path → 打开并同步父目录。中途任一步失败都会清理临时文件并返回错误。

```go
if err := atomicfile.Write(caPath, caPEM, 0644); err != nil {
    return err
}
if err := atomicfile.Write(keyPath, keyPEM, 0600); err != nil {
    return err
}
```
