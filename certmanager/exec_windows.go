package certmanager

import (
	"fmt"
	"os/exec"
	"strings"
	"syscall"
)

// hideWindow 设置命令在隐藏窗口中运行
func hideWindow(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.HideWindow = true
}

// runHiddenCommand 运行命令并隐藏窗口
func runHiddenCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	hideWindow(cmd)
	return cmd.Run()
}

// outputHiddenCommand 运行命令并隐藏窗口，返回输出
func outputHiddenCommand(name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	hideWindow(cmd)
	return cmd.Output()
}

func runElevatedCommand(name string, args ...string) error {
	escape := func(s string) string {
		return strings.ReplaceAll(s, "'", "''")
	}

	quotedArgs := make([]string, 0, len(args))
	for _, arg := range args {
		quotedArgs = append(quotedArgs, fmt.Sprintf("'%s'", escape(arg)))
	}

	// -ErrorAction Stop makes a declined UAC prompt a terminating error, and
	// the null check keeps a missing $p from exiting 0 — without both, the
	// caller is told the elevated command succeeded when it never ran.
	psScript := fmt.Sprintf(
		"$p = Start-Process -FilePath '%s' -ArgumentList @(%s) -Verb RunAs -Wait -PassThru -ErrorAction Stop; if ($null -eq $p) { exit 1 }; exit $p.ExitCode",
		escape(name),
		strings.Join(quotedArgs, ","),
	)

	cmd := exec.Command("powershell", "-NoProfile", "-Command", psScript)
	return cmd.Run()
}
