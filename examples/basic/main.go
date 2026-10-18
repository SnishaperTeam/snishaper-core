// Example basic demonstrates the minimal embedder: load rule files, start the
// hybrid HTTP/SOCKS5 proxy with logging wired to the standard logger, and
// shut down on Ctrl-C.
//
// Usage: go run ./examples/basic [listen-port]
package main

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	corelog "github.com/SnishaperTeam/snishaper-core/log"
	"github.com/SnishaperTeam/snishaper-core/proxy"
)

func main() {
	dir, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(os.Stderr, "getwd:", err)
		os.Exit(1)
	}

	// RuleManager 读取设置与规则文件；文件不存在时会生成默认配置。
	rm := proxy.NewRuleManager(
		filepath.Join(dir, "config", "settings.json"),
		filepath.Join(dir, "rules", "config.json"),
	)
	if err := rm.LoadConfig(); err != nil {
		fmt.Fprintln(os.Stderr, "load config:", err)
		os.Exit(1)
	}

	port := "8080"
	if len(os.Args) > 1 {
		port = os.Args[1]
	}

	p := proxy.NewProxyServer("127.0.0.1:"+port,
		proxy.WithRuleManager(rm),
		proxy.WithLogger(corelog.Std), // 库默认静默，显式注入才有日志
	)
	if err := p.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "start proxy:", err)
		os.Exit(1)
	}
	fmt.Printf("snishaper-core listening on 127.0.0.1:%s (HTTP + SOCKS5)\n", port)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	if err := p.Stop(); err != nil {
		fmt.Fprintln(os.Stderr, "stop proxy:", err)
		os.Exit(1)
	}
}
