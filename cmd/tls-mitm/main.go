// Command tls-mitm 是一个用于 TLS 密文篡改实验的命令行工具。
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"tls-mitm/internal/app"
	"tls-mitm/internal/config"
	"tls-mitm/internal/logging"
)

func main() {
	cfg, err := config.ParseArgs(os.Args[1:])
	if err != nil {
		if errors.Is(err, config.ErrHelpRequested) {
			fmt.Fprint(os.Stdout, config.Usage())
			return
		}
		log.Fatalf("解析参数失败: %v", err)
	}

	logger := logging.New(cfg.LogFormat, os.Stdout)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := app.Run(ctx, cfg, logger); err != nil {
		log.Fatalf("运行失败: %v", err)
	}
}
