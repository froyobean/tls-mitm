// Package app 负责串联配置、抓包与主运行流程。
package app

import (
	"context"
	"fmt"
	"log/slog"

	divert "github.com/imgk/divert-go"

	"tls-mitm/internal/capture"
	"tls-mitm/internal/config"
	"tls-mitm/internal/session"
)

// Run 启动抓包循环并管理 WinDivert 句柄生命周期。
func Run(ctx context.Context, cfg config.Config, logger *slog.Logger) error {
	if logger != nil {
		logger.Info("程序已启动", "target_ip", cfg.TargetIP.String(), "target_host", cfg.TargetHost, "target_port", cfg.TargetPort)
	}

	outFilter, inFilter := capture.BuildFilters(cfg)

	inHandle, err := capture.OpenObserveHandle(inFilter)
	if err != nil {
		return err
	}
	defer inHandle.Close()

	if cfg.TargetHost == "" {
		outHandle, err := capture.OpenHandle(outFilter)
		if err != nil {
			return err
		}
		defer outHandle.Close()

		return capture.RunLoop(ctx, cfg, logger, outHandle, inHandle)
	}

	outObserveHandle, err := capture.OpenObserveHandleWithPriority(outFilter, divert.PriorityHighest)
	if err != nil {
		return err
	}
	defer outObserveHandle.Close()

	blockFactory := func(key session.Key) (*capture.Handle, error) {
		filter := capture.BuildOutboundConnectionFilter(key)
		handle, err := capture.OpenHandleWithPriority(filter, divert.PriorityDefault)
		if err != nil {
			return nil, fmt.Errorf("为命中连接创建专用阻断句柄失败: %w", err)
		}
		return handle, nil
	}

	return capture.RunHostMatchLoop(ctx, cfg, logger, outObserveHandle, inHandle, blockFactory)
}
