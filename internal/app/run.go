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
		logger.Info(
			"程序已启动",
			"target_ip", cfg.TargetIP.String(),
			"target_host", cfg.TargetHost,
			"target_port", cfg.TargetPort,
			"mutate_direction", cfg.MutateDirection,
		)
	}

	outFilter, inFilter := capture.BuildFilters(cfg)

	if cfg.TargetHost == "" {
		outObserveHandle, outBlockHandle, err := openOutboundHandlesForDirectMode(cfg, outFilter)
		if err != nil {
			return err
		}
		if outObserveHandle != nil {
			defer outObserveHandle.Close()
		}
		if outBlockHandle != nil {
			defer outBlockHandle.Close()
		}

		inObserveHandle, inBlockHandle, err := openInboundHandlesForDirectMode(cfg, inFilter)
		if err != nil {
			return err
		}
		if inObserveHandle != nil {
			defer inObserveHandle.Close()
		}
		if inBlockHandle != nil {
			defer inBlockHandle.Close()
		}

		return capture.RunDirectLoop(ctx, cfg, logger, outObserveHandle, outBlockHandle, inObserveHandle, inBlockHandle)
	}

	outObserveHandle, err := capture.OpenObserveHandleWithPriority(outFilter, divert.PriorityHighest)
	if err != nil {
		return err
	}
	defer outObserveHandle.Close()

	inObserveHandle, err := capture.OpenObserveHandleWithPriority(inFilter, divert.PriorityHighest)
	if err != nil {
		return err
	}
	defer inObserveHandle.Close()

	blockFactory := func(key session.Key) (*capture.Handle, error) {
		filter := hostBlockFilter(cfg, key)
		handle, err := capture.OpenHandleWithPriority(filter, divert.PriorityDefault)
		if err != nil {
			return nil, fmt.Errorf("为命中连接创建专用阻断句柄失败: %w", err)
		}
		return handle, nil
	}

	return capture.RunHostMatchLoop(ctx, cfg, logger, outObserveHandle, inObserveHandle, blockFactory)
}

func openInboundHandlesForDirectMode(cfg config.Config, filter string) (*capture.Handle, *capture.Handle, error) {
	if cfg.MutateDirection == "in" || cfg.MutateDirection == "both" {
		handle, err := capture.OpenHandle(filter)
		return nil, handle, err
	}
	handle, err := capture.OpenObserveHandle(filter)
	return handle, nil, err
}

func openOutboundHandlesForDirectMode(cfg config.Config, filter string) (*capture.Handle, *capture.Handle, error) {
	if cfg.MutateDirection == "in" {
		handle, err := capture.OpenObserveHandle(filter)
		return handle, nil, err
	}
	handle, err := capture.OpenHandle(filter)
	return nil, handle, err
}

func hostBlockFilter(cfg config.Config, key session.Key) string {
	switch cfg.MutateDirection {
	case "in":
		return capture.BuildInboundConnectionFilter(key)
	case "both":
		return capture.BuildBidirectionalConnectionFilter(key)
	default:
		return capture.BuildOutboundConnectionFilter(key)
	}
}
