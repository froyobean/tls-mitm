// Package logging 提供项目统一使用的日志构造函数。
package logging

import (
	"io"
	"log/slog"
)

// New 根据格式创建一份写入到 w 的 slog.Logger。
func New(format string, w io.Writer) *slog.Logger {
	var handler slog.Handler

	switch format {
	case "json":
		handler = slog.NewJSONHandler(w, &slog.HandlerOptions{Level: slog.LevelInfo})
	default:
		handler = slog.NewTextHandler(w, &slog.HandlerOptions{Level: slog.LevelInfo})
	}

	return slog.New(handler)
}
