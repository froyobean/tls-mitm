//go:build windows

package capture

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	divert "github.com/imgk/divert-go"
	"golang.org/x/sys/windows"

	"tls-mitm/internal/config"
	"tls-mitm/internal/session"
)

// Handle 封装一份 WinDivert 句柄及其关闭逻辑。
type Handle struct {
	h         *divert.Handle
	closeOnce sync.Once
}

// OpenHandle 打开用于出站抓取和重注入的 WinDivert 句柄。
func OpenHandle(filter string) (*Handle, error) {
	return openHandle(filter, divert.PriorityDefault, divert.FlagDefault)
}

// OpenObserveHandle 打开仅用于观察入站数据的 WinDivert 句柄。
func OpenObserveHandle(filter string) (*Handle, error) {
	return openHandle(filter, divert.PriorityDefault, divert.FlagSniff)
}

// OpenHandleWithPriority 打开一个指定优先级的阻断/重注入句柄。
func OpenHandleWithPriority(filter string, priority int16) (*Handle, error) {
	return openHandle(filter, priority, divert.FlagDefault)
}

// OpenObserveHandleWithPriority 打开一个指定优先级的观察句柄。
func OpenObserveHandleWithPriority(filter string, priority int16) (*Handle, error) {
	return openHandle(filter, priority, divert.FlagSniff)
}

// RunHostMatchLoop 运行基于 SNI 命中的“先观察、后阻断”主循环。
func RunHostMatchLoop(
	ctx context.Context,
	cfg config.Config,
	logger *slog.Logger,
	outObserveHandle, inHandle *Handle,
	newBlockHandle func(key session.Key) (*Handle, error),
) error {
	var factory blockerFactory
	if newBlockHandle != nil {
		factory = func(key session.Key) (packetHandle, error) {
			return newBlockHandle(key)
		}
	}
	return runLoopWithHandles(ctx, cfg, logger, outObserveHandle, nil, inHandle, factory)
}

func openHandle(filter string, priority int16, flags uint64) (*Handle, error) {
	handle, err := divert.Open(filter, divert.Layer(0), priority, flags)
	if err != nil {
		return nil, normalizeOpenError(err)
	}
	return &Handle{h: handle}, nil
}

// Recv 从 WinDivert 句柄读取一个数据包及其地址信息。
func (h *Handle) Recv() ([]byte, any, error) {
	buf := make([]byte, divert.MTUMax)
	addr := &divert.Address{}
	n, err := h.h.Recv(buf, addr)
	if err != nil {
		return nil, nil, err
	}
	return append([]byte(nil), buf[:n]...), addr, nil
}

// Send 重算校验和后将数据包重新注入网络栈。
func (h *Handle) Send(packet []byte, addr any) error {
	divertAddr, ok := addr.(*divert.Address)
	if !ok {
		return fmt.Errorf("WinDivert 地址类型不匹配: %T", addr)
	}

	divert.CalcChecksums(packet, divertAddr, divert.ChecksumDefault)
	_, err := h.h.Send(packet, divertAddr)
	return err
}

// Close 关闭底层 WinDivert 句柄。
func (h *Handle) Close() error {
	if h == nil || h.h == nil {
		return nil
	}

	var err error
	h.closeOnce.Do(func() {
		err = h.h.Close()
	})
	return err
}

func normalizeOpenError(err error) error {
	if err == nil {
		return nil
	}

	var divertErr divert.Error
	if errors.As(err, &divertErr) {
		// WinDivert 把底层 Windows 错误码直接透传上来，这里补一层更面向操作者的中文诊断。
		switch windows.Errno(divertErr) {
		case windows.ERROR_SERVICE_DISABLED:
			return fmt.Errorf("打开 WinDivert 失败: 当前 WinDivert 驱动服务处于禁用状态。请以管理员身份执行 `sc.exe config WinDivert start= demand` 后重试；如果仍有问题，可先执行 `sc.exe delete WinDivert` 再重新运行程序让驱动自动重建: %w", err)
		case windows.EPT_S_NOT_REGISTERED:
			return fmt.Errorf("打开 WinDivert 失败: Base Filtering Engine (BFE) 服务未启用，请先启用并启动该服务: %w", err)
		case windows.ERROR_FILE_NOT_FOUND:
			return fmt.Errorf("打开 WinDivert 失败: 未找到 WinDivert 驱动文件，请确认 `WinDivert64.sys` 与可执行文件位于同一目录或驱动已正确安装: %w", err)
		case windows.ERROR_ACCESS_DENIED:
			return fmt.Errorf("打开 WinDivert 失败: 当前进程缺少管理员权限，请使用管理员身份运行: %w", err)
		case 0:
			return fmt.Errorf("打开 WinDivert 失败: 收到了空错误码，这通常意味着 WinDivert 驱动服务状态异常或 `divert_cgo` 路径返回了不完整的错误信息，请优先检查 WinDivert 服务状态: %w", err)
		}
	}

	if err.Error() == "The operation completed successfully." {
		// `divert_cgo` 路径偶尔会把失败场景折叠成空错误码，这里把它改写成可排障的信息。
		return fmt.Errorf("打开 WinDivert 失败: 收到了空错误码，这通常意味着 WinDivert 驱动服务状态异常或 `divert_cgo` 路径返回了不完整的错误信息，请优先检查 WinDivert 服务状态: %w", err)
	}

	return err
}
