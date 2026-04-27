//go:build !windows

package capture

import "fmt"

// Handle 是非 Windows 平台上的占位句柄类型。
type Handle struct{}

// OpenHandle 在非 Windows 平台上始终返回不支持错误。
func OpenHandle(filter string) (*Handle, error) {
	return nil, fmt.Errorf("WinDivert 仅支持 Windows: %s", filter)
}

// OpenObserveHandle 在非 Windows 平台上始终返回不支持错误。
func OpenObserveHandle(filter string) (*Handle, error) {
	return nil, fmt.Errorf("WinDivert 仅支持 Windows: %s", filter)
}

// Recv 在非 Windows 平台上始终返回不支持错误。
func (h *Handle) Recv() ([]byte, any, error) {
	return nil, nil, fmt.Errorf("WinDivert 仅支持 Windows")
}

// Send 在非 Windows 平台上始终返回不支持错误。
func (h *Handle) Send(packet []byte, addr any) error {
	return fmt.Errorf("WinDivert 仅支持 Windows")
}

// Close 在非 Windows 平台上是空操作。
func (h *Handle) Close() error {
	return nil
}
