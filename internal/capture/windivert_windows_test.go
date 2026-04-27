//go:build windows

package capture

import (
	"strings"
	"testing"

	divert "github.com/imgk/divert-go"
	"golang.org/x/sys/windows"
)

func TestNormalizeOpenErrorServiceDisabled(t *testing.T) {
	err := normalizeOpenError(divert.Error(windows.ERROR_SERVICE_DISABLED))
	if err == nil {
		t.Fatal("expected translated error")
	}
	for _, want := range []string{"WinDivert", "禁用", "sc.exe config WinDivert start= demand"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("expected %q in error, got %v", want, err)
		}
	}
}

func TestNormalizeOpenErrorZeroCode(t *testing.T) {
	err := normalizeOpenError(divert.Error(0))
	if err == nil {
		t.Fatal("expected translated error")
	}
	for _, want := range []string{"空错误码", "WinDivert", "服务状态异常"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("expected %q in error, got %v", want, err)
		}
	}
}
