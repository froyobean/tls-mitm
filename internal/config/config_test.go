package config

import (
	"errors"
	"strings"
	"testing"
)

func TestParseArgsSuccess(t *testing.T) {
	cfg, err := ParseArgs([]string{"-target-ip", "93.184.216.34", "-target-port", "443", "-observe-timeout", "5s", "-mutate-offset", "2"})
	if err != nil {
		t.Fatalf("ParseArgs returned error: %v", err)
	}
	if cfg.TargetIP.String() != "93.184.216.34" || cfg.TargetPort != 443 || cfg.MutateOffset != 2 {
		t.Fatalf("unexpected config: %+v", cfg)
	}
}

func TestParseArgsSupportsTargetHostOnly(t *testing.T) {
	cfg, err := ParseArgs([]string{"-target-host", "  Example.COM \t", "-target-port", "443"})
	if err != nil {
		t.Fatalf("ParseArgs returned error: %v", err)
	}
	if cfg.TargetHost != "example.com" || cfg.TargetPort != 443 {
		t.Fatalf("unexpected config: %+v", cfg)
	}
}

func TestParseArgsSupportsTargetIPAndTargetHost(t *testing.T) {
	cfg, err := ParseArgs([]string{"-target-ip", "93.184.216.34", "-target-host", "example.com", "-target-port", "443"})
	if err != nil {
		t.Fatalf("ParseArgs returned error: %v", err)
	}
	if cfg.TargetIP.String() != "93.184.216.34" || cfg.TargetHost != "example.com" || cfg.TargetPort != 443 {
		t.Fatalf("unexpected config: %+v", cfg)
	}
}

func TestParseArgsRejectsMissingTargetSelectors(t *testing.T) {
	if _, err := ParseArgs([]string{"-target-port", "443"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestParseArgsSupportsUnsafeAnyHostWithoutTargetSelectors(t *testing.T) {
	cfg, err := ParseArgs([]string{"-target-port", "443", "-unsafe-any-host"})
	if err != nil {
		t.Fatalf("ParseArgs returned error: %v", err)
	}
	if !cfg.UnsafeAnyHost || cfg.TargetPort != 443 {
		t.Fatalf("unexpected config: %+v", cfg)
	}
}

func TestParseArgsRejectsBadIP(t *testing.T) {
	if _, err := ParseArgs([]string{"-target-ip", "bad", "-target-port", "443"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestParseArgsHelp(t *testing.T) {
	if _, err := ParseArgs([]string{"-h"}); !errors.Is(err, ErrHelpRequested) {
		t.Fatalf("expected ErrHelpRequested, got %v", err)
	}
}

func TestUsageIncludesFlags(t *testing.T) {
	usage := Usage()
	for _, want := range []string{"-h", "-target-ip", "-target-host", "-target-port", "-observe-timeout", "-log-format", "-mutate-offset", "-unsafe-any-host"} {
		if !strings.Contains(usage, want) {
			t.Fatalf("usage missing %q: %s", want, usage)
		}
	}
}

func TestUsageIncludesSectionsAndExample(t *testing.T) {
	usage := Usage()
	for _, want := range []string{
		"用法:",
		"必填参数:",
		"可选参数:",
		"示例:",
		"tls-mitm -target-ip 93.184.216.34 -target-port 443",
		"tls-mitm -target-host example.com -target-port 443",
		"tls-mitm -target-ip 93.184.216.34 -target-host example.com -target-port 443",
		"tls-mitm -target-port 443 -unsafe-any-host",
	} {
		if !strings.Contains(usage, want) {
			t.Fatalf("usage missing %q: %s", want, usage)
		}
	}
}

func TestUsageKeepsFlagOrder(t *testing.T) {
	usage := Usage()
	targetPortIndex := strings.Index(usage, "-target-port")
	targetIPIndex := strings.Index(usage, "-target-ip")
	targetHostIndex := strings.Index(usage, "-target-host")
	observeTimeoutIndex := strings.Index(usage, "-observe-timeout")
	logFormatIndex := strings.Index(usage, "-log-format")
	mutateOffsetIndex := strings.Index(usage, "-mutate-offset")
	unsafeAnyHostIndex := strings.Index(usage, "-unsafe-any-host")
	helpIndex := strings.Index(usage, "-h, -help")
	if !(targetPortIndex < targetIPIndex &&
		targetIPIndex < targetHostIndex &&
		targetHostIndex < observeTimeoutIndex &&
		observeTimeoutIndex < logFormatIndex &&
		logFormatIndex < mutateOffsetIndex &&
		mutateOffsetIndex < unsafeAnyHostIndex &&
		unsafeAnyHostIndex < helpIndex) {
		t.Fatalf("unexpected usage order: %s", usage)
	}
}

func TestUsageIncludesTargetHostHelpAndExamples(t *testing.T) {
	usage := Usage()
	for _, want := range []string{
		"-target-host <域名>",
		"目标服务器 TLS SNI 域名",
		"-target-ip 与 -target-host 至少提供一个，可以同时提供。",
		"tls-mitm -target-host example.com -target-port 443",
		"tls-mitm -target-ip 93.184.216.34 -target-host example.com -target-port 443",
	} {
		if !strings.Contains(usage, want) {
			t.Fatalf("usage missing %q: %s", want, usage)
		}
	}
}

func TestUsageIncludesTargetSelectorConstraint(t *testing.T) {
	usage := Usage()
	want := "-target-ip 与 -target-host 至少提供一个，可以同时提供。"
	if !strings.Contains(usage, want) {
		t.Fatalf("usage missing %q: %s", want, usage)
	}
}

func TestUsageIncludesUnsafeAnyHostConstraint(t *testing.T) {
	usage := Usage()
	for _, want := range []string{
		"-unsafe-any-host",
		"显式允许按目标端口匹配所有主机",
		"若未提供 -target-ip 和 -target-host，则必须显式添加 -unsafe-any-host。",
		"tls-mitm -target-port 443 -unsafe-any-host",
	} {
		if !strings.Contains(usage, want) {
			t.Fatalf("usage missing %q: %s", want, usage)
		}
	}
}
