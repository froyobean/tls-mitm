// Package config 负责解析命令行参数并构造运行时配置。
package config

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"text/tabwriter"
	"time"
)

// Config 描述程序运行所需的配置。
type Config struct {
	TargetIP        netip.Addr
	TargetHost      string
	TargetPort      uint16
	ObserveTimeout  time.Duration
	LogFormat       string
	MutateOffset    int
	MutateDirection string
	HostMatch       string
	UnsafeAnyHost   bool
}

// ErrHelpRequested 表示用户请求输出帮助信息。
var ErrHelpRequested = errors.New("help requested")

// ParseArgs 解析命令行参数并返回经过校验的 Config。
func ParseArgs(args []string) (Config, error) {
	fs := newFlagSet(io.Discard)

	targetIP, targetHost, targetPort, observeTimeout, logFormat, mutateOffset, mutateDirection, hostMatch, unsafeAnyHost, showHelp := bindFlags(fs)

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return Config{}, ErrHelpRequested
		}
		return Config{}, err
	}
	if *showHelp {
		return Config{}, ErrHelpRequested
	}

	normalizedTargetIP := strings.TrimSpace(*targetIP)
	normalizedTargetHost := normalizeTargetHost(*targetHost)
	normalizedMutateDirection := normalizeMutateDirection(*mutateDirection)
	normalizedHostMatch := normalizeHostMatch(*hostMatch)
	normalizedLogFormat := normalizeLogFormat(*logFormat)

	if normalizedTargetIP == "" && normalizedTargetHost == "" && !*unsafeAnyHost {
		return Config{}, errors.New("至少需要提供 target-ip 或 target-host；如果要按端口匹配所有主机，请显式添加 -unsafe-any-host")
	}
	if *targetPort <= 0 || *targetPort > 65535 {
		return Config{}, fmt.Errorf("无效的目标端口: %d", *targetPort)
	}
	if normalizedMutateDirection == "" {
		normalizedMutateDirection = "out"
	}
	if normalizedMutateDirection != "out" && normalizedMutateDirection != "in" && normalizedMutateDirection != "both" {
		return Config{}, fmt.Errorf("无效的 -mutate-direction: %s（仅支持 out、in 或 both）", normalizedMutateDirection)
	}
	if normalizedHostMatch == "" {
		normalizedHostMatch = "sni"
	}
	if normalizedHostMatch != "sni" && normalizedHostMatch != "dns" && normalizedHostMatch != "both" {
		return Config{}, fmt.Errorf("无效的 -host-match: %s（仅支持 sni、dns 或 both）", normalizedHostMatch)
	}
	if (normalizedHostMatch == "dns" || normalizedHostMatch == "both") && normalizedTargetHost == "" {
		return Config{}, errors.New("-host-match dns 或 both 需要提供 target-host")
	}
	if normalizedLogFormat == "" {
		normalizedLogFormat = "text"
	}
	if normalizedLogFormat != "text" && normalizedLogFormat != "json" {
		return Config{}, fmt.Errorf("无效的 -log-format: %s（仅支持 text 或 json）", normalizedLogFormat)
	}

	var addr netip.Addr
	if normalizedTargetIP != "" {
		parsed, err := netip.ParseAddr(normalizedTargetIP)
		if err != nil {
			return Config{}, fmt.Errorf("解析目标 IP 失败: %w", err)
		}
		if !parsed.Is4() && !parsed.Is6() {
			return Config{}, fmt.Errorf("无效的目标 IP: %s", normalizedTargetIP)
		}
		addr = parsed
	}

	return Config{
		TargetIP:        addr,
		TargetHost:      normalizedTargetHost,
		TargetPort:      uint16(*targetPort),
		ObserveTimeout:  *observeTimeout,
		LogFormat:       normalizedLogFormat,
		MutateOffset:    *mutateOffset,
		MutateDirection: normalizedMutateDirection,
		HostMatch:       normalizedHostMatch,
		UnsafeAnyHost:   *unsafeAnyHost,
	}, nil
}

// Usage 返回命令行帮助文本。
func Usage() string {
	var builder strings.Builder
	builder.WriteString("用法:\n")
	builder.WriteString("  tls-mitm -target-port <端口> [-target-ip <IP>] [-target-host <域名>] [可选参数]\n\n")
	builder.WriteString("必填参数:\n")
	renderUsageTable(&builder, []usageItem{
		{name: "-target-port <端口>", description: "目标服务器端口"},
	})
	builder.WriteString("\n可选参数:\n")
	renderUsageTable(&builder, []usageItem{
		{name: "-target-ip <IP>", description: "目标服务器 IP 地址"},
		{name: "-target-host <域名>", description: "目标服务器 TLS SNI 域名"},
		{name: "-observe-timeout <时长>", description: "篡改后的观察窗口", defaultValue: "5s"},
		{name: "-log-format <格式>", description: "日志格式，可选 text 或 json", defaultValue: "text"},
		{name: "-mutate-offset <偏移>", description: "命中 record 后要翻转的密文字节偏移", defaultValue: "0"},
		{name: "-mutate-direction <方向>", description: "篡改方向：out、in 或 both", defaultValue: "out"},
		{name: "-host-match <模式>", description: "域名命中方式：sni、dns 或 both", defaultValue: "sni"},
		{name: "-unsafe-any-host", description: "显式允许按目标端口匹配所有主机"},
		{name: "-h, -help", description: "显示帮助信息"},
	})
	builder.WriteString("\n示例:\n")
	builder.WriteString("  tls-mitm -target-ip 93.184.216.34 -target-port 443\n")
	builder.WriteString("  tls-mitm -target-host example.com -target-port 443\n")
	builder.WriteString("  tls-mitm -target-ip 93.184.216.34 -target-host example.com -target-port 443\n")
	builder.WriteString("  tls-mitm -target-ip 93.184.216.34 -target-port 443 -mutate-direction out\n")
	builder.WriteString("  tls-mitm -target-host example.com -target-port 443 -mutate-direction in\n")
	builder.WriteString("  tls-mitm -target-host example.com -target-port 443 -mutate-direction both\n")
	builder.WriteString("  tls-mitm -target-host example.com -target-port 443 -host-match both\n")
	builder.WriteString("  tls-mitm -target-host www.bing.com -target-port 443 -host-match dns\n")
	builder.WriteString("  tls-mitm -target-port 443 -unsafe-any-host\n")
	builder.WriteString("\n约束:\n")
	builder.WriteString("  -target-ip 与 -target-host 至少提供一个，可以同时提供。\n")
	builder.WriteString("  若未提供 -target-ip 和 -target-host，则必须显式添加 -unsafe-any-host。\n")
	return builder.String()
}

func newFlagSet(output io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet("tls-mitm", flag.ContinueOnError)
	fs.SetOutput(output)
	return fs
}

func bindFlags(fs *flag.FlagSet) (*string, *string, *int, *time.Duration, *string, *int, *string, *string, *bool, *bool) {
	targetIP := fs.String("target-ip", "", "目标 IP")
	targetHost := fs.String("target-host", "", "目标域名")
	targetPort := fs.Int("target-port", 0, "目标端口")
	observeTimeout := fs.Duration("observe-timeout", 5*time.Second, "观察超时")
	logFormat := fs.String("log-format", "text", "日志格式")
	mutateOffset := fs.Int("mutate-offset", 0, "篡改偏移")
	mutateDirection := fs.String("mutate-direction", "out", "篡改方向：out、in 或 both")
	hostMatch := fs.String("host-match", "sni", "域名命中方式：sni、dns 或 both")
	unsafeAnyHost := fs.Bool("unsafe-any-host", false, "显式允许按目标端口匹配所有主机")
	showHelp := fs.Bool("h", false, "显示帮助信息")
	fs.BoolVar(showHelp, "help", false, "显示帮助信息")
	return targetIP, targetHost, targetPort, observeTimeout, logFormat, mutateOffset, mutateDirection, hostMatch, unsafeAnyHost, showHelp
}

func normalizeTargetHost(targetHost string) string {
	return strings.ToLower(strings.TrimSpace(targetHost))
}

func normalizeMutateDirection(mutateDirection string) string {
	return strings.ToLower(strings.TrimSpace(mutateDirection))
}

func normalizeHostMatch(hostMatch string) string {
	return strings.ToLower(strings.TrimSpace(hostMatch))
}

func normalizeLogFormat(logFormat string) string {
	return strings.ToLower(strings.TrimSpace(logFormat))
}

type usageItem struct {
	name         string
	description  string
	defaultValue string
}

func renderUsageTable(builder *strings.Builder, items []usageItem) {
	writer := tabwriter.NewWriter(builder, 0, 0, 2, ' ', 0)
	for _, item := range items {
		line := fmt.Sprintf("  %s\t%s", item.name, item.description)
		if item.defaultValue != "" {
			line += fmt.Sprintf("（默认值：%s）", item.defaultValue)
		}
		line += "\n"
		_, _ = writer.Write([]byte(line))
	}
	_ = writer.Flush()
}
