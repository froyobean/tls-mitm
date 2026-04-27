# 基于域名拦截护栏与危险模式 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 为 `host-only` 模式补上“先观察、后阻断”的护栏，并通过 `-unsafe-any-host` 把按端口影响所有主机的高风险行为改成显式授权。

**Architecture:** 保持既有 `target-ip`、`target-ip + target-host` 与出站最小重组链路不变，只在纯 `target-host` 模式上增加高优先级 `sniff` 观察句柄和按四元组创建的专用阻断句柄。配置层同步增加 `unsafe-any-host` 约束，帮助信息与 README 必须和新行为一致。

**Tech Stack:** Go、WinDivert（`github.com/imgk/divert-go`）、`log/slog`、`flag`、Go 单元测试

---

## 文件结构与职责

- `internal/config/config.go`
  - 命令行参数解析
  - `unsafe-any-host` 约束与帮助文案
- `internal/config/config_test.go`
  - 配置组合与帮助信息测试
- `internal/app/run.go`
  - 根据 `target-host` 是否存在选择“直接阻断”或“先观察后阻断”的主流程
- `internal/capture/windivert_windows.go`
  - WinDivert 句柄打开方式、优先级与 `sniff`/阻断类型封装
  - `RunHostMatchLoop` 桥接入口
- `internal/capture/loop.go`
  - 动态 blocker 创建、观察/阻断分流、host-only 连接命中与日志
- `internal/capture/loop_test.go`
  - host-only 护栏回归测试
- `README.md`
  - 四种模式、危险模式、运行示例

## 任务拆分

### Task 1: 配置层增加危险模式开关与显式约束

**Files:**
- Modify: `E:\code\GoProject\tls-mitm\internal\config\config.go`
- Test: `E:\code\GoProject\tls-mitm\internal\config\config_test.go`

- [ ] **Step 1: 先写失败测试，锁定危险模式约束**

```go
func TestParseArgsSupportsUnsafeAnyHostWithoutTargetSelectors(t *testing.T) {
	cfg, err := ParseArgs([]string{
		"-target-port", "443",
		"-unsafe-any-host",
	})
	if err != nil {
		t.Fatalf("expected unsafe-any-host mode to parse, got error: %v", err)
	}
	if !cfg.UnsafeAnyHost {
		t.Fatal("expected UnsafeAnyHost to be true")
	}
}

func TestParseArgsRejectsMissingTargetSelectorsWithoutUnsafeAnyHost(t *testing.T) {
	_, err := ParseArgs([]string{
		"-target-port", "443",
	})
	if err == nil {
		t.Fatal("expected parse to fail without target-ip/target-host/unsafe-any-host")
	}
}

func TestUsageIncludesUnsafeAnyHostConstraint(t *testing.T) {
	usage := Usage()
	if !strings.Contains(usage, "-unsafe-any-host") {
		t.Fatalf("expected usage to mention -unsafe-any-host, got: %s", usage)
	}
	if !strings.Contains(usage, "未提供 -target-ip 和 -target-host") {
		t.Fatalf("expected usage to explain selector constraint, got: %s", usage)
	}
}
```

- [ ] **Step 2: 运行配置测试，确认当前实现先失败**

Run: `go test ./internal/config -run "TestParseArgsSupportsUnsafeAnyHostWithoutTargetSelectors|TestParseArgsRejectsMissingTargetSelectorsWithoutUnsafeAnyHost|TestUsageIncludesUnsafeAnyHostConstraint" -count=1`

Expected: 至少有一个测试失败，提示缺少 `UnsafeAnyHost` 字段、帮助文案未包含新开关，或无约束错误。

- [ ] **Step 3: 在配置层增加 `UnsafeAnyHost` 字段、flag 绑定和约束**

```go
type Config struct {
	TargetIP       netip.Addr
	TargetHost     string
	TargetPort     uint16
	ObserveTimeout time.Duration
	LogFormat      string
	MutateOffset   int
	UnsafeAnyHost  bool
}

func ParseArgs(args []string) (Config, error) {
	fs := newFlagSet(io.Discard)

	targetIP, targetHost, targetPort, observeTimeout, logFormat, mutateOffset, unsafeAnyHost, showHelp := bindFlags(fs)

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

	if normalizedTargetIP == "" && normalizedTargetHost == "" && !*unsafeAnyHost {
		return Config{}, errors.New("至少需要提供 target-ip 或 target-host；如果要按端口匹配所有主机，请显式添加 -unsafe-any-host")
	}

	return Config{
		TargetIP:       addr,
		TargetHost:     normalizedTargetHost,
		TargetPort:     uint16(*targetPort),
		ObserveTimeout: *observeTimeout,
		LogFormat:      *logFormat,
		MutateOffset:   *mutateOffset,
		UnsafeAnyHost:  *unsafeAnyHost,
	}, nil
}

func bindFlags(fs *flag.FlagSet) (*string, *string, *int, *time.Duration, *string, *int, *bool, *bool) {
	targetIP := fs.String("target-ip", "", "目标 IP")
	targetHost := fs.String("target-host", "", "目标域名")
	targetPort := fs.Int("target-port", 0, "目标端口")
	observeTimeout := fs.Duration("observe-timeout", 5*time.Second, "观察超时")
	logFormat := fs.String("log-format", "text", "日志格式")
	mutateOffset := fs.Int("mutate-offset", 0, "篡改偏移")
	unsafeAnyHost := fs.Bool("unsafe-any-host", false, "显式允许按目标端口匹配所有主机")
	showHelp := fs.Bool("h", false, "显示帮助信息")
	fs.BoolVar(showHelp, "help", false, "显示帮助信息")
	return targetIP, targetHost, targetPort, observeTimeout, logFormat, mutateOffset, unsafeAnyHost, showHelp
}
```

- [ ] **Step 4: 更新帮助文案，明确危险模式与约束**

```go
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
		{name: "-target-ip <IP>", description: "按目标服务器 IP 匹配"},
		{name: "-target-host <域名>", description: "按 TLS SNI 域名匹配"},
		{name: "-unsafe-any-host", description: "显式允许按目标端口匹配所有主机"},
		{name: "-observe-timeout <时长>", description: "篡改后的观察窗口", defaultValue: "5s"},
		{name: "-log-format <格式>", description: "日志格式，可选 text 或 json", defaultValue: "text"},
		{name: "-mutate-offset <偏移>", description: "命中 record 后要翻转的密文字节偏移", defaultValue: "0"},
		{name: "-h, -help", description: "显示帮助信息"},
	})
	builder.WriteString("\n约束:\n")
	builder.WriteString("  -target-ip 和 -target-host 至少提供一个，可以同时提供。\n")
	builder.WriteString("  若未提供 -target-ip 和 -target-host，则必须显式添加 -unsafe-any-host。\n")
	return builder.String()
}
```

- [ ] **Step 5: 重新运行配置测试，确认全部通过**

Run: `go test ./internal/config -count=1`

Expected: PASS

- [ ] **Step 6: 提交配置层改动**

```bash
git add internal/config/config.go internal/config/config_test.go
git commit -m "feat: 增加危险模式开关与配置约束"
```

### Task 2: host-only 模式改为先观察后阻断

**Files:**
- Modify: `E:\code\GoProject\tls-mitm\internal\app\run.go`
- Modify: `E:\code\GoProject\tls-mitm\internal\capture\windivert_windows.go`

- [ ] **Step 1: 先写 host-only 句柄分流的失败测试**

在 `internal/capture/loop_test.go` 中增加两条测试：

```go
func TestDynamicHostOnlyModeDoesNotBlockMismatchedConnection(t *testing.T) {
	cfg := config.Config{
		TargetHost:     "example.com",
		TargetPort:     443,
		ObserveTimeout: 10 * time.Millisecond,
		MutateOffset:   0,
	}

	observe := &scriptedHandle{steps: []recvStep{
		{packet: outboundClientHelloPacket("other.example")},
		{packet: outboundTLSPacketWithSeq(uint32(len(outboundClientHelloPacket("other.example")) - 40))},
	}}
	factoryCalls := 0
	factory := func(key session.Key) (packetHandle, error) {
		factoryCalls++
		return &fakeHandle{}, nil
	}

	if err := runLoopWithHandles(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), observe, nil, nil, factory); err != nil {
		t.Fatalf("runLoopWithHandles returned error: %v", err)
	}
	if factoryCalls != 0 {
		t.Fatalf("expected mismatched host not to create blocker handle, got %d", factoryCalls)
	}
}

func TestDynamicHostOnlyModeMutatesThroughDedicatedBlocker(t *testing.T) {
	cfg := config.Config{
		TargetHost:     "example.com",
		TargetPort:     443,
		ObserveTimeout: 10 * time.Millisecond,
		MutateOffset:   0,
	}

	hello := outboundClientHelloPacket("example.com")
	observe := &scriptedHandle{steps: []recvStep{{packet: hello}}}
	blocker := &scriptedHandle{steps: []recvStep{
		{packet: outboundTLSPacketWithSeq(uint32(len(hello) - 40))},
	}}
	factory := func(key session.Key) (packetHandle, error) {
		return blocker, nil
	}

	if err := runLoopWithHandles(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), observe, nil, nil, factory); err != nil {
		t.Fatalf("runLoopWithHandles returned error: %v", err)
	}
	if len(blocker.sent) != 1 {
		t.Fatalf("expected blocker handle to reinject one mutated packet, got %d", len(blocker.sent))
	}
}
```

- [ ] **Step 2: 运行 host-only 测试，确认当前实现先失败**

Run: `go test ./internal/capture -run "TestDynamicHostOnlyModeDoesNotBlockMismatchedConnection|TestDynamicHostOnlyModeMutatesThroughDedicatedBlocker" -count=1`

Expected: FAIL，提示尚未支持动态 blocker 或 host-only 仍走统一阻断路径。

- [ ] **Step 3: 在 WinDivert 封装层增加优先级与 sniff 观察句柄接口**

```go
func OpenHandle(filter string) (*Handle, error) {
	return openHandle(filter, divert.PriorityDefault, divert.FlagDefault)
}

func OpenObserveHandle(filter string) (*Handle, error) {
	return openHandle(filter, divert.PriorityDefault, divert.FlagSniff)
}

func OpenHandleWithPriority(filter string, priority int16) (*Handle, error) {
	return openHandle(filter, priority, divert.FlagDefault)
}

func OpenObserveHandleWithPriority(filter string, priority int16) (*Handle, error) {
	return openHandle(filter, priority, divert.FlagSniff)
}

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
```

- [ ] **Step 4: 在应用入口按 `target-host` 选择句柄策略**

```go
func Run(ctx context.Context, cfg config.Config, logger *slog.Logger) error {
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
```

- [ ] **Step 5: 运行针对句柄分流的测试，确认通过**

Run: `go test ./internal/capture -run "TestDynamicHostOnlyModeDoesNotBlockMismatchedConnection|TestDynamicHostOnlyModeMutatesThroughDedicatedBlocker" -count=1`

Expected: PASS

- [ ] **Step 6: 提交 host-only 句柄策略改动**

```bash
git add internal/app/run.go internal/capture/windivert_windows.go internal/capture/loop_test.go
git commit -m "feat: 为 host-only 模式增加先观察后阻断链路"
```

### Task 3: 在抓包主循环中接入动态 blocker、日志与回收

**Files:**
- Modify: `E:\code\GoProject\tls-mitm\internal\capture\loop.go`
- Test: `E:\code\GoProject\tls-mitm\internal\capture\loop_test.go`

- [ ] **Step 1: 先写日志与动态句柄行为测试**

```go
func TestLoopLogsHostMatchBeforeMutation(t *testing.T) {
	cfg := config.Config{
		TargetHost:     "example.com",
		TargetPort:     443,
		ObserveTimeout: 10 * time.Millisecond,
		MutateOffset:   0,
	}

	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	hello := outboundClientHelloPacketToWithSeq("93.184.216.34", 0, "example.com")
	out := &scriptedHandle{steps: []recvStep{
		{packet: hello},
		{packet: outboundTLSPacketWithSeq(uint32(len(hello) - 40))},
	}}

	if err := RunLoop(context.Background(), cfg, logger, out, nil); err != nil {
		t.Fatalf("RunLoop returned error: %v", err)
	}

	logOutput := logs.String()
	if !strings.Contains(logOutput, "SNI 命中目标域名") {
		t.Fatalf("expected host-only flow to log SNI match, got: %s", logOutput)
	}
}

func TestLoopLogsHostExclusionWhenSNIMismatches(t *testing.T) {
	cfg := config.Config{
		TargetHost:     "example.com",
		TargetPort:     443,
		ObserveTimeout: 10 * time.Millisecond,
		MutateOffset:   0,
	}

	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	hello := outboundClientHelloPacket("other.example")
	out := &scriptedHandle{steps: []recvStep{
		{packet: hello},
		{packet: outboundTLSPacketWithSeq(uint32(len(hello) - 40))},
	}}

	if err := RunLoop(context.Background(), cfg, logger, out, nil); err != nil {
		t.Fatalf("RunLoop returned error: %v", err)
	}

	logOutput := logs.String()
	if !strings.Contains(logOutput, "SNI 未命中目标域名") {
		t.Fatalf("expected mismatched host flow to log exclusion, got: %s", logOutput)
	}
}
```

- [ ] **Step 2: 运行 loop 相关测试，确认当前逻辑先失败**

Run: `go test ./internal/capture -run "TestLoopLogsHostMatchBeforeMutation|TestLoopLogsHostExclusionWhenSNIMismatches" -count=1`

Expected: FAIL，提示日志缺失或 host-only 未正确分流。

- [ ] **Step 3: 在主循环中增加观察事件、阻断事件和动态 blocker 管理**

```go
type blockerFactory func(key session.Key) (packetHandle, error)

type recvKind uint8

const (
	recvKindOutboundObserve recvKind = iota
	recvKindOutboundBlock
	recvKindInboundObserve
)

type recvEvent struct {
	kind   recvKind
	key    session.Key
	packet []byte
	addr   any
	err    error
}

func BuildOutboundConnectionFilter(key session.Key) string {
	return fmt.Sprintf(
		"(outbound and tcp and ip and ip.SrcAddr == %s and tcp.SrcPort == %d and ip.DstAddr == %s and tcp.DstPort == %d)",
		key.ClientIP,
		key.ClientPort,
		key.ServerIP,
		key.ServerPort,
	)
}
```

- [ ] **Step 4: 拆分观察路径与阻断路径，保证 host-only 非命中连接只观察不阻断**

```go
func processObservedOutbound(
	cfg config.Config,
	logger *slog.Logger,
	store *session.Store,
	packet []byte,
) (session.Key, bool, bool, error) {
	meta, err := tcpmeta.ParseIPv4TCP(packet)
	if err != nil {
		logger.Debug("跳过无法解析的出站观察数据包", "error", err)
		return session.Key{}, false, false, nil
	}

	key := outboundKey(meta)
	if !matchesOutbound(cfg, meta) {
		return session.Key{}, false, false, nil
	}

	matched := false
	if shouldResolveHost(cfg, store, key) {
		if serverName, ok := tlshello.ParseServerName(meta.Payload); ok {
			if hostMatches(cfg, serverName) {
				store.MarkMatched(key)
				matched = true
				logger.Info("SNI 命中目标域名", "target_host", cfg.TargetHost, "matched_host", serverName)
			} else {
				store.MarkExcluded(key)
				logger.Info("SNI 未命中目标域名", "target_host", cfg.TargetHost, "observed_host", serverName)
			}
		}
	}
	return key, matched, false, nil
}

func processBlockedOutbound(
	cfg config.Config,
	logger *slog.Logger,
	store *session.Store,
	knownKey session.Key,
	packet []byte,
	addr any,
	handle packetHandle,
) (session.Key, bool, bool, error) {
	// 省略前置解析代码

	if !isConnectionMatched(cfg, store, key) {
		if err := handle.Send(packet, addr); err != nil {
			return session.Key{}, false, false, err
		}
		return session.Key{}, false, false, nil
	}

	// 进入既有重组、MutationPoint、重注入逻辑
}
```

- [ ] **Step 5: 在主循环里接入 blocker 创建、关闭与回收**

```go
if matched && newBlockHandle != nil {
	if _, exists := blockers[key]; !exists {
		handle, err := newBlockHandle(key)
		if err != nil {
			return shutdown(err)
		}
		blockers[key] = handle
		readers++
		startReader(handle, recvKindOutboundBlock, key)
	}
}

closeDynamicBlocker := func(key session.Key) {
	handle, ok := blockers[key]
	if !ok {
		return
	}
	delete(blockers, key)
	_ = handle.Close()
}
```

- [ ] **Step 6: 运行 capture 包测试，确认行为与日志通过**

Run: `go test ./internal/capture -count=1`

Expected: PASS

- [ ] **Step 7: 提交主循环与测试改动**

```bash
git add internal/capture/loop.go internal/capture/loop_test.go
git commit -m "feat: 为 host-only 模式增加动态阻断与日志"
```

### Task 4: 更新 README 与帮助示例，并做整体验证

**Files:**
- Modify: `E:\code\GoProject\tls-mitm\README.md`
- Verify: `E:\code\GoProject\tls-mitm\internal\config\config.go`
- Verify: `E:\code\GoProject\tls-mitm\internal\app\run.go`
- Verify: `E:\code\GoProject\tls-mitm\internal\capture\loop.go`

- [ ] **Step 1: 更新 README 顶部“最新说明”，覆盖四种模式与危险模式**

```md
## 最新说明
当前版本支持以下四种目标选择模式：
- `-target-ip + -target-port`
  只按目标 `IP:端口` 选择连接，不解析 `SNI`。
- `-target-host + -target-port`
  先用高优先级 `sniff` 句柄观察所有目标端口流量，只在 `ClientHello` 中的 `SNI` 命中目标域名后，才为该四元组创建专用阻断句柄并执行篡改。
- `-target-ip + -target-host + -target-port`
  按 `IP AND SNI AND 端口` 交集匹配。
- `-target-port + -unsafe-any-host`
  显式启用危险模式，按端口匹配所有主机。
```

- [ ] **Step 2: 在 README 中加入危险模式示例**

```md
显式启用危险的“按端口匹配所有主机”模式：

```powershell
.\build\tls-mitm.exe -target-port 443 -unsafe-any-host -observe-timeout 5s -mutate-offset 0
```
```

- [ ] **Step 3: 运行帮助信息与全量测试**

Run: `go run .\cmd\tls-mitm -h`

Expected: 输出中包含 `-unsafe-any-host`，并明确说明未提供 `-target-ip` 和 `-target-host` 时需要显式开启该开关。

Run: `go test ./...`

Expected: PASS

- [ ] **Step 4: 提交文档与最终验证改动**

```bash
git add README.md
git commit -m "docs: 补充主机选择护栏与危险模式说明"
```

## 自检

### 1. Spec 覆盖检查

- `host-only` 不再先阻断所有目标端口流量：Task 2、Task 3 覆盖
- `-unsafe-any-host` 显式授权：Task 1 覆盖
- 帮助信息和 README 同步：Task 1、Task 4 覆盖
- 日志可观测性：Task 3 覆盖

没有遗漏 spec 需求。

### 2. 占位符检查

已检查本计划，不包含 `TODO`、`TBD`、`后续补`、`类似 Task N` 等占位写法。

### 3. 类型与命名一致性检查

本计划中使用的关键名称与现有代码一致：

- `UnsafeAnyHost`
- `OpenObserveHandleWithPriority`
- `OpenHandleWithPriority`
- `RunHostMatchLoop`
- `BuildOutboundConnectionFilter`
- `runLoopWithHandles`
- `processObservedOutbound`
- `processBlockedOutbound`

未发现前后命名不一致问题。

## 执行交接

Plan complete and saved to `docs/superpowers/plans/2026-04-18-host-targeting-guardrails.md`. Two execution options:

1. Subagent-Driven（推荐） - 我按任务逐个派发 subagent，实现一个任务、审一次、再进下一个  
2. Inline Execution - 我在当前会话里直接按计划连续实现，做到阶段点再给你回报

补充说明：这份 plan 主要用于对已落地改动做流程追认与后续复核，当前代码不需要再次实现；如果你愿意，我也可以按这份 plan 逐项对照现有实现做一次“实现与计划一致性复核”。
