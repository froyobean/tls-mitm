# 双向 TLS Application Data 篡改方向控制 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 为 `tls-mitm` 增加 `-mutate-direction` 参数，使工具可以只篡改出站、只篡改入站，或同时篡改两个方向的 `TLS Application Data record`。

**Architecture:** 保持现有目标连接识别逻辑不变，仍然先通过 `target-ip` / `target-host` / `target-port` / `unsafe-any-host` 判定目标连接，再按 `mutate-direction=out|in|both` 决定是否启用某一侧的最小 TCP 重组与 record 级破坏点追踪。连接级 `trace_id` 继续共享，但出站与入站的重组状态、待确认破坏点和 ACK 清理状态必须严格隔离，并遵循“payload 按本方向处理，ACK 按反方向清理”的规则。

**Tech Stack:** Go、WinDivert、`log/slog`、现有 `internal/reassembly`、现有 `internal/session.Store`、Go 单元测试

---

## 文件结构与职责

- `E:\code\GoProject\tls-mitm\internal\config\config.go`
  - 新增 `MutateDirection string`
  - 解析并校验 `-mutate-direction`
  - 更新帮助信息与示例
- `E:\code\GoProject\tls-mitm\internal\config\config_test.go`
  - 覆盖默认值、合法值、非法值、帮助输出
- `E:\code\GoProject\tls-mitm\internal\session\store.go`
  - 将单向 `reassembly` / `pendingPoints` / `lastAck` 拆成出站与入站两套独立状态
  - 提供方向明确的方法，避免布尔参数污染调用点
- `E:\code\GoProject\tls-mitm\internal\session\store_test.go`
  - 验证双向状态隔离
  - 验证 ACK 反方向清理规则
- `E:\code\GoProject\tls-mitm\internal\capture\loop.go`
  - 根据 `MutateDirection` 决定是否对出站或入站 payload 执行重组与篡改
  - 保留现有目标连接识别逻辑
  - 关键日志补充 `direction=out|in`
  - 在入站篡改场景下补足客户端侧失败信号观察
- `E:\code\GoProject\tls-mitm\internal\capture\loop_test.go`
  - 覆盖 `out`、`in`、`both`
  - 覆盖 `target-host + in`、`target-host + both`
  - 覆盖 ACK 反方向清理与双向日志方向字段
- `E:\code\GoProject\tls-mitm\internal\app\run.go`
  - 按方向模式选择出站/入站句柄的阻断或观察模式
  - 在 `host-only` 模式下为目标连接创建正确方向的动态 blocker
- `E:\code\GoProject\tls-mitm\internal\capture\windivert_windows.go`
  - 若需要，为入站方向新增专用连接过滤器构造函数或句柄辅助入口
- `E:\code\GoProject\tls-mitm\README.md`
  - 补充 `-mutate-direction` 说明与示例

## 任务拆分

### Task 1: 配置层增加 `-mutate-direction`

**Files:**
- Modify: `E:\code\GoProject\tls-mitm\internal\config\config.go`
- Test: `E:\code\GoProject\tls-mitm\internal\config\config_test.go`

- [ ] **Step 1: 先写失败测试，锁定默认值、合法值、非法值与帮助信息**

在 `E:\code\GoProject\tls-mitm\internal\config\config_test.go` 追加以下测试：

```go
func TestParseArgsDefaultsMutateDirectionToOut(t *testing.T) {
	cfg, err := ParseArgs([]string{"-target-ip", "93.184.216.34", "-target-port", "443"})
	if err != nil {
		t.Fatalf("ParseArgs returned error: %v", err)
	}
	if cfg.MutateDirection != "out" {
		t.Fatalf("expected default mutate direction out, got %q", cfg.MutateDirection)
	}
}

func TestParseArgsAcceptsInAndBothMutateDirection(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "in",
			args: []string{"-target-ip", "93.184.216.34", "-target-port", "443", "-mutate-direction", "in"},
			want: "in",
		},
		{
			name: "both",
			args: []string{"-target-host", "example.com", "-target-port", "443", "-mutate-direction", "both"},
			want: "both",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := ParseArgs(tc.args)
			if err != nil {
				t.Fatalf("ParseArgs returned error: %v", err)
			}
			if cfg.MutateDirection != tc.want {
				t.Fatalf("expected mutate direction %q, got %q", tc.want, cfg.MutateDirection)
			}
		})
	}
}

func TestParseArgsRejectsInvalidMutateDirection(t *testing.T) {
	_, err := ParseArgs([]string{
		"-target-ip", "93.184.216.34",
		"-target-port", "443",
		"-mutate-direction", "sideways",
	})
	if err == nil {
		t.Fatal("expected invalid mutate direction error")
	}
	if !strings.Contains(err.Error(), "mutate-direction") {
		t.Fatalf("expected mutate-direction in error, got %v", err)
	}
}

func TestUsageMentionsMutateDirection(t *testing.T) {
	usage := Usage()
	if !strings.Contains(usage, "-mutate-direction <方向>") {
		t.Fatalf("expected usage to mention mutate-direction, got: %s", usage)
	}
	if !strings.Contains(usage, "out、in 或 both") {
		t.Fatalf("expected usage to describe mutate-direction values, got: %s", usage)
	}
}
```

- [ ] **Step 2: 运行配置测试，确认当前实现先失败**

Run: `go test ./internal/config -run "TestParseArgsDefaultsMutateDirectionToOut|TestParseArgsAcceptsInAndBothMutateDirection|TestParseArgsRejectsInvalidMutateDirection|TestUsageMentionsMutateDirection" -count=1`

Expected: FAIL，提示 `Config` 缺少 `MutateDirection` 字段，或 `ParseArgs` / `Usage()` 尚未处理新参数。

- [ ] **Step 3: 以最小实现补上配置字段、参数绑定、校验与帮助信息**

把 `E:\code\GoProject\tls-mitm\internal\config\config.go` 调整为以下要点：

```go
type Config struct {
	TargetIP         netip.Addr
	TargetHost       string
	TargetPort       uint16
	ObserveTimeout   time.Duration
	LogFormat        string
	MutateOffset     int
	MutateDirection  string
	UnsafeAnyHost    bool
}

func ParseArgs(args []string) (Config, error) {
	fs := newFlagSet(io.Discard)

	targetIP, targetHost, targetPort, observeTimeout, logFormat, mutateOffset, mutateDirection, unsafeAnyHost, showHelp := bindFlags(fs)

	// ...保持现有 Parse 与 help 分支...

	normalizedDirection := strings.ToLower(strings.TrimSpace(*mutateDirection))
	if normalizedDirection == "" {
		normalizedDirection = "out"
	}
	switch normalizedDirection {
	case "out", "in", "both":
	default:
		return Config{}, fmt.Errorf("无效的 mutate-direction: %s（仅支持 out、in 或 both）", *mutateDirection)
	}

	return Config{
		TargetIP:         addr,
		TargetHost:       normalizedTargetHost,
		TargetPort:       uint16(*targetPort),
		ObserveTimeout:   *observeTimeout,
		LogFormat:        *logFormat,
		MutateOffset:     *mutateOffset,
		MutateDirection:  normalizedDirection,
		UnsafeAnyHost:    *unsafeAnyHost,
	}, nil
}

func bindFlags(fs *flag.FlagSet) (*string, *string, *int, *time.Duration, *string, *int, *string, *bool, *bool) {
	targetIP := fs.String("target-ip", "", "目标 IP")
	targetHost := fs.String("target-host", "", "目标域名")
	targetPort := fs.Int("target-port", 0, "目标端口")
	observeTimeout := fs.Duration("observe-timeout", 5*time.Second, "观察超时")
	logFormat := fs.String("log-format", "text", "日志格式")
	mutateOffset := fs.Int("mutate-offset", 0, "篡改偏移")
	mutateDirection := fs.String("mutate-direction", "out", "篡改方向：out、in 或 both")
	unsafeAnyHost := fs.Bool("unsafe-any-host", false, "显式允许按目标端口匹配所有主机")
	showHelp := fs.Bool("h", false, "显示帮助信息")
	fs.BoolVar(showHelp, "help", false, "显示帮助信息")
	return targetIP, targetHost, targetPort, observeTimeout, logFormat, mutateOffset, mutateDirection, unsafeAnyHost, showHelp
}
```

同时把 `Usage()` 中的可选参数和示例补成：

```go
renderUsageTable(&builder, []usageItem{
	{name: "-mutate-direction <方向>", description: "篡改方向，可选 out、in 或 both", defaultValue: "out"},
	// 保留其他已有参数
})

builder.WriteString("  tls-mitm -target-ip 93.184.216.34 -target-port 443 -mutate-direction out\n")
builder.WriteString("  tls-mitm -target-host example.com -target-port 443 -mutate-direction in\n")
builder.WriteString("  tls-mitm -target-host example.com -target-port 443 -mutate-direction both\n")
```

- [ ] **Step 4: 重新运行配置测试，确认新参数行为成立**

Run: `go test ./internal/config -count=1`

Expected: PASS

- [ ] **Step 5: 提交配置层改动**

```bash
git add internal/config/config.go internal/config/config_test.go
git commit -m "feat: 增加篡改方向配置"
```

### Task 2: 将 session 状态拆成出站与入站两套独立状态

**Files:**
- Modify: `E:\code\GoProject\tls-mitm\internal\session\store.go`
- Test: `E:\code\GoProject\tls-mitm\internal\session\store_test.go`

- [ ] **Step 1: 先写失败测试，锁定双向状态隔离与 ACK 反方向清理**

在 `E:\code\GoProject\tls-mitm\internal\session\store_test.go` 追加以下测试：

```go
func TestStoreSeparatesOutboundAndInboundReassemblyState(t *testing.T) {
	store := NewStore(func() time.Time { return time.Unix(100, 0) })
	key := testSessionKey()

	outState := store.OutboundReassembly(key, 1000)
	inState := store.InboundReassembly(key, 2000)

	if outState == nil || inState == nil {
		t.Fatal("expected both reassembly states to exist")
	}
	if outState == inState {
		t.Fatal("expected outbound and inbound reassembly states to be independent")
	}
	if outState.NextSeq() != 1000 {
		t.Fatalf("unexpected outbound next seq: %d", outState.NextSeq())
	}
	if inState.NextSeq() != 2000 {
		t.Fatalf("unexpected inbound next seq: %d", inState.NextSeq())
	}
}

func TestStoreSeparatesOutboundAndInboundPendingMutationPoints(t *testing.T) {
	store := NewStore(func() time.Time { return time.Unix(100, 0) })
	key := testSessionKey()

	store.AddOutboundMutationPoint(key, reassembly.MutationPoint{TargetSeq: 1010})
	store.AddInboundMutationPoint(key, reassembly.MutationPoint{TargetSeq: 2010})

	if got := len(store.OutboundPendingMutationPoints(key)); got != 1 {
		t.Fatalf("expected one outbound pending point, got %d", got)
	}
	if got := len(store.InboundPendingMutationPoints(key)); got != 1 {
		t.Fatalf("expected one inbound pending point, got %d", got)
	}
}

func TestStoreInboundAckClearsOutboundPointsOnly(t *testing.T) {
	store := NewStore(func() time.Time { return time.Unix(100, 0) })
	key := testSessionKey()

	store.AddOutboundMutationPoint(key, reassembly.MutationPoint{TargetSeq: 1010})
	store.AddInboundMutationPoint(key, reassembly.MutationPoint{TargetSeq: 2010})

	store.AckOutboundUpTo(key, 1011)

	if got := len(store.OutboundPendingMutationPoints(key)); got != 0 {
		t.Fatalf("expected outbound points to be cleared, got %d", got)
	}
	if got := len(store.InboundPendingMutationPoints(key)); got != 1 {
		t.Fatalf("expected inbound points to remain, got %d", got)
	}
}

func TestStoreOutboundAckClearsInboundPointsOnly(t *testing.T) {
	store := NewStore(func() time.Time { return time.Unix(100, 0) })
	key := testSessionKey()

	store.AddOutboundMutationPoint(key, reassembly.MutationPoint{TargetSeq: 1010})
	store.AddInboundMutationPoint(key, reassembly.MutationPoint{TargetSeq: 2010})

	store.AckInboundUpTo(key, 2011)

	if got := len(store.OutboundPendingMutationPoints(key)); got != 1 {
		t.Fatalf("expected outbound points to remain, got %d", got)
	}
	if got := len(store.InboundPendingMutationPoints(key)); got != 0 {
		t.Fatalf("expected inbound points to be cleared, got %d", got)
	}
}
```

- [ ] **Step 2: 运行 session 定向测试，确认当前实现先失败**

Run: `go test ./internal/session -run "TestStoreSeparatesOutboundAndInboundReassemblyState|TestStoreSeparatesOutboundAndInboundPendingMutationPoints|TestStoreInboundAckClearsOutboundPointsOnly|TestStoreOutboundAckClearsInboundPointsOnly" -count=1`

Expected: FAIL，提示缺少 `OutboundReassembly` / `InboundReassembly` / 方向化 pending points / ACK 方法。

- [ ] **Step 3: 在 session.Store 中引入方向明确的内部状态与方法，同时保留现有出站包装方法**

把 `E:\code\GoProject\tls-mitm\internal\session\store.go` 中的 `entry` 拆成：

```go
type directionState struct {
	reassembly    *reassembly.State
	pendingPoints []reassembly.MutationPoint
	lastAck       uint32
}

type entry struct {
	traceID      string
	mutatedAt    time.Time
	observeFor   time.Duration
	byteIndex    int
	matchState   MatchState
	hasMutation  bool
	lastObserved time.Time
	done         bool
	outcome      Outcome
	frozen       Result
	outbound     directionState
	inbound      directionState
}
```

新增方向明确的方法：

```go
func (s *Store) OutboundReassembly(key Key, initialSeq uint32) *reassembly.State { ... }
func (s *Store) InboundReassembly(key Key, initialSeq uint32) *reassembly.State { ... }

func (s *Store) AddOutboundMutationPoint(key Key, point reassembly.MutationPoint) { ... }
func (s *Store) AddInboundMutationPoint(key Key, point reassembly.MutationPoint) { ... }

func (s *Store) OutboundPendingMutationPoints(key Key) []reassembly.MutationPoint { ... }
func (s *Store) InboundPendingMutationPoints(key Key) []reassembly.MutationPoint { ... }

func (s *Store) AckOutboundUpTo(key Key, ack uint32) { ... }
func (s *Store) AckInboundUpTo(key Key, ack uint32) { ... }
```

方向内部逻辑使用一个共享辅助函数，避免复制粘贴：

```go
func reassemblyFor(state *directionState, initialSeq uint32) *reassembly.State {
	if state.reassembly == nil {
		state.reassembly = reassembly.NewState(initialSeq)
	}
	return state.reassembly
}

func addMutationPoint(state *directionState, point reassembly.MutationPoint) {
	if state.lastAck > point.TargetSeq {
		return
	}
	state.pendingPoints = append(state.pendingPoints, point)
}

func pendingMutationPoints(state *directionState) []reassembly.MutationPoint {
	if len(state.pendingPoints) == 0 {
		return nil
	}
	points := make([]reassembly.MutationPoint, len(state.pendingPoints))
	copy(points, state.pendingPoints)
	return points
}

func ackUpTo(state *directionState, ack uint32) {
	effectiveAck := state.lastAck
	if ack > effectiveAck {
		effectiveAck = ack
	}
	state.lastAck = effectiveAck

	filtered := state.pendingPoints[:0]
	for _, point := range state.pendingPoints {
		if effectiveAck <= point.TargetSeq {
			filtered = append(filtered, point)
		}
	}
	if len(filtered) == 0 {
		state.pendingPoints = nil
		return
	}
	state.pendingPoints = filtered
}
```

为了保持 Task 2 可独立通过，临时保留现有出站包装接口，让当前 `capture` 代码不需要在同一任务内一起改：

```go
func (s *Store) Reassembly(key Key, initialSeq uint32) *reassembly.State {
	return s.OutboundReassembly(key, initialSeq)
}

func (s *Store) AddMutationPoint(key Key, point reassembly.MutationPoint) {
	s.AddOutboundMutationPoint(key, point)
}

func (s *Store) PendingMutationPoints(key Key) []reassembly.MutationPoint {
	return s.OutboundPendingMutationPoints(key)
}

func (s *Store) AckUpTo(key Key, ack uint32) {
	s.AckOutboundUpTo(key, ack)
}
```

- [ ] **Step 4: 重新运行 session 测试，确认双向状态接口和现有包装接口同时成立**

Run: `go test ./internal/session -count=1`

Expected: PASS

- [ ] **Step 5: 提交 session 层改动**

```bash
git add internal/session/store.go internal/session/store_test.go
git commit -m "feat: 拆分双向重组与破坏点状态"
```

### Task 3: 在 capture 主循环中接入 `out|in|both` 的方向化篡改与观测

**Files:**
- Modify: `E:\code\GoProject\tls-mitm\internal\capture\loop.go`
- Test: `E:\code\GoProject\tls-mitm\internal\capture\loop_test.go`

- [ ] **Step 1: 先写失败测试，锁定 out、in、both 与 ACK 反方向清理**

在 `E:\code\GoProject\tls-mitm\internal\capture\loop_test.go` 追加以下测试：

```go
func TestLoopMutatesOutboundOnlyWhenDirectionOut(t *testing.T) {
	cfg := config.Config{
		TargetIP:         netip.MustParseAddr("93.184.216.34"),
		TargetPort:       443,
		ObserveTimeout:   20 * time.Millisecond,
		MutateOffset:     0,
		MutateDirection:  "out",
	}

	out := &scriptedHandle{steps: []recvStep{{packet: outboundTLSPacket()}}}
	in := &scriptedHandle{steps: []recvStep{{packet: inboundTLSPacket()}}}

	if err := RunLoop(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), out, in); err != nil {
		t.Fatalf("RunLoop returned error: %v", err)
	}
	if len(out.sent) != 1 || out.sent[0].packet[45] != 0x55 {
		t.Fatalf("expected outbound packet to mutate in out mode")
	}
	if len(in.sent) != 0 {
		t.Fatalf("expected inbound packet not to be reinjected in out mode")
	}
}

func TestLoopMutatesInboundOnlyWhenDirectionIn(t *testing.T) {
	cfg := config.Config{
		TargetIP:         netip.MustParseAddr("93.184.216.34"),
		TargetPort:       443,
		ObserveTimeout:   20 * time.Millisecond,
		MutateOffset:     0,
		MutateDirection:  "in",
	}

	out := &scriptedHandle{steps: []recvStep{{packet: outboundTLSPacket()}}}
	in := &scriptedHandle{steps: []recvStep{{packet: inboundTLSPacket()}}}

	if err := RunLoop(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), out, in); err != nil {
		t.Fatalf("RunLoop returned error: %v", err)
	}
	if len(out.sent) != 1 || out.sent[0].packet[45] != 0xaa {
		t.Fatalf("expected outbound packet to stay unchanged in in mode")
	}
	if len(in.sent) != 1 || in.sent[0].packet[45] != 0x55 {
		t.Fatalf("expected inbound packet to mutate in in mode")
	}
}

func TestLoopMutatesBothDirectionsWhenDirectionBoth(t *testing.T) {
	cfg := config.Config{
		TargetIP:         netip.MustParseAddr("93.184.216.34"),
		TargetPort:       443,
		ObserveTimeout:   20 * time.Millisecond,
		MutateOffset:     0,
		MutateDirection:  "both",
	}

	out := &scriptedHandle{steps: []recvStep{{packet: outboundTLSPacket()}}}
	in := &scriptedHandle{steps: []recvStep{{packet: inboundTLSPacket()}}}

	if err := RunLoop(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), out, in); err != nil {
		t.Fatalf("RunLoop returned error: %v", err)
	}
	if len(out.sent) != 1 || out.sent[0].packet[45] != 0x55 {
		t.Fatalf("expected outbound packet to mutate in both mode")
	}
	if len(in.sent) != 1 || in.sent[0].packet[45] != 0x55 {
		t.Fatalf("expected inbound packet to mutate in both mode")
	}
}

func TestInboundAckStillClearsOutboundMutationPointInBothMode(t *testing.T) {
	cfg := config.Config{
		TargetIP:         netip.MustParseAddr("93.184.216.34"),
		TargetPort:       443,
		ObserveTimeout:   50 * time.Millisecond,
		MutateOffset:     0,
		MutateDirection:  "both",
	}

	packet := outboundTLSPacketWithSeq(1000)
	out := &scriptedHandle{steps: []recvStep{
		{packet: packet},
		{delay: 20 * time.Millisecond, packet: packet},
	}}
	in := &scriptedHandle{steps: []recvStep{
		{delay: 5 * time.Millisecond, packet: inboundAckPacket(1006)},
	}}

	if err := RunLoop(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), out, in); err != nil {
		t.Fatalf("RunLoop returned error: %v", err)
	}
	if got := out.sent[1].packet[45]; got != 0xaa {
		t.Fatalf("expected inbound ACK to clear outbound pending mutation point, got 0x%02x", got)
	}
}

func TestLoopLogsDirectionOnMutationAndResult(t *testing.T) {
	cfg := config.Config{
		TargetIP:         netip.MustParseAddr("93.184.216.34"),
		TargetPort:       443,
		ObserveTimeout:   20 * time.Millisecond,
		MutateOffset:     0,
		MutateDirection:  "both",
	}

	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	out := &scriptedHandle{steps: []recvStep{{packet: outboundTLSPacket()}}}
	in := &scriptedHandle{steps: []recvStep{{packet: inboundTLSPacket()}}}

	if err := RunLoop(context.Background(), cfg, logger, out, in); err != nil {
		t.Fatalf("RunLoop returned error: %v", err)
	}

	logOutput := logs.String()
	if !strings.Contains(logOutput, "direction=out") {
		t.Fatalf("expected outbound mutation logs to include direction=out, got: %s", logOutput)
	}
	if !strings.Contains(logOutput, "direction=in") {
		t.Fatalf("expected inbound mutation logs to include direction=in, got: %s", logOutput)
	}
}
```

如果文件中还没有入站 TLS application data 帮助函数，同时追加一个最小 helper：

```go
func inboundTLSPacket() []byte {
	return makeIPv4TCPPacketWithSeqAck(
		[4]byte{93, 184, 216, 34},
		[4]byte{10, 0, 0, 2},
		443,
		50000,
		0,
		0,
		0x18,
		[]byte{0x17, 0x03, 0x03, 0x00, 0x04, 0xaa, 0xbb, 0xcc, 0xdd},
	)
}
```

- [ ] **Step 2: 运行 capture 定向测试，确认当前实现先失败**

Run: `go test ./internal/capture -run "TestLoopMutatesOutboundOnlyWhenDirectionOut|TestLoopMutatesInboundOnlyWhenDirectionIn|TestLoopMutatesBothDirectionsWhenDirectionBoth|TestInboundAckStillClearsOutboundMutationPointInBothMode|TestLoopLogsDirectionOnMutationAndResult" -count=1`

Expected: FAIL，提示配置缺少方向判断、入站 payload 尚未进入重组/篡改链路，或日志中缺少 `direction=`。

- [ ] **Step 3: 在 capture 主循环里接入方向化 payload 处理、反方向 ACK 清理和双向日志**

把 `E:\code\GoProject\tls-mitm\internal\capture\loop.go` 调整为以下结构要点：

1. 新增方向判断辅助函数：

```go
func mutatesOutbound(cfg config.Config) bool {
	return cfg.MutateDirection == "out" || cfg.MutateDirection == "both"
}

func mutatesInbound(cfg config.Config) bool {
	return cfg.MutateDirection == "in" || cfg.MutateDirection == "both"
}
```

2. 出站处理改为显式使用出站状态与入站 ACK 清理：

```go
pendingPoints := store.OutboundPendingMutationPoints(key)
state := store.OutboundReassembly(key, meta.Seq)
// 生成与应用出站 mutation points
```

3. 入站处理改为：

```go
store.AckOutboundUpTo(key, meta.Ack) // 入站 ACK 清理出站点

if mutatesInbound(cfg) && isConnectionMatched(cfg, store, key) {
	pendingPoints := store.InboundPendingMutationPoints(key)
	state := store.InboundReassembly(key, meta.Seq)
	// 先应用已有入站 pending points
	// 再 Push(...) 生成新的入站 mutation points
	// 任何命中的入站包都通过入站 handle.Send(...) 重新注入
}
```

4. 出站路径也补上反方向 ACK 清理（用于 `in` 或 `both` 模式）：

```go
store.AckInboundUpTo(key, meta.Ack) // 出站 ACK 清理入站点
```

5. 关键日志补上方向字段：

```go
logger.Info(
	"命中完整 application data 破坏点",
	"trace_id", store.TraceID(key),
	"direction", "out",
	// ...
)

logger.Info(
	"命中完整 application data 破坏点",
	"trace_id", store.TraceID(key),
	"direction", "in",
	// ...
)
```

6. 为了让 `in` 模式能观察到“客户端因入站篡改而失败”的结果，在处理出站包终止信号时补上已篡改连接的观察分支，而不是只让入站路径观察：

```go
if store.HasMutation(key) {
	result := store.Observe(key, observeSignal(false, meta))
	logResultOnce(logger, reported, store, key, result, signalReason(observeSignal(false, meta)))
	if isTerminalSignal(observeSignal(false, meta)) || result.Outcome != session.OutcomeUnknown {
		store.Forget(key)
		return key, packetMutated, true, nil
	}
}
```

这样 `in` 模式下客户端回 `FIN/RST` 时，仍然能产出连接观察结果，而不是静默丢掉。

- [ ] **Step 4: 重新运行 capture 测试，确认三个方向模式与日志字段成立**

Run: `go test ./internal/capture -count=1`

Expected: PASS

- [ ] **Step 5: 再跑一遍全量测试，确认没有破坏现有 host-only、trace_id 与重组行为**

Run: `go test ./...`

Expected: PASS

- [ ] **Step 6: 提交 capture 主循环改动**

```bash
git add internal/capture/loop.go internal/capture/loop_test.go
git commit -m "feat: 支持双向篡改方向控制"
```

### Task 4: 调整 app/WinDivert 句柄编排，并补 README 文档

**Files:**
- Modify: `E:\code\GoProject\tls-mitm\internal\app\run.go`
- Modify: `E:\code\GoProject\tls-mitm\internal\capture\windivert_windows.go`
- Modify: `E:\code\GoProject\tls-mitm\README.md`

- [ ] **Step 1: 先补失败测试或最小验证脚本，锁定不同方向下的句柄组合**

由于 `run.go` 当前没有单元测试，先在 `E:\code\GoProject\tls-mitm\internal/capture\loop_test.go` 追加一个最小 host-only 方向回归测试，确保 `target-host + in` 只靠 `SNI` 命中连接、后续由入站阻断句柄生效：

```go
func TestDynamicHostOnlyModeMutatesInboundThroughDedicatedBlocker(t *testing.T) {
	cfg := config.Config{
		TargetHost:       "example.com",
		TargetPort:       443,
		ObserveTimeout:   10 * time.Millisecond,
		MutateOffset:     0,
		MutateDirection:  "in",
	}

	hello := outboundClientHelloPacket("example.com")
	observe := &scriptedHandle{steps: []recvStep{{packet: hello}}}
	blocker := &scriptedHandle{steps: []recvStep{{packet: inboundTLSPacket()}}}
	factoryCalls := 0
	factory := func(key session.Key) (packetHandle, error) {
		factoryCalls++
		return blocker, nil
	}

	if err := runLoopWithHandles(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), observe, nil, blocker, factory); err != nil {
		t.Fatalf("runLoopWithHandles returned error: %v", err)
	}
	if factoryCalls != 1 {
		t.Fatalf("expected exactly one blocker handle, got %d", factoryCalls)
	}
	if len(blocker.sent) != 1 || blocker.sent[0].packet[45] != 0x55 {
		t.Fatalf("expected inbound dedicated blocker to mutate one packet")
	}
}
```

如果这条测试过于依赖现有签名，可以改成 Step 2 的命令式验证：先实现，再用 `go test ./internal/capture -run TestDynamicHostOnlyModeMutatesInboundThroughDedicatedBlocker -count=1` 验证。

- [ ] **Step 2: 在 app/run 与 windivert_windows 中落地方向化句柄编排**

把 `E:\code\GoProject\tls-mitm\internal\app\run.go` 调整为以下组合规则：

```go
switch {
case cfg.TargetHost == "":
	switch cfg.MutateDirection {
	case "out":
		outHandle, err := capture.OpenHandle(outFilter)
		inHandle, err := capture.OpenObserveHandle(inFilter)
		return capture.RunLoop(ctx, cfg, logger, outHandle, inHandle)
	case "in":
		outHandle, err := capture.OpenObserveHandle(outFilter)
		inHandle, err := capture.OpenHandle(inFilter)
		return capture.RunLoop(ctx, cfg, logger, outHandle, inHandle)
	case "both":
		outHandle, err := capture.OpenHandle(outFilter)
		inHandle, err := capture.OpenHandle(inFilter)
		return capture.RunLoop(ctx, cfg, logger, outHandle, inHandle)
	}
default:
	outObserveHandle, err := capture.OpenObserveHandleWithPriority(outFilter, divert.PriorityHighest)
	// host-only 仍通过出站 observe 识别 SNI
	blockFactory := func(key session.Key) (*capture.Handle, error) {
		switch cfg.MutateDirection {
		case "out":
			filter := capture.BuildOutboundConnectionFilter(key)
			return capture.OpenHandleWithPriority(filter, divert.PriorityDefault)
		case "in":
			filter := capture.BuildInboundConnectionFilter(key)
			return capture.OpenHandleWithPriority(filter, divert.PriorityDefault)
		case "both":
			filter := capture.BuildBidirectionalConnectionFilter(key)
			return capture.OpenHandleWithPriority(filter, divert.PriorityDefault)
		default:
			return nil, fmt.Errorf("不支持的 mutate-direction: %s", cfg.MutateDirection)
		}
	}
	return capture.RunHostMatchLoop(ctx, cfg, logger, outObserveHandle, inHandle, blockFactory)
}
```

同时在 `E:\code\GoProject\tls-mitm\internal\capture\windivert_windows.go` 增加连接级过滤器：

```go
func BuildInboundConnectionFilter(key session.Key) string {
	return fmt.Sprintf(
		"(inbound and tcp and ip and ip.SrcAddr == %s and tcp.SrcPort == %d and ip.DstAddr == %s and tcp.DstPort == %d)",
		key.ServerIP,
		key.ServerPort,
		key.ClientIP,
		key.ClientPort,
	)
}

func BuildBidirectionalConnectionFilter(key session.Key) string {
	return fmt.Sprintf(
		"((outbound and tcp and ip and ip.SrcAddr == %s and tcp.SrcPort == %d and ip.DstAddr == %s and tcp.DstPort == %d) or (inbound and tcp and ip and ip.SrcAddr == %s and tcp.SrcPort == %d and ip.DstAddr == %s and tcp.DstPort == %d))",
		key.ClientIP,
		key.ClientPort,
		key.ServerIP,
		key.ServerPort,
		key.ServerIP,
		key.ServerPort,
		key.ClientIP,
		key.ClientPort,
	)
}
```

确保 `host-only` 模式仍然遵守“非目标连接只观察、不阻断”的护栏。

- [ ] **Step 3: 更新 README，让新参数和三种模式对用户可见**

把 `E:\code\GoProject\tls-mitm\README.md` 的参数说明和示例补成：

```md
## 方向控制

使用 `-mutate-direction` 控制篡改方向：

- `out`：只篡改客户端到服务器的 `TLS Application Data`
- `in`：只篡改服务器到客户端的 `TLS Application Data`
- `both`：两个方向都篡改

默认值为 `out`。

### 示例

```powershell
.\build\tls-mitm.exe -target-ip 93.184.216.34 -target-port 443 -mutate-direction out
.\build\tls-mitm.exe -target-host www.bing.com -target-port 443 -mutate-direction in
.\build\tls-mitm.exe -target-host www.bing.com -target-port 443 -mutate-direction both
```
```

- [ ] **Step 4: 运行全量测试与帮助输出验证**

Run: `go test ./...`

Expected: PASS

Run: `go run ./cmd/tls-mitm -h`

Expected: 输出里包含 `-mutate-direction` 及 `out、in 或 both` 说明。

- [ ] **Step 5: 提交句柄编排与文档改动**

```bash
git add internal/app/run.go internal/capture/windivert_windows.go README.md
git commit -m "docs: 补充双向篡改方向使用说明"
```

## 自检

- **Spec coverage**
  - `-mutate-direction` 参数与默认值：Task 1
  - `out` / `in` / `both` 语义：Task 1 + Task 3 + Task 4
  - 出入站状态独立、ACK 反方向清理：Task 2 + Task 3
  - `target-ip` / `target-host` / `unsafe-any-host` 的目标连接判定不变：Task 3 + Task 4
  - `host-only + in` / `host-only + both` 的句柄编排与护栏：Task 4
  - 日志增加 `direction`：Task 3
  - README / help：Task 1 + Task 4

- **Placeholder scan**
  - 没有 `TODO`、`TBD`、`以后再补`
  - 每个代码步骤都给出具体代码块或明确命令
  - 没有“类似 Task N”的跳跃式描述

- **Type consistency**
  - `MutateDirection` 在 Task 1 定义，并在 Task 3 / Task 4 一致使用
  - `OutboundReassembly` / `InboundReassembly`
  - `AddOutboundMutationPoint` / `AddInboundMutationPoint`
  - `OutboundPendingMutationPoints` / `InboundPendingMutationPoints`
  - `AckOutboundUpTo` / `AckInboundUpTo`
  - 方法名在所有后续任务中保持一致
