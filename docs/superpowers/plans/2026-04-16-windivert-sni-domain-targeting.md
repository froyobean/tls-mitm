# WinDivert 基于域名拦截 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在保留现有 `target-ip` 拦截模式的前提下，为 `tls-mitm` 增加基于 TLS `ClientHello` 中 `SNI` 的 `target-host` 域名拦截能力。

**Architecture:** 本次实现只新增一层“目标连接识别”逻辑，不改现有单连接单次篡改主链路。配置层扩展 `target-host`，抓包层按需解析 `ClientHello/SNI`，连接状态层增加“未判定/已命中/已排除”状态，只有命中的连接才继续进入现有 `Application Data` 篡改与结果观察逻辑。

**Tech Stack:** Go 1.25、标准库 `flag`/`log/slog`/`strings`/`net/netip`、现有 `imgk/divert-go` WinDivert 适配层、纯单元测试与集成测试。

---

## 文件结构

- Modify: `cmd/tls-mitm/main.go`
- Modify: `internal/config/config.go`
- Modify: `internal/config/config_test.go`
- Create: `internal/tlshello/clienthello.go`
- Create: `internal/tlshello/clienthello_test.go`
- Modify: `internal/session/store.go`
- Modify: `internal/session/store_test.go`
- Modify: `internal/capture/loop.go`
- Modify: `internal/capture/loop_test.go`

## Task 1: 扩展配置层支持 `target-host`

**Files:**
- Modify: `internal/config/config.go`
- Modify: `internal/config/config_test.go`

- [ ] **Step 1: 先写配置解析失败测试**

```go
func TestParseArgsSupportsTargetHostOnly(t *testing.T) {
	cfg, err := ParseArgs([]string{"-target-host", "Example.COM", "-target-port", "443"})
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
	if cfg.TargetIP.String() != "93.184.216.34" || cfg.TargetHost != "example.com" {
		t.Fatalf("unexpected config: %+v", cfg)
	}
}

func TestParseArgsRejectsMissingTargetSelectors(t *testing.T) {
	if _, err := ParseArgs([]string{"-target-port", "443"}); err == nil {
		t.Fatal("expected error")
	}
}
```

- [ ] **Step 2: 运行配置测试确认失败**

Run: `go test ./internal/config -run "TestParseArgsSupportsTargetHostOnly|TestParseArgsSupportsTargetIPAndTargetHost|TestParseArgsRejectsMissingTargetSelectors" -v`  
Expected: FAIL，提示 `Config` 缺少 `TargetHost` 字段或校验逻辑不满足。

- [ ] **Step 3: 最小实现配置扩展**

```go
type Config struct {
	TargetIP       netip.Addr
	TargetHost     string
	TargetPort     uint16
	ObserveTimeout time.Duration
	LogFormat      string
	MutateOffset   int
}
```

```go
func ParseArgs(args []string) (Config, error) {
	fs := newFlagSet(io.Discard)

	targetIP, targetHost, targetPort, observeTimeout, logFormat, mutateOffset, showHelp := bindFlags(fs)

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return Config{}, ErrHelpRequested
		}
		return Config{}, err
	}
	if *showHelp {
		return Config{}, ErrHelpRequested
	}

	normalizedHost := strings.ToLower(strings.TrimSpace(*targetHost))
	if *targetIP == "" && normalizedHost == "" {
		return Config{}, errors.New("缺少目标条件，target-ip 和 target-host 至少要提供一个")
	}

	// target-ip 可选；若提供则继续沿用当前 IP 校验逻辑。
	// target-port 仍为必填。
}
```

```go
func bindFlags(fs *flag.FlagSet) (*string, *string, *int, *time.Duration, *string, *int, *bool) {
	targetIP := fs.String("target-ip", "", "按目标 IP 匹配，可选")
	targetHost := fs.String("target-host", "", "按 TLS SNI 域名匹配，可选")
	targetPort := fs.Int("target-port", 0, "目标端口，必填")
	observeTimeout := fs.Duration("observe-timeout", 5*time.Second, "观察超时")
	logFormat := fs.String("log-format", "text", "日志格式")
	mutateOffset := fs.Int("mutate-offset", 0, "篡改偏移")
	showHelp := fs.Bool("h", false, "显示帮助信息")
	fs.BoolVar(showHelp, "help", false, "显示帮助信息")
	return targetIP, targetHost, targetPort, observeTimeout, logFormat, mutateOffset, showHelp
}
```

- [ ] **Step 4: 更新帮助文本并重新运行配置测试**

Run: `go test ./internal/config -v`  
Expected: PASS，帮助文本中新增 `-target-host`，并包含三种示例：
- `tls-mitm -target-ip 93.184.216.34 -target-port 443`
- `tls-mitm -target-host example.com -target-port 443`
- `tls-mitm -target-ip 93.184.216.34 -target-host example.com -target-port 443`

- [ ] **Step 5: 提交配置扩展**

```bash
git add internal/config/config.go internal/config/config_test.go
git commit -m "feat: 支持 target-host 配置"
```

## Task 2: 新增最小 `ClientHello/SNI` 解析模块

**Files:**
- Create: `internal/tlshello/clienthello.go`
- Create: `internal/tlshello/clienthello_test.go`

- [ ] **Step 1: 先写 `SNI` 提取失败测试**

```go
func TestParseClientHelloExtractsSNI(t *testing.T) {
	payload := mustBuildSingleRecordClientHello(t, "example.com")
	got, ok := ParseServerName(payload)
	if !ok || got != "example.com" {
		t.Fatalf("unexpected SNI: %q ok=%v", got, ok)
	}
}

func TestParseClientHelloRejectsIncompleteRecord(t *testing.T) {
	payload := mustBuildSingleRecordClientHello(t, "example.com")
	payload = payload[:len(payload)-1]
	if _, ok := ParseServerName(payload); ok {
		t.Fatal("expected incomplete record to be rejected")
	}
}

func TestParseClientHelloRejectsNonClientHello(t *testing.T) {
	payload := []byte{0x16, 0x03, 0x03, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00}
	if _, ok := ParseServerName(payload); ok {
		t.Fatal("expected non-ClientHello to be rejected")
	}
}
```

- [ ] **Step 2: 运行新模块测试确认失败**

Run: `go test ./internal/tlshello -v`  
Expected: FAIL，提示缺少 `internal/tlshello` 包或 `ParseServerName` 实现。

- [ ] **Step 3: 实现最小 `ClientHello` 与 `server_name` 解析**

```go
package tlshello

import "strings"

func ParseServerName(payload []byte) (string, bool) {
	record, ok := findHandshakeRecord(payload)
	if !ok {
		return "", false
	}
	body, ok := extractClientHelloBody(record)
	if !ok {
		return "", false
	}
	name, ok := extractServerName(body)
	if !ok {
		return "", false
	}
	return strings.ToLower(name), true
}
```

```go
// 只接受单个 TCP payload 内完整可见的 Handshake record 与 ClientHello。
// 不做跨包拼接，不做完整 TLS 状态机。
```

- [ ] **Step 4: 运行 `tlshello` 测试并补 1 个无 `server_name` 扩展的负向用例**

Run: `go test ./internal/tlshello -v`  
Expected: PASS

- [ ] **Step 5: 提交 `SNI` 解析模块**

```bash
git add internal/tlshello/clienthello.go internal/tlshello/clienthello_test.go
git commit -m "feat: 实现最小 ClientHello SNI 解析"
```

## Task 3: 扩展连接状态以区分“未判定 / 已命中 / 已排除”

**Files:**
- Modify: `internal/session/store.go`
- Modify: `internal/session/store_test.go`

- [ ] **Step 1: 先写目标连接判定状态测试**

```go
func TestStoreSupportsMatchStateTransitions(t *testing.T) {
	store := NewStore(func() time.Time { return time.Unix(100, 0) })
	key := Key{ClientIP: "10.0.0.2", ClientPort: 50000, ServerIP: "93.184.216.34", ServerPort: 443}

	if got := store.MatchState(key); got != MatchStateUnknown {
		t.Fatalf("unexpected initial state: %v", got)
	}

	store.MarkMatched(key)
	if got := store.MatchState(key); got != MatchStateMatched {
		t.Fatalf("unexpected matched state: %v", got)
	}
}

func TestStoreExcludeStatePreventsMutation(t *testing.T) {
	store := NewStore(func() time.Time { return time.Unix(100, 0) })
	key := Key{ClientIP: "10.0.0.2", ClientPort: 50000, ServerIP: "93.184.216.34", ServerPort: 443}

	store.MarkExcluded(key)
	if store.ShouldMutate(key) {
		t.Fatal("excluded connection must not be mutable")
	}
}
```

- [ ] **Step 2: 运行状态测试确认失败**

Run: `go test ./internal/session -run "TestStoreSupportsMatchStateTransitions|TestStoreExcludeStatePreventsMutation" -v`  
Expected: FAIL，提示缺少 `MatchState`、`MarkMatched` 或 `MarkExcluded`。

- [ ] **Step 3: 最小扩展 `Store`**

```go
type MatchState string

const (
	MatchStateUnknown  MatchState = "unknown"
	MatchStateMatched  MatchState = "matched"
	MatchStateExcluded MatchState = "excluded"
)
```

```go
type entry struct {
	matchState   MatchState
	mutatedAt    time.Time
	observeFor   time.Duration
	byteIndex    int
	hasMutation  bool
	lastObserved time.Time
	done         bool
	outcome      Outcome
	frozen       Result
}
```

```go
func (s *Store) MatchState(key Key) MatchState
func (s *Store) MarkMatched(key Key)
func (s *Store) MarkExcluded(key Key)
```

```go
func (s *Store) ShouldMutate(key Key) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.data[key]
	if !ok {
		return false
	}
	return e.matchState == MatchStateMatched && !e.hasMutation
}
```

- [ ] **Step 4: 运行完整 `session` 测试并修正对旧行为的影响**

Run: `go test ./internal/session -v`  
Expected: PASS

- [ ] **Step 5: 提交连接判定状态扩展**

```bash
git add internal/session/store.go internal/session/store_test.go
git commit -m "feat: 增加目标连接判定状态"
```

## Task 4: 接入 `SNI` 判定并保持纯 `target-ip` 模式兼容

**Files:**
- Modify: `internal/capture/loop.go`
- Modify: `internal/capture/loop_test.go`
- Modify: `internal/app/run.go`

- [ ] **Step 1: 先写抓包主循环的域名命中测试**

```go
func TestLoopMatchesTargetHostBeforeMutation(t *testing.T) {
	cfg := config.Config{
		TargetHost:     "example.com",
		TargetPort:     443,
		ObserveTimeout: 5 * time.Second,
		MutateOffset:   0,
	}
	out := &fakeHandle{recv: []packetWithAddr{
		{packet: outboundClientHelloPacketWithSNI("example.com")},
		{packet: outboundTLSPacket()},
	}}
	in := &fakeHandle{}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := RunLoop(context.Background(), cfg, logger, out, in); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("RunLoop returned error: %v", err)
	}
	if len(out.sent) != 2 {
		t.Fatalf("expected two outbound sends, got %d", len(out.sent))
	}
	if got := out.sent[1].packet[45]; got != 0x55 {
		t.Fatalf("expected mutation on matched connection, got 0x%02x", got)
	}
}

func TestLoopSkipsMutationWhenSNIIsDifferent(t *testing.T) {
	cfg := config.Config{
		TargetHost:     "example.com",
		TargetPort:     443,
		ObserveTimeout: 5 * time.Second,
		MutateOffset:   0,
	}
	out := &fakeHandle{recv: []packetWithAddr{
		{packet: outboundClientHelloPacketWithSNI("other.example")},
		{packet: outboundTLSPacket()},
	}}
	in := &fakeHandle{}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := RunLoop(context.Background(), cfg, logger, out, in); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("RunLoop returned error: %v", err)
	}
	if len(out.sent) != 2 {
		t.Fatalf("expected two outbound sends, got %d", len(out.sent))
	}
	if got := out.sent[1].packet[45]; got == 0x55 {
		t.Fatalf("unexpected mutation on excluded connection")
	}
}
```

- [ ] **Step 2: 运行抓包测试确认失败**

Run: `go test ./internal/capture -run "TestLoopMatchesTargetHostBeforeMutation|TestLoopSkipsMutationWhenSNIIsDifferent" -v`  
Expected: FAIL，提示缺少 `target-host` 路径、`SNI` 解析接入或连接判定逻辑。

- [ ] **Step 3: 最小接入域名判定**

```go
func BuildFilters(cfg config.Config) (string, string) {
	switch {
	case cfg.TargetIP.IsValid():
		outbound := fmt.Sprintf("(outbound and tcp and ip and ip.DstAddr == %s and tcp.DstPort == %d)", cfg.TargetIP, cfg.TargetPort)
		inbound := fmt.Sprintf("(inbound and tcp and ip and ip.SrcAddr == %s and tcp.SrcPort == %d)", cfg.TargetIP, cfg.TargetPort)
		return outbound, inbound
	default:
		outbound := fmt.Sprintf("(outbound and tcp and ip and tcp.DstPort == %d)", cfg.TargetPort)
		inbound := fmt.Sprintf("(inbound and tcp and ip and tcp.SrcPort == %d)", cfg.TargetPort)
		return outbound, inbound
	}
}
```

```go
func processOutbound(...) (session.Key, bool, error) {
	meta, err := tcpmeta.ParseIPv4TCP(packet)
	if err != nil {
		return session.Key{}, false, handle.Send(packet, addr)
	}

	key := outboundKey(meta)
	if !matchesPortAndOptionalIP(cfg, meta) {
		return session.Key{}, false, handle.Send(packet, addr)
	}

	if shouldResolveHost(cfg, store, key) {
		if name, ok := tlshello.ParseServerName(meta.Payload); ok {
			switch {
			case hostMatches(cfg, name):
				store.MarkMatched(key)
			default:
				store.MarkExcluded(key)
			}
		}
	}

	if !isConnectionMatched(cfg, store, key) {
		return session.Key{}, false, handle.Send(packet, addr)
	}

	// 后续沿用现有 record 篡改逻辑。
}
```

```go
func isConnectionMatched(cfg config.Config, store *session.Store, key session.Key) bool {
	switch {
	case cfg.TargetHost == "":
		return true
	default:
		return store.MatchState(key) == session.MatchStateMatched
	}
}
```

- [ ] **Step 4: 运行完整 `capture` 测试并补一个“IP AND SNI 交集匹配”的用例**

Run: `go test ./internal/capture -v`  
Expected: PASS

- [ ] **Step 5: 提交抓包主循环改造**

```bash
git add internal/capture/loop.go internal/capture/loop_test.go internal/app/run.go
git commit -m "feat: 接入基于 SNI 的目标连接判定"
```

## Task 5: 回归验证与帮助信息收口

**Files:**
- Modify: `internal/config/config_test.go`
- Modify: `internal/capture/loop_test.go`

- [ ] **Step 1: 补充帮助信息与纯 `target-ip` 回归测试**

```go
func TestUsageIncludesTargetHost(t *testing.T) {
	usage := Usage()
	for _, want := range []string{
		"-target-host <域名>",
		"tls-mitm -target-host example.com -target-port 443",
		"tls-mitm -target-ip 93.184.216.34 -target-host example.com -target-port 443",
	} {
		if !strings.Contains(usage, want) {
			t.Fatalf("usage missing %q: %s", want, usage)
		}
	}
}
```

```go
func TestLoopKeepsPureTargetIPMode(t *testing.T) {
	cfg := config.Config{
		TargetIP:       netip.MustParseAddr("93.184.216.34"),
		TargetPort:     443,
		ObserveTimeout: 5 * time.Second,
		MutateOffset:   0,
	}
	out := &fakeHandle{recv: []packetWithAddr{{packet: outboundTLSPacket()}}}
	in := &fakeHandle{}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := RunLoop(context.Background(), cfg, logger, out, in); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("RunLoop returned error: %v", err)
	}
	if len(out.sent) != 1 {
		t.Fatalf("expected one outbound send, got %d", len(out.sent))
	}
	if got := out.sent[0].packet[45]; got != 0x55 {
		t.Fatalf("expected target-ip mode to keep mutation behavior, got 0x%02x", got)
	}
}
```

- [ ] **Step 2: 运行全量测试**

Run: `go test ./...`  
Expected: PASS

- [ ] **Step 3: 做一次最小手工验证**

Run: `go run ./cmd/tls-mitm -target-host example.com -target-port 443 -h`  
Expected:
- 帮助信息包含 `target-host`
- 示例包含“只配 host”与“IP + host”两种模式

- [ ] **Step 4: 提交域名拦截收口**

```bash
git add internal/config/config_test.go internal/capture/loop_test.go
git commit -m "test: 完成域名拦截回归验证"
```

## 自检

### Spec coverage

- `同时支持 target-ip 和 target-host`: Task 1
- `target-port 必填`: Task 1
- `只配 target-ip 时不解析 SNI`: Task 4、Task 5
- `只配 target-host 时按 SNI 命中`: Task 2、Task 4
- `IP AND SNI 交集匹配`: Task 4
- `第一版不做 TCP 重组`: Task 2、Task 4
- `未识别 SNI 时保守放行`: Task 4
- `帮助信息更新`: Task 1、Task 5

### Placeholder scan

- 无 `TODO`、`TBD`、`后续补充`
- 每个任务都给出了具体文件、测试代码、运行命令和提交命令
- 没有引用未在任务中定义的新模块名或函数名

### Type consistency

- 配置统一使用 `config.Config`
- 域名解析入口统一使用 `tlshello.ParseServerName`
- 连接目标状态统一使用 `session.MatchState`
- 抓包主循环继续围绕现有 `processOutbound` / `processInbound` 扩展
