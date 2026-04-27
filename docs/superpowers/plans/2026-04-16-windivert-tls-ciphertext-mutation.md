# WinDivert TLS 密文篡改实验 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 构建一个 Windows 专用的 Go 命令行实验工具，基于 `imgk/divert-go` 拦截目标 TLS 连接，只篡改单个连接首个完整出站 `Application Data record` 的一个密文字节，并观察对端是否中止连接。

**Architecture:** 实现采用两个互斥的 WinDivert `NETWORK` 层句柄：出站句柄只捕获发往目标 `IP:端口` 的 TCP 包并执行篡改，入站句柄只捕获来自目标 `IP:端口` 的 TCP 包并执行观察。核心逻辑拆成配置入口、IPv4/TCP 解析、TLS record 识别、篡改策略、连接状态机、WinDivert 适配器六部分，先用纯单元测试和离线字节样本把核心逻辑钉住，再接入真实句柄。

**Tech Stack:** Go 1.23、标准库 `flag`/`log/slog`/`net/netip`、`github.com/imgk/divert-go`、WinDivert 2.x、Windows 管理员权限。

---

## 文件结构

- Create: `go.mod`
- Create: `cmd/tls-mitm/main.go`
- Create: `internal/app/run.go`
- Create: `internal/config/config.go`
- Create: `internal/config/config_test.go`
- Create: `internal/logging/logger.go`
- Create: `internal/tcpmeta/packet.go`
- Create: `internal/tcpmeta/packet_test.go`
- Create: `internal/tlsrecord/record.go`
- Create: `internal/tlsrecord/record_test.go`
- Create: `internal/mutate/mutate.go`
- Create: `internal/mutate/mutate_test.go`
- Create: `internal/session/store.go`
- Create: `internal/session/store_test.go`
- Create: `internal/capture/loop.go`
- Create: `internal/capture/loop_test.go`
- Create: `internal/capture/windivert_windows.go`
- Create: `internal/capture/windivert_stub.go`

## Task 1: 初始化模块、配置与日志骨架

**Files:**
- Create: `go.mod`
- Create: `cmd/tls-mitm/main.go`
- Create: `internal/app/run.go`
- Create: `internal/config/config.go`
- Create: `internal/config/config_test.go`
- Create: `internal/logging/logger.go`

- [ ] **Step 1: 写配置解析失败测试**

```go
func TestParseArgsSuccess(t *testing.T) {
	cfg, err := ParseArgs([]string{"-target-ip", "93.184.216.34", "-target-port", "443", "-observe-timeout", "5s", "-mutate-offset", "2"})
	if err != nil {
		t.Fatalf("ParseArgs returned error: %v", err)
	}
	if cfg.TargetIP.String() != "93.184.216.34" || cfg.TargetPort != 443 || cfg.MutateOffset != 2 {
		t.Fatalf("unexpected config: %+v", cfg)
	}
}

func TestParseArgsRejectsBadIP(t *testing.T) {
	if _, err := ParseArgs([]string{"-target-ip", "bad", "-target-port", "443"}); err == nil {
		t.Fatal("expected error")
	}
}
```

- [ ] **Step 2: 运行测试确认失败**

Run: `go test ./internal/config -run TestParseArgs -v`  
Expected: FAIL，提示缺少 `internal/config`

- [ ] **Step 3: 实现最小配置与入口骨架**

```go
module tls-mitm

go 1.23

require github.com/imgk/divert-go v0.1.0
```

```go
type Config struct {
	TargetIP       netip.Addr
	TargetPort     uint16
	ObserveTimeout time.Duration
	LogFormat      string
	LogLevel       string
	MutateOffset   int
}
```

```go
func main() {
	cfg, err := config.ParseArgs(os.Args[1:])
	if err != nil {
		log.Fatalf("解析参数失败: %v", err)
	}
	logger := logging.New(cfg.LogFormat, os.Stdout)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := app.Run(ctx, cfg, logger); err != nil {
		log.Fatalf("运行失败: %v", err)
	}
}
```

- [ ] **Step 4: 重新运行配置测试**

Run: `go test ./internal/config -run TestParseArgs -v`  
Expected: PASS

- [ ] **Step 5: 提交骨架**

```bash
git add go.mod cmd/tls-mitm/main.go internal/app/run.go internal/config/config.go internal/config/config_test.go internal/logging/logger.go
git commit -m "feat: 初始化命令行与配置骨架"
```

## Task 2: 实现 IPv4/TCP 解析、TLS record 识别与密文翻转

**Files:**
- Create: `internal/tcpmeta/packet.go`
- Create: `internal/tcpmeta/packet_test.go`
- Create: `internal/tlsrecord/record.go`
- Create: `internal/tlsrecord/record_test.go`
- Create: `internal/mutate/mutate.go`
- Create: `internal/mutate/mutate_test.go`

- [ ] **Step 1: 写解析与篡改测试**

```go
func TestParseIPv4TCP(t *testing.T) {
	packet := makeIPv4TCPPacket([]byte("hello"))
	meta, err := ParseIPv4TCP(packet)
	if err != nil {
		t.Fatalf("ParseIPv4TCP returned error: %v", err)
	}
	if meta.PayloadOffset != 40 || string(meta.Payload) != "hello" {
		t.Fatalf("unexpected meta: %+v", meta)
	}
}

func TestFindFirstCompleteApplicationData(t *testing.T) {
	payload := []byte{0x16, 0x03, 0x03, 0x00, 0x02, 0x01, 0x02, 0x17, 0x03, 0x03, 0x00, 0x04, 0xaa, 0xbb, 0xcc, 0xdd}
	rec, ok := FindFirstCompleteApplicationData(payload)
	if !ok || rec.Start != 7 || rec.DataLen != 4 {
		t.Fatalf("unexpected record: %+v", rec)
	}
}

func TestFlipCiphertextByte(t *testing.T) {
	payload := []byte{0x17, 0x03, 0x03, 0x00, 0x04, 0xaa, 0xbb, 0xcc, 0xdd}
	rec, _ := tlsrecord.FindFirstCompleteApplicationData(payload)
	m, err := FlipCiphertextByte(payload, rec, 1)
	if err != nil || m.PayloadIndex != 6 || payload[6] != 0x44 {
		t.Fatalf("unexpected mutation: %+v err=%v payload=%x", m, err, payload)
	}
}
```

- [ ] **Step 2: 运行测试确认失败**

Run: `go test ./internal/tcpmeta ./internal/tlsrecord ./internal/mutate -v`  
Expected: FAIL，提示缺少对应包

- [ ] **Step 3: 实现解析、识别与翻转**

```go
type Packet struct {
	SrcIP, DstIP   netip.Addr
	SrcPort, DstPort uint16
	Seq, Ack       uint32
	PayloadOffset  int
	TCPFlags       byte
	Payload        []byte
}
```

```go
type Record struct {
	Start, HeaderLen, DataStart, DataLen, TotalLen int
	Type byte
	Version uint16
}

func FindFirstCompleteApplicationData(payload []byte) (Record, bool)
```

```go
type Mutation struct {
	PayloadIndex int
	OldByte      byte
	NewByte      byte
}

func FlipCiphertextByte(payload []byte, record tlsrecord.Record, offset int) (Mutation, error)
```

- [ ] **Step 4: 重新运行测试**

Run: `go test ./internal/tcpmeta ./internal/tlsrecord ./internal/mutate -v`  
Expected: PASS

- [ ] **Step 5: 提交底层解析能力**

```bash
git add internal/tcpmeta/packet.go internal/tcpmeta/packet_test.go internal/tlsrecord/record.go internal/tlsrecord/record_test.go internal/mutate/mutate.go internal/mutate/mutate_test.go
git commit -m "feat: 实现 TCP 解析与 TLS 密文翻转"
```

## Task 3: 实现连接状态机与双向观察分类

**Files:**
- Create: `internal/session/store.go`
- Create: `internal/session/store_test.go`

- [ ] **Step 1: 写连接状态机测试**

```go
func TestStoreMutatesOnlyOncePerConnection(t *testing.T) {
	store := NewStore(func() time.Time { return time.Unix(100, 0) })
	key := Key{ClientIP: "10.0.0.2", ClientPort: 50000, ServerIP: "93.184.216.34", ServerPort: 443}
	if !store.ShouldMutate(key) {
		t.Fatal("first mutation should be allowed")
	}
	store.MarkMutated(key, 5*time.Second, 8)
	if store.ShouldMutate(key) {
		t.Fatal("same connection should not mutate twice")
	}
}

func TestObserveRSTMeansDefiniteFailure(t *testing.T) {
	store := NewStore(func() time.Time { return time.Unix(100, 0) })
	key := Key{ClientIP: "10.0.0.2", ClientPort: 50000, ServerIP: "93.184.216.34", ServerPort: 443}
	store.MarkMutated(key, 5*time.Second, 8)
	got := store.Observe(key, Signal{FromServer: true, RST: true})
	if got.Outcome != OutcomeDefiniteFailure {
		t.Fatalf("unexpected outcome: %s", got.Outcome)
	}
}
```

- [ ] **Step 2: 运行测试确认失败**

Run: `go test ./internal/session -v`  
Expected: FAIL，提示缺少 `internal/session`

- [ ] **Step 3: 实现状态机**

```go
type Key struct {
	ClientIP   string
	ClientPort uint16
	ServerIP   string
	ServerPort uint16
}

type Outcome string

const (
	OutcomeUnknown         Outcome = "unknown"
	OutcomeDefiniteFailure Outcome = "definite_failure"
	OutcomeProbableFailure Outcome = "probable_failure"
	OutcomeNoConclusion    Outcome = "no_conclusion"
)
```

```go
func (s *Store) ShouldMutate(key Key) bool
func (s *Store) MarkMutated(key Key, observe time.Duration, byteIndex int)
func (s *Store) Observe(key Key, sig Signal) Result
```

- [ ] **Step 4: 重新运行测试**

Run: `go test ./internal/session -v`  
Expected: PASS

- [ ] **Step 5: 提交连接状态能力**

```bash
git add internal/session/store.go internal/session/store_test.go
git commit -m "feat: 实现连接状态与结果分类"
```

## Task 4: 接入 `imgk/divert-go` 并完成真实抓包循环

**Files:**
- Create: `internal/capture/loop.go`
- Create: `internal/capture/loop_test.go`
- Create: `internal/capture/windivert_windows.go`
- Create: `internal/capture/windivert_stub.go`
- Modify: `internal/app/run.go`

- [ ] **Step 1: 写抓包循环测试**

```go
func TestBuildFilters(t *testing.T) {
	cfg := config.Config{TargetIP: netip.MustParseAddr("93.184.216.34"), TargetPort: 443}
	outbound, inbound := BuildFilters(cfg)
	if !strings.Contains(outbound, "outbound") || !strings.Contains(inbound, "inbound") {
		t.Fatalf("unexpected filters: %s / %s", outbound, inbound)
	}
}

func TestLoopMutatesOutboundButNotInbound(t *testing.T) {
	cfg := config.Config{
		TargetIP:       netip.MustParseAddr("93.184.216.34"),
		TargetPort:     443,
		ObserveTimeout: 5 * time.Second,
		MutateOffset:   0,
	}
	out := &fakeHandle{recv: []packetWithAddr{{packet: outboundTLSPacket()}}}
	in := &fakeHandle{recv: []packetWithAddr{{packet: inboundRSTPacket()}}}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := RunLoop(context.Background(), cfg, logger, out, in); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("RunLoop returned error: %v", err)
	}
	if len(out.sent) != 1 {
		t.Fatalf("expected one outbound mutated send, got %d", len(out.sent))
	}
	if len(in.sent) != 0 {
		t.Fatalf("inbound packets should not be re-sent, got %d", len(in.sent))
	}
}
```

- [ ] **Step 2: 运行测试确认失败**

Run: `go test ./internal/capture -v`  
Expected: FAIL，提示缺少 `internal/capture`

- [ ] **Step 3: 实现真实 WinDivert 适配器与循环**

```go
//go:build windows

package capture

import divert "github.com/imgk/divert-go"

type Handle struct{ h *divert.Handle }

func OpenHandle(filter string) (*Handle, error) {
	returned, err := divert.Open(filter, divert.Layer(0), divert.PriorityDefault, divert.FlagDefault)
	if err != nil {
		return nil, err
	}
	return &Handle{h: returned}, nil
}

func (h *Handle) Recv() ([]byte, *divert.Address, error) {
	buf := make([]byte, 65535)
	addr := &divert.Address{}
	n, err := h.h.Recv(buf, addr)
	if err != nil {
		return nil, nil, err
	}
	return append([]byte(nil), buf[:n]...), addr, nil
}

func (h *Handle) Send(packet []byte, addr *divert.Address) error {
	divert.CalcChecksums(packet, addr, divert.ChecksumDefault)
	_, err := h.h.Send(packet, addr)
	return err
}
```

```go
func BuildFilters(cfg config.Config) (string, string) {
	outbound := fmt.Sprintf("(outbound and tcp and ip and ip.DstAddr == %s and tcp.DstPort == %d)", cfg.TargetIP, cfg.TargetPort)
	inbound := fmt.Sprintf("(inbound and tcp and ip and ip.SrcAddr == %s and tcp.SrcPort == %d)", cfg.TargetIP, cfg.TargetPort)
	return outbound, inbound
}
```

```go
func Run(ctx context.Context, cfg config.Config, logger *slog.Logger) error {
	outFilter, inFilter := capture.BuildFilters(cfg)
	outHandle, err := capture.OpenHandle(outFilter)
	if err != nil {
		return err
	}
	defer outHandle.Close()
	inHandle, err := capture.OpenHandle(inFilter)
	if err != nil {
		return err
	}
	defer inHandle.Close()
	return capture.RunLoop(ctx, cfg, logger, outHandle, inHandle)
}
```

- [ ] **Step 4: 运行完整测试并做一次 Windows 手工验证**

Run: `go test ./...`  
Expected: PASS

Run: `go run ./cmd/tls-mitm -target-ip 93.184.216.34 -target-port 443 -observe-timeout 5s -mutate-offset 0`  
Expected:
- 管理员权限下成功打开两个 WinDivert 句柄
- 访问目标 HTTPS 站点时出现“命中首个完整 application data”日志
- 同一连接不会出现第二次篡改日志
- 入站如收到 `RST`、`FIN` 或疑似 alert，会输出结果分类

- [ ] **Step 5: 提交真实集成**

```bash
git add internal/capture/loop.go internal/capture/loop_test.go internal/capture/windivert_windows.go internal/capture/windivert_stub.go internal/app/run.go
git commit -m "feat: 接入 WinDivert 抓包与重注入"
```

## 自检

### Spec coverage

- `Windows 专用`: Task 4 的 `windivert_windows.go` / `windivert_stub.go`
- `目标 IP:端口 选流`: Task 1 配置 + Task 4 `BuildFilters`
- `只改出站`: Task 4 的双句柄设计
- `入站只观察`: Task 3 结果分类 + Task 4 入站循环
- `首个完整 Application Data record`: Task 2 `FindFirstCompleteApplicationData`
- `单连接只改一次`: Task 3 `ShouldMutate` / `MarkMutated`
- `重注入`: Task 4 `Handle.Send`
- `checksum 更新`: Task 4 `divert.CalcChecksums`

### Placeholder scan

- 没有 `TODO`、`TBD`、`后续补充`
- 每个任务都有具体文件、命令、提交信息
- 未引用未定义的类型名或函数名

### Type consistency

- 配置统一使用 `config.Config`
- 连接键统一使用 `session.Key`
- record 与篡改统一使用 `tlsrecord.Record` 和 `mutate.Mutation`
- WinDivert 适配统一封装在 `internal/capture`
