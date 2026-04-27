# trace_id 日志链路关联 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 为每条 TCP 连接分配连接级 `trace_id`，并把它打到从 `SNI` 识别到 record 破坏再到观察结果的关键日志中，让整条日志链路可以被直观追踪。

**Architecture:** 在 `internal/session/store.go` 中把 `trace_id` 做成连接级状态，与现有 `matchState`、`reassembly` 和观察结果状态同生命周期管理；`internal/capture/loop.go` 只负责读取 `trace_id` 并写入关键日志，不自行生成连接标识。测试分成两层：`session` 层验证 `trace_id` 的生成、复用和释放，`capture` 层验证同一连接的关键日志都带统一 `trace_id`。

**Tech Stack:** Go、`log/slog`、现有 `session.Store`、Go 单元测试

---

## 文件结构与职责

- `E:\code\GoProject\tls-mitm\internal\session\store.go`
  - 为连接状态增加 `traceID`
  - 维护递增 `nextTraceID`
  - 暴露 `TraceID(key Key) string`
- `E:\code\GoProject\tls-mitm\internal\session\store_test.go`
  - 覆盖同连接稳定、跨连接唯一、`Forget()` 后重分配
- `E:\code\GoProject\tls-mitm\internal\capture\loop.go`
  - 为 `SNI 命中/未命中`
  - `目标连接已命中，但当前包尚未覆盖破坏点`
  - `命中完整 application data 破坏点`
  - `连接观察结果`
  统一补 `trace_id`
- `E:\code\GoProject\tls-mitm\internal\capture\loop_test.go`
  - 验证关键日志包含 `trace_id`
  - 验证同一连接上的多条日志共享同一个 `trace_id`

## 任务拆分

### Task 1: 在 session.Store 中增加连接级 trace_id

**Files:**
- Modify: `E:\code\GoProject\tls-mitm\internal\session\store.go`
- Test: `E:\code\GoProject\tls-mitm\internal\session\store_test.go`

- [ ] **Step 1: 先写失败测试，锁定 trace_id 的生命周期**

在 `internal/session/store_test.go` 追加以下测试：

```go
func TestStoreTraceIDIsStableForSameConnection(t *testing.T) {
	store := NewStore(func() time.Time { return time.Unix(100, 0) })
	key := testSessionKey()

	store.MarkMatched(key)
	first := store.TraceID(key)
	second := store.TraceID(key)

	if first == "" {
		t.Fatal("expected trace id for known connection")
	}
	if first != second {
		t.Fatalf("expected same connection to keep one trace id, got %q and %q", first, second)
	}
}

func TestStoreTraceIDDiffersAcrossConnections(t *testing.T) {
	store := NewStore(func() time.Time { return time.Unix(100, 0) })
	firstKey := testSessionKey()
	secondKey := Key{
		ClientIP:   "10.0.0.2",
		ClientPort: 50001,
		ServerIP:   "93.184.216.34",
		ServerPort: 443,
	}

	store.MarkMatched(firstKey)
	store.MarkMatched(secondKey)

	firstID := store.TraceID(firstKey)
	secondID := store.TraceID(secondKey)
	if firstID == "" || secondID == "" {
		t.Fatalf("expected both trace ids to exist, got %q and %q", firstID, secondID)
	}
	if firstID == secondID {
		t.Fatalf("expected different connections to have different trace ids, both were %q", firstID)
	}
}

func TestStoreTraceIDChangesAfterForgetAndReuse(t *testing.T) {
	store := NewStore(func() time.Time { return time.Unix(100, 0) })
	key := testSessionKey()

	store.MarkMatched(key)
	firstID := store.TraceID(key)
	store.Forget(key)

	store.MarkMatched(key)
	secondID := store.TraceID(key)

	if firstID == "" || secondID == "" {
		t.Fatalf("expected non-empty trace ids, got %q and %q", firstID, secondID)
	}
	if firstID == secondID {
		t.Fatalf("expected forgotten connection to get a new trace id, both were %q", firstID)
	}
}
```

- [ ] **Step 2: 运行 session 测试，确认当前实现先失败**

Run: `go test ./internal/session -run "TestStoreTraceIDIsStableForSameConnection|TestStoreTraceIDDiffersAcrossConnections|TestStoreTraceIDChangesAfterForgetAndReuse" -count=1`

Expected: FAIL，提示 `Store` 缺少 `TraceID` 方法，或连接状态里尚未维护 `traceID`。

- [ ] **Step 3: 在 session.Store 中增加 trace_id 状态与访问方法**

把 `internal/session/store.go` 中的 `Store` 和 `entry` 扩展为：

```go
type Store struct {
	mu          sync.Mutex
	now         func() time.Time
	data        map[Key]*entry
	nextTraceID uint64
}

type entry struct {
	traceID       string
	mutatedAt     time.Time
	observeFor    time.Duration
	byteIndex     int
	matchState    MatchState
	hasMutation   bool
	lastObserved  time.Time
	done          bool
	outcome       Outcome
	frozen        Result
	reassembly    *reassembly.State
	pendingPoints []reassembly.MutationPoint
	lastAck       uint32
}
```

在同文件中新增 `TraceID` 方法，并让新连接在 `ensureEntryLocked` 中自动获得短 ID：

```go
func (s *Store) TraceID(key Key) string {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.data[key]
	if !ok {
		return ""
	}
	return e.traceID
}

func (s *Store) ensureEntryLocked(key Key) *entry {
	if e, ok := s.data[key]; ok {
		return e
	}

	s.nextTraceID++
	e := &entry{
		matchState: MatchStateUnknown,
		traceID:    fmt.Sprintf("t%06d", s.nextTraceID),
	}
	s.data[key] = e
	return e
}
```

同时补上缺失导入：

```go
import (
	"fmt"
	"sync"
	"time"

	"tls-mitm/internal/reassembly"
)
```

- [ ] **Step 4: 重新运行 session 测试，确认 trace_id 语义成立**

Run: `go test ./internal/session -count=1`

Expected: PASS

- [ ] **Step 5: 提交 session 层改动**

```bash
git add internal/session/store.go internal/session/store_test.go
git commit -m "feat: 为连接状态增加 trace_id"
```

### Task 2: 为关键 capture 日志补充 trace_id

**Files:**
- Modify: `E:\code\GoProject\tls-mitm\internal\capture\loop.go`
- Test: `E:\code\GoProject\tls-mitm\internal\capture\loop_test.go`

- [ ] **Step 1: 先写失败测试，锁定关键日志都必须带 trace_id**

在 `internal/capture/loop_test.go` 追加以下测试：

```go
func TestLoopLogsTraceIDForHostMatchMutationAndResult(t *testing.T) {
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
	in := &scriptedHandle{steps: []recvStep{
		{packet: inboundFINPacket()},
	}}

	if err := RunLoop(context.Background(), cfg, logger, out, in); err != nil {
		t.Fatalf("RunLoop returned error: %v", err)
	}

	logOutput := logs.String()
	matches := regexp.MustCompile(`trace_id=t\\d{6}`).FindAllString(logOutput, -1)
	if len(matches) < 3 {
		t.Fatalf("expected trace_id on host match, mutation and result logs, got: %s", logOutput)
	}
	first := matches[0]
	for _, match := range matches[1:] {
		if match != first {
			t.Fatalf("expected one connection to keep one trace id, got %v", matches)
		}
	}
}

func TestLoopLogsTraceIDForHostExclusion(t *testing.T) {
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
		t.Fatalf("expected host exclusion log, got: %s", logOutput)
	}
	if !regexp.MustCompile(`trace_id=t\\d{6}`).MatchString(logOutput) {
		t.Fatalf("expected exclusion log to include trace_id, got: %s", logOutput)
	}
}
```

在文件顶部补充测试所需导入：

```go
import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"tls-mitm/internal/config"
	"tls-mitm/internal/reassembly"
	"tls-mitm/internal/session"
)
```

- [ ] **Step 2: 运行 capture 定向测试，确认当前日志里还没有 trace_id**

Run: `go test ./internal/capture -run "TestLoopLogsTraceIDForHostMatchMutationAndResult|TestLoopLogsTraceIDForHostExclusion" -count=1`

Expected: FAIL，提示日志缺少 `trace_id=`，或同一连接上的关键日志未共享统一标识。

- [ ] **Step 3: 在关键日志点统一补充 trace_id 字段**

先在 `internal/capture/loop.go` 中为 `logResultOnce` 增加 `store` 参数：

```go
func logResultOnce(
	logger *slog.Logger,
	reported map[session.Key]struct{},
	store *session.Store,
	key session.Key,
	result session.Result,
	reason string,
) {
	if result.Outcome == session.OutcomeUnknown {
		return
	}
	if result.Outcome == session.OutcomeNoConclusion && reason != "timeout" {
		return
	}
	if _, ok := reported[key]; ok {
		return
	}
	reported[key] = struct{}{}

	logger.Info(
		"连接观察结果",
		"trace_id", store.TraceID(key),
		"client_ip", key.ClientIP,
		"client_port", key.ClientPort,
		"server_ip", key.ServerIP,
		"server_port", key.ServerPort,
		"outcome", string(result.Outcome),
		"observed_for", result.ObservedFor.String(),
		"byte_index", result.ByteIndex,
		"reason", reason,
	)
}
```

再把 `processObservedOutbound`、`processBlockedOutbound` 和等待日志中的 `logger.Info/Debug` 更新为统一带 `trace_id`：

```go
logger.Info(
	"SNI 命中目标域名",
	"trace_id", store.TraceID(key),
	"client_ip", key.ClientIP,
	"client_port", key.ClientPort,
	"server_ip", key.ServerIP,
	"server_port", key.ServerPort,
	"target_host", cfg.TargetHost,
	"matched_host", serverName,
)

logger.Info(
	"SNI 未命中目标域名",
	"trace_id", store.TraceID(key),
	"client_ip", key.ClientIP,
	"client_port", key.ClientPort,
	"server_ip", key.ServerIP,
	"server_port", key.ServerPort,
	"target_host", cfg.TargetHost,
	"observed_host", serverName,
)

logger.Debug(
	"目标连接已命中，但当前包尚未覆盖破坏点",
	"trace_id", store.TraceID(key),
	"client_ip", key.ClientIP,
	"client_port", key.ClientPort,
	"server_ip", key.ServerIP,
	"server_port", key.ServerPort,
	"seq", meta.Seq,
	"payload_len", len(meta.Payload),
)

logger.Info(
	"命中完整 application data 破坏点",
	"trace_id", store.TraceID(key),
	"client_ip", key.ClientIP,
	"client_port", key.ClientPort,
	"server_ip", key.ServerIP,
	"server_port", key.ServerPort,
	"payload_index", firstAppliedMutation.PayloadIndex,
	"packet_index", byteIndex,
	"old_byte", fmt.Sprintf("%02x", firstAppliedMutation.OldByte),
	"new_byte", fmt.Sprintf("%02x", firstAppliedMutation.NewByte),
	"first_observation", enteredObservation,
)
```

同时把 `logResultOnce(...)` 的调用点改为传入 `store`：

```go
logResultOnce(logger, reported, store, key, result, "timeout")
logResultOnce(logger, reported, store, key, result, signalReason(signal))
```

- [ ] **Step 4: 运行 capture 测试，确认关键日志已经带 trace_id**

Run: `go test ./internal/capture -count=1`

Expected: PASS

- [ ] **Step 5: 运行全量测试，确认这是纯日志增强，不影响现有行为**

Run: `go test ./...`

Expected: PASS

- [ ] **Step 6: 提交 capture 层改动**

```bash
git add internal/capture/loop.go internal/capture/loop_test.go
git commit -m "feat: 为关键日志补充 trace_id"
```

## 自检

- **Spec coverage**
  - 连接级 `trace_id`：Task 1
  - `Forget()` 后重分配：Task 1
  - `SNI 命中/未命中`、等待、破坏点、观察结果全链路日志：Task 2
  - 不改变匹配、篡改、重组行为：Task 2 的全量回归测试覆盖

- **Placeholder scan**
  - 未使用任何占位标记或“稍后补充”式描述
  - 每个代码步骤都给出了具体代码和命令

- **Type consistency**
  - `TraceID(key Key) string` 在 Task 1 定义，在 Task 2 统一引用
  - `logResultOnce` 的新签名在 Task 2 中显式同步所有调用点
