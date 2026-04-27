# host-only 命中后持续阻断整条连接 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 让 `host-only` 模式在 `SNI` 命中后持续接管整条目标连接，使后续多轮 TLS Application Data 都能继续被篡改，直到连接真正结束。

**Architecture:** 保持现有“先观察、后阻断”的 `host-only` 护栏不变，只调整动态 blocker 的生命周期与 `Store` 的状态清理粒度。把“结束一轮篡改观察”和“释放整条连接”拆成两条路径：前者只清空本轮 mutation/结果去重状态，后者才关闭 blocker 并彻底删除连接状态。

**Tech Stack:** Go、WinDivert、`log/slog`、现有 `internal/capture` 主循环、现有 `internal/session.Store`、Go 单元测试

---

## 文件结构与职责

- `E:\code\GoProject\tls-mitm\internal\session\store.go`
  - 新增“仅清空本轮观察状态”的接口
  - 新增“清空结果去重状态”的接口或语义支撑
  - 保留 `trace_id`、`matchState` 和连接级身份
- `E:\code\GoProject\tls-mitm\internal\session\store_test.go`
  - 验证轮次清理不会丢失命中状态
  - 验证连接级删除仍然彻底清空
- `E:\code\GoProject\tls-mitm\internal\capture\windivert_windows.go`
  - 在 `RunHostMatchLoop` 中区分“结束本轮观察”和“结束整条连接”
  - 只在真实连接终止时关闭动态 blocker
- `E:\code\GoProject\tls-mitm\internal\capture\loop_test.go`
  - 补 host-only 多轮篡改持续生效测试
  - 补日志链路与 blocker 生命周期测试
- `E:\code\GoProject\tls-mitm\README.md`
  - 补充 `host-only` 模式下“命中后持续覆盖整条连接”的行为说明

## 任务拆分

### Task 1: Store 支持“结束本轮观察但保留连接命中状态”

**Files:**
- Modify: `E:\code\GoProject\tls-mitm\internal\session\store.go`
- Test: `E:\code\GoProject\tls-mitm\internal\session\store_test.go`

- [ ] **Step 1: 先写失败测试，锁定轮次清理与整条连接删除的差异**

在 `E:\code\GoProject\tls-mitm\internal\session\store_test.go` 追加：

```go
func TestStoreResetMutationKeepsMatchedStateAndTraceID(t *testing.T) {
	store := NewStore(func() time.Time { return time.Unix(100, 0) })
	key := testSessionKey()

	store.MarkMatched(key)
	traceID := store.TraceID(key)
	if traceID == "" {
		t.Fatal("expected trace id after MarkMatched")
	}

	first := store.TryMarkMutated(key, 5*time.Second, 45)
	if !first {
		t.Fatal("expected first mutation to report first observation")
	}

	store.ResetObservation(key)

	if got := store.MatchState(key); got != MatchStateMatched {
		t.Fatalf("expected matched state to survive observation reset, got %q", got)
	}
	if got := store.TraceID(key); got != traceID {
		t.Fatalf("expected trace id to survive observation reset, got %q want %q", got, traceID)
	}
	if store.HasMutation(key) {
		t.Fatal("expected mutation state to be cleared after observation reset")
	}
	if first := store.TryMarkMutated(key, 5*time.Second, 46); !first {
		t.Fatal("expected next mutation round to be treated as a new first observation")
	}
}

func TestStoreForgetStillRemovesEntireConnectionState(t *testing.T) {
	store := NewStore(func() time.Time { return time.Unix(100, 0) })
	key := testSessionKey()

	store.MarkMatched(key)
	traceID := store.TraceID(key)
	store.TryMarkMutated(key, 5*time.Second, 45)

	store.Forget(key)

	if got := store.MatchState(key); got != MatchStateUnknown {
		t.Fatalf("expected forget to remove match state, got %q", got)
	}
	if got := store.TraceID(key); got != "" {
		t.Fatalf("expected forget to remove trace id, got %q (old %q)", got, traceID)
	}
	if store.HasMutation(key) {
		t.Fatal("expected forget to clear mutation state")
	}
}
```

- [ ] **Step 2: 运行 session 定向测试，确认当前实现先失败**

Run: `go test ./internal/session -run "TestStoreResetMutationKeepsMatchedStateAndTraceID|TestStoreForgetStillRemovesEntireConnectionState" -count=1`

Expected: FAIL，提示 `ResetObservation` 尚不存在，或现有清理语义无法区分轮次清理和整条连接删除。

- [ ] **Step 3: 在 Store 中增加轮次清理能力**

把 `E:\code\GoProject\tls-mitm\internal\session\store.go` 调整为以下要点：

```go
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

func (s *Store) ResetObservation(key Key) {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.data[key]
	if !ok {
		return
	}
	e.mutatedAt = time.Time{}
	e.observeFor = 0
	e.byteIndex = 0
	e.hasMutation = false
	e.lastObserved = time.Time{}
	e.done = false
	e.outcome = OutcomeUnknown
	e.frozen = Result{}
}
```

不要改 `Forget` 的整条连接删除语义，继续保持：

```go
func (s *Store) Forget(key Key) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, key)
}
```

- [ ] **Step 4: 重新运行 session 全量测试**

Run: `go test ./internal/session -count=1`

Expected: PASS

- [ ] **Step 5: 提交 Store 轮次清理改动**

```bash
git add internal/session/store.go internal/session/store_test.go
git commit -m "feat: 为 host-only 连接保留连接级状态"
```

### Task 2: host-only 主循环改为“结果结束不关 blocker，连接终止才关”

**Files:**
- Modify: `E:\code\GoProject\tls-mitm\internal\capture\windivert_windows.go`
- Modify: `E:\code\GoProject\tls-mitm\internal\capture\loop_test.go`

- [ ] **Step 1: 先写失败测试，锁定 host-only 多轮篡改行为**

在 `E:\code\GoProject\tls-mitm\internal\capture\loop_test.go` 追加：

```go
func TestHostOnlyMatchedConnectionMutatesMultipleApplicationDataRounds(t *testing.T) {
	cfg := config.Config{
		TargetHost:      "example.com",
		TargetPort:      443,
		ObserveTimeout:  10 * time.Millisecond,
		MutateOffset:    0,
		MutateDirection: "out",
	}

	hello := outboundClientHelloPacket("example.com")
	firstSeq := uint32(len(hello) - 40)
	secondSeq := firstSeq + 9

	outObserve := &scriptedHandle{steps: []recvStep{
		{packet: hello},
	}}
	inObserve := &scriptedHandle{steps: []recvStep{
		{delay: 2 * time.Millisecond, packet: inboundFINPacket()},
	}}
	blocker := &scriptedHandle{steps: []recvStep{
		{packet: outboundTLSPacketWithSeq(firstSeq)},
		{delay: 15 * time.Millisecond, packet: outboundTLSPacketWithSeq(secondSeq)},
		{delay: 1 * time.Millisecond, packet: outboundFINPacketWithSeq(secondSeq + 9)},
	}}
	factoryCalls := 0
	factory := func(key session.Key) (packetHandle, error) {
		factoryCalls++
		return blocker, nil
	}

	if err := runHostMatchLoopWithHandles(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), outObserve, inObserve, factory); err != nil {
		t.Fatalf("runHostMatchLoopWithHandles returned error: %v", err)
	}
	if factoryCalls != 1 {
		t.Fatalf("expected exactly one dynamic blocker, got %d", factoryCalls)
	}
	if len(blocker.sent) != 3 {
		t.Fatalf("expected blocker to keep forwarding same connection until FIN, got %d sends", len(blocker.sent))
	}
	if got := blocker.sent[0].packet[45]; got != 0x55 {
		t.Fatalf("expected first application data packet to be mutated, got 0x%02x", got)
	}
	if got := blocker.sent[1].packet[45]; got != 0x55 {
		t.Fatalf("expected second application data packet to be mutated, got 0x%02x", got)
	}
}

func TestHostOnlyMatchedConnectionLogsMultipleObservationResultsWithSameTraceID(t *testing.T) {
	cfg := config.Config{
		TargetHost:      "example.com",
		TargetPort:      443,
		ObserveTimeout:  10 * time.Millisecond,
		MutateOffset:    0,
		MutateDirection: "out",
	}

	hello := outboundClientHelloPacket("example.com")
	firstSeq := uint32(len(hello) - 40)
	secondSeq := firstSeq + 9

	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	outObserve := &scriptedHandle{steps: []recvStep{{packet: hello}}}
	inObserve := &scriptedHandle{}
	blocker := &scriptedHandle{steps: []recvStep{
		{packet: outboundTLSPacketWithSeq(firstSeq)},
		{delay: 15 * time.Millisecond, packet: outboundTLSPacketWithSeq(secondSeq)},
		{delay: 1 * time.Millisecond, packet: outboundFINPacketWithSeq(secondSeq + 9)},
	}}
	factory := func(key session.Key) (packetHandle, error) { return blocker, nil }

	if err := runHostMatchLoopWithHandles(context.Background(), cfg, logger, outObserve, inObserve, factory); err != nil {
		t.Fatalf("runHostMatchLoopWithHandles returned error: %v", err)
	}

	logOutput := logs.String()
	if got := strings.Count(logOutput, "msg=连接观察结果"); got < 2 {
		t.Fatalf("expected at least two observation result logs, got %d: %s", got, logOutput)
	}
	matches := regexp.MustCompile(`trace_id=t\\d{6}`).FindAllString(logOutput, -1)
	if len(matches) < 2 || matches[0] != matches[1] {
		t.Fatalf("expected multiple rounds to reuse same trace id, got: %v", matches)
	}
}
```

- [ ] **Step 2: 运行 host-only 定向测试，确认当前实现先失败**

Run: `go test ./internal/capture -run "TestHostOnlyMatchedConnectionMutatesMultipleApplicationDataRounds|TestHostOnlyMatchedConnectionLogsMultipleObservationResultsWithSameTraceID" -count=1`

Expected: FAIL，提示第二轮未被继续篡改，或结果日志只打印一轮。

- [ ] **Step 3: 在 host-only 主循环中拆分轮次清理和连接终止清理**

把 `E:\code\GoProject\tls-mitm\internal\capture\windivert_windows.go` 调整为以下要点：

```go
closeDynamicBlocker := func(key session.Key) {
	handle, ok := blockers[key]
	if !ok {
		return
	}
	delete(blockers, key)
	delete(blockerKinds, key)
	_ = handle.Close()
}

resetObservationCycle := func(key session.Key) {
	delete(deadlines, key)
	delete(observeDirections, key)
	delete(reported, key)
	store.ResetObservation(key)
}

cleanupConnection := func(key session.Key) {
	resetObservationCycle(key)
	closeDynamicBlocker(key)
	store.Forget(key)
}
```

同时把 host-only 事件分支中的收尾逻辑改成：

```go
signal := observeSignal(metaFromServer, meta)

if cleanup {
	if result.Outcome != session.OutcomeUnknown && !isTerminalSignal(signal) {
		resetObservationCycle(key)
	} else {
		cleanupConnection(key)
	}
	resetTimer()
}
```

这里的 `metaFromServer` 要在各分支根据当前方向明确传值：

- `recvKindOutboundBlock` / `recvKindBidirectionalBlock` 的出站分支传 `false`
- `recvKindInboundObserve` / `recvKindInboundBlock` / `recvKindBidirectionalBlock` 的入站分支传 `true`

如果你不想在调用点重复构造 `signal`，也可以在 `processInbound` / `processBlockedOutbound` 的返回值中补充一个 `terminal bool`，让调用点能明确区分：

- 本轮观察结束，但连接未终止
- 连接真实终止，应彻底清理

推荐最小实现：

```go
type cycleResult struct {
	key      session.Key
	mutated  bool
	observed bool
	cleanup  bool
	terminal bool
	result   session.Result
}
```

但如果不引入新结构，也必须保证调用点能拿到 `terminal` 语义。

- [ ] **Step 4: 重置 host-only 结果日志去重状态**

在 host-only 路径中，结束一轮观察但保留连接时，必须同步执行：

```go
delete(reported, key)
```

这样第二轮篡改才不会被上一轮 `reported` 永久压制。

- [ ] **Step 5: 重新运行 host-only 定向测试**

Run: `go test ./internal/capture -run "TestHostOnlyMatchedConnectionMutatesMultipleApplicationDataRounds|TestHostOnlyMatchedConnectionLogsMultipleObservationResultsWithSameTraceID" -count=1`

Expected: PASS

- [ ] **Step 6: 运行 capture 全量测试，确认没有回归**

Run: `go test ./internal/capture -count=1`

Expected: PASS

- [ ] **Step 7: 提交 host-only 生命周期调整**

```bash
git add internal/capture/windivert_windows.go internal/capture/loop_test.go
git commit -m "feat: 让 host-only 命中连接持续进入篡改链路"
```

### Task 3: 同步文档并做全量验证

**Files:**
- Modify: `E:\code\GoProject\tls-mitm\README.md`

- [ ] **Step 1: 先补 README 中的 host-only 行为说明**

把 `E:\code\GoProject\tls-mitm\README.md` 的 host-only 说明补成类似下面的内容：

```md
- 仅提供 `-target-host` 时，程序先通过出站 `ClientHello/SNI` 观察命中目标域名，再为该四元组创建专用 blocker。
- 一旦连接命中目标域名，该 blocker 会持续覆盖整条已命中连接；后续多轮 TLS Application Data 都会继续进入篡改链路。
- 只有在连接真正结束（例如 `FIN` / `RST`）或程序退出时，host-only 动态 blocker 才会被释放。
```

- [ ] **Step 2: 运行全量测试**

Run: `go test ./...`

Expected: PASS

- [ ] **Step 3: 自检工作树**

Run: `git diff --check`

Expected: 无空白错误、无冲突标记

- [ ] **Step 4: 提交文档与最终收尾改动**

```bash
git add README.md
git commit -m "docs: 说明 host-only 持续阻断连接行为"
```

## 自检结论

- 规格覆盖：
  - `Store` 轮次清理能力：Task 1
  - host-only blocker 持续存在直到连接终止：Task 2
  - 多轮结果日志与 `trace_id`：Task 2
  - README 同步：Task 3
- 模糊写法扫描：
  - 已移除含糊示意写法
  - 代码步骤均给出明确片段与命令
- 类型一致性：
  - 计划统一使用 `ResetObservation` 表示轮次清理
  - 整条连接删除继续使用 `Forget`
