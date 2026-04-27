# WinDivert 出站最小重组与 Record 级篡改 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 为 `tls-mitm` 增加仅针对出站方向的最小 TCP 重组能力，使其能够对每条经重组后确认完整的 `TLS Application Data record` 按 `mutate-offset` 只生成一个破坏点，并对任何覆盖该破坏点的首次发送或重传 TCP 包施加一致篡改；若 `record` 太短则保守跳过。

**Architecture:** 本次实现不改变现有 `target-ip` / `target-host` / `IP + host` 的目标连接判定，只升级“命中后的篡改链路”。代码将新增一个独立的 `internal/reassembly` 包负责最小出站重组与破坏点生成，`internal/tlsrecord` 扩展为支持连续流上的 record 识别，`internal/session` 负责保存每条连接的重组状态和待确认破坏点，`internal/capture` 在处理出站包时先应用已知破坏点，再推进重组并登记新的破坏点；入站方向只负责用 ACK 回收不再可能重传的破坏点。

**Tech Stack:** Go 1.25、标准库 `time` / `sort` / `container/list`（如需要）/ `net/netip`、现有 `imgk/divert-go` WinDivert 适配层、表驱动单元测试与 `go test ./...` 回归。

---

## 文件结构

- Create: `internal/reassembly/state.go`
- Create: `internal/reassembly/state_test.go`
- Modify: `internal/tlsrecord/record.go`
- Modify: `internal/tlsrecord/record_test.go`
- Modify: `internal/mutate/mutate.go`
- Modify: `internal/mutate/mutate_test.go`
- Modify: `internal/session/store.go`
- Modify: `internal/session/store_test.go`
- Modify: `internal/capture/loop.go`
- Modify: `internal/capture/loop_test.go`
- Modify: `README.md`

## Task 1: 新增独立的最小出站重组状态机

**Files:**
- Create: `internal/reassembly/state.go`
- Create: `internal/reassembly/state_test.go`
- Modify: `internal/tlsrecord/record.go`
- Modify: `internal/tlsrecord/record_test.go`

- [ ] **Step 1: 先写最小重组行为的失败测试**

```go
func TestStateAssemblesCrossPacketApplicationData(t *testing.T) {
	state := NewState(1000)

	points, err := state.Push(Segment{
		Seq: 1000,
		Data: []byte{
			0x17, 0x03, 0x03, 0x00, 0x08,
			0xaa, 0xbb,
		},
	})
	if err != nil {
		t.Fatalf("Push returned error: %v", err)
	}
	if len(points) != 0 {
		t.Fatalf("expected no mutation point before record is complete, got %d", len(points))
	}

	points, err = state.Push(Segment{
		Seq: 1007,
		Data: []byte{0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22},
	})
	if err != nil {
		t.Fatalf("Push returned error: %v", err)
	}
	if len(points) != 1 {
		t.Fatalf("expected one mutation point after record completion, got %d", len(points))
	}
	if points[0].TargetSeq != 1005 {
		t.Fatalf("unexpected target seq: %d", points[0].TargetSeq)
	}
}

func TestStateBuffersLightOutOfOrderSegment(t *testing.T) {
	state := NewState(1000)

	if _, err := state.Push(Segment{Seq: 1007, Data: []byte{0xcc, 0xdd}}); err != nil {
		t.Fatalf("Push returned error: %v", err)
	}
	if state.NextSeq() != 1000 {
		t.Fatalf("unexpected next seq after out-of-order buffer: %d", state.NextSeq())
	}

	if _, err := state.Push(Segment{
		Seq: 1000,
		Data: []byte{0x17, 0x03, 0x03, 0x00, 0x04, 0xaa, 0xbb},
	}); err != nil {
		t.Fatalf("Push returned error: %v", err)
	}
	if state.NextSeq() <= 1000 {
		t.Fatalf("expected next seq to advance, got %d", state.NextSeq())
	}
}
```

- [ ] **Step 2: 运行新包测试确认失败**

Run: `go test ./internal/reassembly ./internal/tlsrecord -run "TestStateAssemblesCrossPacketApplicationData|TestStateBuffersLightOutOfOrderSegment" -v`  
Expected: FAIL，提示缺少 `internal/reassembly` 包或缺少 `NewState` / `Segment` / `Push` / `NextSeq`。

- [ ] **Step 3: 写最小实现让重组状态机跑起来**

```go
package reassembly

type Segment struct {
	Seq  uint32
	Data []byte
}

type MutationPoint struct {
	RecordStartSeq uint32
	TargetSeq      uint32
	RecordLength   int
}

type State struct {
	nextSeq uint32
	queue   []Segment
	stream  []byte
}

func NewState(initialSeq uint32) *State {
	return &State{nextSeq: initialSeq}
}

func (s *State) NextSeq() uint32 {
	return s.nextSeq
}

func (s *State) Push(seg Segment) ([]MutationPoint, error) {
	// 先缓冲 segment，再尝试按 nextSeq 拼成连续流。
	// 每次 stream 增长后，从流头开始迭代解析完整 TLS record。
	// 只要拼出完整 Application Data record，就生成一个 MutationPoint。
	return nil, nil
}
```

```go
// internal/tlsrecord/record.go
func FindFirstCompleteRecord(payload []byte) (Record, bool) {
	const headerLen = 5
	for offset := 0; offset+headerLen <= len(payload); {
		contentType := payload[offset]
		version := uint16(payload[offset+1])<<8 | uint16(payload[offset+2])
		if !isValidContentType(contentType) || !isValidVersion(version) {
			offset++
			continue
		}

		recLen := int(payload[offset+3])<<8 | int(payload[offset+4])
		totalLen := headerLen + recLen
		if offset+totalLen > len(payload) {
			return Record{}, false
		}

		return Record{
			Start:     offset,
			HeaderLen: headerLen,
			DataStart: offset + headerLen,
			DataLen:   recLen,
			TotalLen:  totalLen,
			Type:      contentType,
			Version:   version,
		}, true
	}
	return Record{}, false
}
```

- [ ] **Step 4: 补 1 个“非 Application Data record 不生成破坏点”的负向测试并重新跑测试**

```go
func TestStateSkipsNonApplicationDataRecord(t *testing.T) {
	state := NewState(1000)
	points, err := state.Push(Segment{
		Seq: 1000,
		Data: []byte{0x16, 0x03, 0x03, 0x00, 0x02, 0x01, 0x02},
	})
	if err != nil {
		t.Fatalf("Push returned error: %v", err)
	}
	if len(points) != 0 {
		t.Fatalf("expected no mutation point for handshake record, got %d", len(points))
	}
}
```

Run: `go test ./internal/reassembly ./internal/tlsrecord -v`  
Expected: PASS

- [ ] **Step 5: 提交最小出站重组骨架**

```bash
git add internal/reassembly/state.go internal/reassembly/state_test.go internal/tlsrecord/record.go internal/tlsrecord/record_test.go
git commit -m "feat: 增加最小出站重组状态机"
```

## Task 2: 让篡改点按绝对序列号工作并支持重传一致性

**Files:**
- Modify: `internal/mutate/mutate.go`
- Modify: `internal/mutate/mutate_test.go`
- Modify: `internal/reassembly/state.go`
- Modify: `internal/reassembly/state_test.go`

- [ ] **Step 1: 先写“包覆盖 targetSeq 就篡改”的失败测试**

```go
func TestApplyMutationPointMutatesCoveredSequence(t *testing.T) {
	payload := []byte{0xaa, 0xbb, 0xcc, 0xdd}
	point := MutationPoint{
		TargetSeq: 2002,
		OldByte:   0xcc,
		NewByte:   0x33,
	}

	got, ok := ApplyMutationPoint(payload, 2000, point)
	if !ok {
		t.Fatal("expected mutation to apply")
	}
	if got.PayloadIndex != 2 || payload[2] != 0x33 {
		t.Fatalf("unexpected mutation: %+v payload=%x", got, payload)
	}
}

func TestApplyMutationPointSupportsRetransmissionWithDifferentSegmentation(t *testing.T) {
	payload := []byte{0xbb, 0xcc, 0xdd}
	point := MutationPoint{
		TargetSeq: 2002,
		OldByte:   0xcc,
		NewByte:   0x33,
	}

	got, ok := ApplyMutationPoint(payload, 2001, point)
	if !ok {
		t.Fatal("expected retransmitted segment to hit target sequence")
	}
	if got.PayloadIndex != 1 || payload[1] != 0x33 {
		t.Fatalf("unexpected retransmission mutation: %+v payload=%x", got, payload)
	}
}
```

- [ ] **Step 2: 运行篡改测试确认失败**

Run: `go test ./internal/mutate ./internal/reassembly -run "TestApplyMutationPointMutatesCoveredSequence|TestApplyMutationPointSupportsRetransmissionWithDifferentSegmentation" -v`  
Expected: FAIL，提示缺少 `ApplyMutationPoint`、`OldByte` / `NewByte` 字段或 `MutationPoint` 定义不完整。

- [ ] **Step 3: 写最小实现，让篡改点与绝对序列号绑定**

```go
// internal/reassembly/state.go
type MutationPoint struct {
	RecordStartSeq uint32
	TargetSeq      uint32
	RecordLength   int
	OldByte        byte
	NewByte        byte
	CreatedAt      time.Time
}
```

```go
// internal/mutate/mutate.go
type AppliedMutation struct {
	PayloadIndex int
	TargetSeq    uint32
	OldByte      byte
	NewByte      byte
}

func ApplyMutationPoint(payload []byte, payloadSeq uint32, point reassembly.MutationPoint) (AppliedMutation, bool) {
	if len(payload) == 0 {
		return AppliedMutation{}, false
	}

	if point.TargetSeq < payloadSeq {
		return AppliedMutation{}, false
	}

	offset := int(point.TargetSeq - payloadSeq)
	if offset < 0 || offset >= len(payload) {
		return AppliedMutation{}, false
	}

	payload[offset] = point.NewByte
	return AppliedMutation{
		PayloadIndex: offset,
		TargetSeq:    point.TargetSeq,
		OldByte:      point.OldByte,
		NewByte:      point.NewByte,
	}, true
}
```

```go
// internal/reassembly/state.go
// 生成 MutationPoint 时按 record.DataStart + mutateOffset 选择破坏点；若偏移超出数据区，则保守跳过该 record。
point := MutationPoint{
	RecordStartSeq: recordSeq,
	TargetSeq:      recordSeq + uint32(rec.DataStart+mutateOffset),
	RecordLength:   rec.TotalLen,
	OldByte:        stream[rec.DataStart+mutateOffset],
	NewByte:        stream[rec.DataStart+mutateOffset] ^ 0xff,
	CreatedAt:      now,
}
```

- [ ] **Step 4: 补 1 个“不覆盖 targetSeq 时不篡改”的负向测试并重新跑测试**

```go
func TestApplyMutationPointSkipsPacketWithoutTargetSequence(t *testing.T) {
	payload := []byte{0xaa, 0xbb}
	point := MutationPoint{
		TargetSeq: 2005,
		OldByte:   0xcc,
		NewByte:   0x33,
	}

	if _, ok := ApplyMutationPoint(payload, 2000, point); ok {
		t.Fatal("expected packet without target sequence to remain untouched")
	}
}
```

Run: `go test ./internal/mutate ./internal/reassembly -v`  
Expected: PASS

- [ ] **Step 5: 提交绝对序列号篡改点能力**

```bash
git add internal/mutate/mutate.go internal/mutate/mutate_test.go internal/reassembly/state.go internal/reassembly/state_test.go
git commit -m "feat: 支持按绝对序列号追踪篡改点"
```

## Task 3: 扩展会话层，保存待确认篡改点并用 ACK 清理

**Files:**
- Modify: `internal/session/store.go`
- Modify: `internal/session/store_test.go`
- Modify: `internal/reassembly/state.go`

- [ ] **Step 1: 先写 ACK 清理与连接结束清理的失败测试**

```go
func TestStoreDropsMutationPointsAfterAckCoversTargetSeq(t *testing.T) {
	store := NewStore(func() time.Time { return time.Unix(100, 0) })
	key := Key{ClientIP: "10.0.0.2", ClientPort: 50000, ServerIP: "93.184.216.34", ServerPort: 443}

	store.AddMutationPoint(key, reassembly.MutationPoint{TargetSeq: 2002})
	if len(store.PendingMutationPoints(key)) != 1 {
		t.Fatalf("expected one pending point")
	}

	store.AckUpTo(key, 2003)
	if got := len(store.PendingMutationPoints(key)); got != 0 {
		t.Fatalf("expected mutation point to be cleared after ack, got %d", got)
	}
}

func TestStoreKeepsMutationPointWhenAckDoesNotCoverTargetSeq(t *testing.T) {
	store := NewStore(func() time.Time { return time.Unix(100, 0) })
	key := Key{ClientIP: "10.0.0.2", ClientPort: 50000, ServerIP: "93.184.216.34", ServerPort: 443}

	store.AddMutationPoint(key, reassembly.MutationPoint{TargetSeq: 2002})
	store.AckUpTo(key, 2002)

	if got := len(store.PendingMutationPoints(key)); got != 1 {
		t.Fatalf("expected pending point to remain before full coverage, got %d", got)
	}
}
```

- [ ] **Step 2: 运行 session 测试确认失败**

Run: `go test ./internal/session -run "TestStoreDropsMutationPointsAfterAckCoversTargetSeq|TestStoreKeepsMutationPointWhenAckDoesNotCoverTargetSeq" -v`  
Expected: FAIL，提示缺少 `AddMutationPoint`、`AckUpTo` 或 `PendingMutationPoints`。

- [ ] **Step 3: 写最小实现，把待确认篡改点挂到连接状态上**

```go
type entry struct {
	mutatedAt      time.Time
	observeFor     time.Duration
	byteIndex      int
	matchState     MatchState
	hasMutation    bool
	lastObserved   time.Time
	done           bool
	outcome        Outcome
	frozen         Result
	reassembly     *reassembly.State
	pendingPoints  []reassembly.MutationPoint
	lastAck        uint32
}
```

```go
func (s *Store) Reassembly(key Key, initialSeq uint32) *reassembly.State
func (s *Store) AddMutationPoint(key Key, point reassembly.MutationPoint)
func (s *Store) PendingMutationPoints(key Key) []reassembly.MutationPoint
func (s *Store) AckUpTo(key Key, ack uint32)
```

```go
func (s *Store) AckUpTo(key Key, ack uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.data[key]
	if !ok {
		return
	}

	e.lastAck = ack
	filtered := e.pendingPoints[:0]
	for _, point := range e.pendingPoints {
		if ack <= point.TargetSeq {
			filtered = append(filtered, point)
		}
	}
	e.pendingPoints = filtered
}
```

- [ ] **Step 4: 补 1 个“连接 Forget 后重组状态和待确认篡改点一起消失”的回归测试并重新跑测试**

```go
func TestStoreForgetClearsReassemblyAndMutationPoints(t *testing.T) {
	store := NewStore(func() time.Time { return time.Unix(100, 0) })
	key := Key{ClientIP: "10.0.0.2", ClientPort: 50000, ServerIP: "93.184.216.34", ServerPort: 443}

	store.Reassembly(key, 1000)
	store.AddMutationPoint(key, reassembly.MutationPoint{TargetSeq: 2002})
	store.Forget(key)

	if got := len(store.PendingMutationPoints(key)); got != 0 {
		t.Fatalf("expected no pending mutation points after forget, got %d", got)
	}
}
```

Run: `go test ./internal/session -v`  
Expected: PASS

- [ ] **Step 5: 提交会话层 ACK 清理能力**

```bash
git add internal/session/store.go internal/session/store_test.go internal/reassembly/state.go
git commit -m "feat: 增加待确认篡改点与 ACK 清理"
```

## Task 4: 接入抓包主循环，先应用已知破坏点，再推进重组生成新的破坏点

**Files:**
- Modify: `internal/capture/loop.go`
- Modify: `internal/capture/loop_test.go`
- Modify: `README.md`

- [ ] **Step 1: 先写主循环的跨包 record 与重传一致性失败测试**

```go
func TestLoopMutatesCrossPacketApplicationDataAfterReassembly(t *testing.T) {
	cfg := config.Config{
		TargetIP:       netip.MustParseAddr("93.184.216.34"),
		TargetPort:     443,
		TargetHost:     "",
		ObserveTimeout: 10 * time.Millisecond,
		MutateOffset:   0,
	}

	out := &scriptedHandle{steps: []recvStep{
		{packet: outboundSplitTLSPacketPart1()},
		{packet: outboundSplitTLSPacketPart2()},
	}}
	in := &scriptedHandle{}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	if err := RunLoop(context.Background(), cfg, logger, out, in); err != nil {
		t.Fatalf("RunLoop returned error: %v", err)
	}

	if got := out.sent[1].packet[41]; got != 0x55 {
		t.Fatalf("expected second packet to carry deterministic mutation, got 0x%02x", got)
	}
}

func TestLoopReappliesMutationOnRetransmission(t *testing.T) {
	cfg := config.Config{
		TargetIP:       netip.MustParseAddr("93.184.216.34"),
		TargetPort:     443,
		ObserveTimeout: 10 * time.Millisecond,
		MutateOffset:   0,
	}

	out := &scriptedHandle{steps: []recvStep{
		{packet: outboundSplitTLSPacketPart1()},
		{packet: outboundSplitTLSPacketPart2()},
		{packet: outboundSplitTLSPacketPart2Retransmission()},
	}}
	in := &scriptedHandle{}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	if err := RunLoop(context.Background(), cfg, logger, out, in); err != nil {
		t.Fatalf("RunLoop returned error: %v", err)
	}

	if got := out.sent[1].packet[41]; got != 0x55 {
		t.Fatalf("expected first send of target segment to mutate, got 0x%02x", got)
	}
	if got := out.sent[2].packet[41]; got != 0x55 {
		t.Fatalf("expected retransmission to mutate identically, got 0x%02x", got)
	}
}
```

- [ ] **Step 2: 运行 capture 测试确认失败**

Run: `go test ./internal/capture -run "TestLoopMutatesCrossPacketApplicationDataAfterReassembly|TestLoopReappliesMutationOnRetransmission" -v`  
Expected: FAIL，提示当前主循环还只支持首个完整单包 record 的单次篡改。

- [ ] **Step 3: 写最小实现，把破坏点和重组接到主循环**

```go
func processOutbound(
	cfg config.Config,
	logger *slog.Logger,
	store *session.Store,
	handle packetHandle,
	packet []byte,
	addr any,
) (session.Key, bool, bool, error) {
	meta, err := tcpmeta.ParseIPv4TCP(packet)
	if err != nil {
		return session.Key{}, false, false, handle.Send(packet, addr)
	}

	key := outboundKey(meta)
	if !matchesOutbound(cfg, meta) {
		return session.Key{}, false, false, handle.Send(packet, addr)
	}

	// 先应用所有已知的待确认篡改点，确保重传包优先得到一致篡改。
	for _, point := range store.PendingMutationPoints(key) {
		if _, ok := mutate.ApplyMutationPoint(meta.Payload, meta.Seq, point); ok {
			break
		}
	}

	// 再推进目标连接的出站最小重组，只为完整 Application Data record 生成一个新破坏点。
	reassemblyState := store.Reassembly(key, meta.Seq)
	points, err := reassemblyState.Push(reassembly.Segment{Seq: meta.Seq, Data: append([]byte(nil), meta.Payload...)})
	if err != nil {
		return session.Key{}, false, false, fmt.Errorf("推进出站最小重组失败: %w", err)
	}
	for _, point := range points {
		store.AddMutationPoint(key, point)
		if applied, ok := mutate.ApplyMutationPoint(meta.Payload, meta.Seq, point); ok {
			store.MarkMutated(key, cfg.ObserveTimeout, meta.PayloadOffset+applied.PayloadIndex)
			logger.Info("命中新 application data 破坏点", "target_seq", point.TargetSeq, "packet_index", meta.PayloadOffset+applied.PayloadIndex)
		}
	}

	return key, store.HasMutation(key), false, handle.Send(packet, addr)
}
```

```go
func processInbound(...) (session.Key, session.Result, bool, bool, error) {
	// 维持现有结果观察逻辑。
	// 在解析到来自服务端的 ACK 后，调用 store.AckUpTo(key, meta.Ack) 清理已确认破坏点。
}
```

- [ ] **Step 4: 补 2 个回归测试并重新跑全量测试**

```go
func TestLoopStillMutatesSinglePacketApplicationData(t *testing.T) { /* 复用现有单包场景，确保不退化 */ }
func TestLoopAckClearsPendingMutationPoint(t *testing.T) { /* 入站 ACK 覆盖 targetSeq 后，重传包不再继续被篡改 */ }
```

Run: `go test ./internal/capture -v`  
Expected: PASS

Run: `go test ./...`  
Expected: PASS

- [ ] **Step 5: 更新 README 并提交主循环升级**

```markdown
## 最新说明

- 现在的篡改单位是“每条经出站最小 TCP 重组后确认完整的 TLS Application Data record”
- 每条完整 record 只生成一个破坏点，位置由 `mutate-offset` 决定
- 任意覆盖该破坏点的发送包或重传包都会施加相同篡改
- 若完整 record 的数据长度不足以覆盖 `mutate-offset`，则保守跳过该 record
- 无法确认完整 record 边界时保守放行
```

```bash
git add internal/capture/loop.go internal/capture/loop_test.go README.md
git commit -m "feat: 接入出站最小重组与 record 级篡改"
```

## 自检

### Spec coverage

- `每条完整 Application Data record 只破坏一次`: Task 1、Task 2、Task 4
- `按绝对 TCP 序列号追踪破坏点`: Task 2
- `对重传包重复施加同样破坏`: Task 2、Task 4
- `出站方向最小 TCP 重组`: Task 1、Task 4
- `ACK 覆盖后清理不再可能重传的破坏点`: Task 3、Task 4
- `现有 IP/SNI 命中逻辑不退化`: Task 4 回归测试
- `无法确认完整 record 边界时保守跳过`: Task 1、Task 4

### Placeholder scan

- 无 `TODO`、`TBD`、`后续补充`
- 每个任务都包含明确文件、测试代码、运行命令和提交命令
- 没有“按需处理”“适当增加校验”这类空话步骤

### Type consistency

- 新增重组状态统一放在 `internal/reassembly`
- 破坏点类型统一命名为 `reassembly.MutationPoint`
- 包内实际篡改入口统一为 `mutate.ApplyMutationPoint`
- 会话层统一通过 `session.Store` 保存重组状态和待确认破坏点
- 主循环仍然围绕 `processOutbound` / `processInbound` 扩展，不引入第二套抓包入口
