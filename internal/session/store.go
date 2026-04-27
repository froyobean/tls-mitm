// Package session 维护连接级篡改状态与观察结果。
package session

import (
	"fmt"
	"sync"
	"time"

	"tls-mitm/internal/reassembly"
)

// Key 唯一标识一条客户端到服务端的 TCP 连接。
type Key struct {
	ClientIP   string
	ClientPort uint16
	ServerIP   string
	ServerPort uint16
}

// Outcome 表示一次连接观察的最终分类结果。
type Outcome string

const (
	// OutcomeUnknown 表示当前仍未得到确定结果。
	OutcomeUnknown Outcome = "unknown"
	// OutcomeDefiniteFailure 表示已明确观察到认证失败或连接失败信号。
	OutcomeDefiniteFailure Outcome = "definite_failure"
	// OutcomeProbableFailure 表示观察到较强但非绝对的失败信号。
	OutcomeProbableFailure Outcome = "probable_failure"
	// OutcomeNoConclusion 表示在观察窗口内没有得到明确结论。
	OutcomeNoConclusion Outcome = "no_conclusion"
)

// MatchState 表示连接当前的目标匹配状态。
type MatchState string

const (
	// MatchStateUnknown 表示当前连接尚未判定是否命中目标。
	MatchStateUnknown MatchState = "unknown"
	// MatchStateMatched 表示当前连接已确认命中目标。
	MatchStateMatched MatchState = "matched"
	// MatchStateExcluded 表示当前连接已确认不命中目标。
	MatchStateExcluded MatchState = "excluded"
)

// Signal 描述一次与连接状态相关的外部观测信号。
type Signal struct {
	FromServer bool
	RST        bool
	FIN        bool
	Alert      bool
}

// Result 描述一条连接当前或最终的观察结果。
type Result struct {
	Outcome     Outcome
	ObservedFor time.Duration
	ByteIndex   int
}

// Store 保存连接篡改状态以及后续观察结果。
type Store struct {
	mu          sync.Mutex
	now         func() time.Time
	data        map[Key]*entry
	nextTraceID uint64
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

type directionState struct {
	reassembly    *reassembly.State
	pendingPoints []reassembly.MutationPoint
	lastAck       uint32
}

// NewStore 创建一份新的连接状态存储。
func NewStore(now func() time.Time) *Store {
	if now == nil {
		now = time.Now
	}
	return &Store{
		now:  now,
		data: make(map[Key]*entry),
	}
}

// ShouldMutate 返回该连接当前是否允许执行首次篡改。
func (s *Store) ShouldMutate(key Key) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.data[key]
	if !ok {
		return false
	}
	return e.matchState == MatchStateMatched && !e.hasMutation
}

// MatchState 返回连接当前的目标匹配状态。
func (s *Store) MatchState(key Key) MatchState {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.data[key]
	if !ok {
		return MatchStateUnknown
	}
	if e.matchState == "" {
		return MatchStateUnknown
	}
	return e.matchState
}

// HasMutation 报告连接是否已经进入过一次篡改。
func (s *Store) HasMutation(key Key) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.data[key]
	if !ok {
		return false
	}
	return e.hasMutation
}

// OutboundReassembly 返回出站方向对应的重组状态。
func (s *Store) OutboundReassembly(key Key, initialSeq uint32) *reassembly.State {
	s.mu.Lock()
	defer s.mu.Unlock()

	e := s.ensureEntryLocked(key)
	return reassemblyFor(&e.outbound, initialSeq)
}

// InboundReassembly 返回入站方向对应的重组状态。
func (s *Store) InboundReassembly(key Key, initialSeq uint32) *reassembly.State {
	s.mu.Lock()
	defer s.mu.Unlock()

	e := s.ensureEntryLocked(key)
	return reassemblyFor(&e.inbound, initialSeq)
}

// Reassembly 返回连接对应的出站重组状态，不存在时按初始序号创建。
// 调用方应串行使用返回的内部可变状态。
func (s *Store) Reassembly(key Key, initialSeq uint32) *reassembly.State {
	return s.OutboundReassembly(key, initialSeq)
}

// TraceID 返回连接级 trace_id，未知连接返回空字符串。
func (s *Store) TraceID(key Key) string {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.data[key]
	if !ok {
		return ""
	}
	return e.traceID
}

// AddOutboundMutationPoint 记录一个出站方向待确认的篡改点。
func (s *Store) AddOutboundMutationPoint(key Key, point reassembly.MutationPoint) {
	s.mu.Lock()
	defer s.mu.Unlock()

	e := s.ensureEntryLocked(key)
	addMutationPoint(&e.outbound, point)
}

// AddInboundMutationPoint 记录一个入站方向待确认的篡改点。
func (s *Store) AddInboundMutationPoint(key Key, point reassembly.MutationPoint) {
	s.mu.Lock()
	defer s.mu.Unlock()

	e := s.ensureEntryLocked(key)
	addMutationPoint(&e.inbound, point)
}

// AddMutationPoint 保留给现有调用方使用，语义映射到出站方向。
func (s *Store) AddMutationPoint(key Key, point reassembly.MutationPoint) {
	s.AddOutboundMutationPoint(key, point)
}

// OutboundPendingMutationPoints 返回出站方向当前尚未被 ACK 覆盖的篡改点副本。
func (s *Store) OutboundPendingMutationPoints(key Key) []reassembly.MutationPoint {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.data[key]
	if !ok {
		return nil
	}
	return pendingMutationPoints(&e.outbound)
}

// InboundPendingMutationPoints 返回入站方向当前尚未被 ACK 覆盖的篡改点副本。
func (s *Store) InboundPendingMutationPoints(key Key) []reassembly.MutationPoint {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.data[key]
	if !ok {
		return nil
	}
	return pendingMutationPoints(&e.inbound)
}

// PendingMutationPoints 保留给现有调用方使用，语义映射到出站方向。
func (s *Store) PendingMutationPoints(key Key) []reassembly.MutationPoint {
	return s.OutboundPendingMutationPoints(key)
}

// AckOutboundUpTo 处理入站包携带的 ACK，清理已经被确认的 outbound pending points.
func (s *Store) AckOutboundUpTo(key Key, ack uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.data[key]
	if !ok {
		return
	}
	ackUpTo(&e.outbound, ack)
}

// AckInboundUpTo 处理出站包携带的 ACK，清理已经被确认的 inbound pending points.
func (s *Store) AckInboundUpTo(key Key, ack uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.data[key]
	if !ok {
		return
	}
	ackUpTo(&e.inbound, ack)
}

// AckUpTo 保留给现有调用方使用，语义映射到出站方向。
func (s *Store) AckUpTo(key Key, ack uint32) {
	s.AckOutboundUpTo(key, ack)
}

// MarkMatched 将连接标记为已命中目标。
func (s *Store) MarkMatched(key Key) {
	s.mu.Lock()
	defer s.mu.Unlock()

	e := s.ensureEntryLocked(key)
	e.matchState = MatchStateMatched
}

// MarkExcluded 将连接标记为已排除目标。
func (s *Store) MarkExcluded(key Key) {
	s.mu.Lock()
	defer s.mu.Unlock()

	e := s.ensureEntryLocked(key)
	e.matchState = MatchStateExcluded
}

// Forget 删除连接的全部状态，让同一四元组后续可以重新判定。
func (s *Store) Forget(key Key) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.data, key)
}

// ResetObservation 结束当前轮次观察，但保留连接级身份与状态（如 traceID、matchState、重组状态等）。
func (s *Store) ResetObservation(key Key) {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.data[key]
	if !ok {
		return
	}
	resetObservationLocked(e)
	e.hasMutation = false
}

// MarkMutated 记录一条连接进入或刷新篡改后观察阶段。
func (s *Store) MarkMutated(key Key, observe time.Duration, byteIndex int) {
	_ = s.TryMarkMutated(key, observe, byteIndex)
}

// TryMarkMutated 以原子方式尝试将连接标记为首次篡改，并刷新观察窗口起点。
func (s *Store) TryMarkMutated(key Key, observe time.Duration, byteIndex int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	e := s.ensureEntryLocked(key)
	firstMutation := !e.hasMutation
	resetObservationLocked(e)
	e.hasMutation = true
	e.mutatedAt = s.now()
	e.observeFor = observe
	e.byteIndex = byteIndex
	return firstMutation
}

// Observe 根据新的观测信号更新并返回连接结果。
func (s *Store) Observe(key Key, sig Signal) Result {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.data[key]
	if !ok || !e.hasMutation {
		return Result{Outcome: OutcomeNoConclusion}
	}

	now := s.now()
	e.lastObserved = now

	if e.done {
		// 一旦结果冻结，后续信号只能复用同一份终态，避免晚到数据包改写已经判定的结论。
		return e.frozen
	}

	observedFor := now.Sub(e.mutatedAt)
	if observedFor >= e.observeFor {
		e.done = true
		e.outcome = OutcomeNoConclusion
		e.frozen = s.buildResultLocked(e, e.outcome, observedFor)
		return e.frozen
	}

	if outcome, ok := classifySignal(sig); ok {
		e.done = true
		e.outcome = outcome
		e.frozen = s.buildResultLocked(e, e.outcome, observedFor)
		return e.frozen
	}

	return s.buildResultLocked(e, OutcomeUnknown, observedFor)
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

func (s *Store) buildResultLocked(e *entry, outcome Outcome, observedFor time.Duration) Result {
	return Result{
		Outcome:     outcome,
		ObservedFor: observedFor,
		ByteIndex:   e.byteIndex,
	}
}

func resetObservationLocked(e *entry) {
	e.mutatedAt = time.Time{}
	e.observeFor = 0
	e.byteIndex = 0
	e.lastObserved = time.Time{}
	e.done = false
	e.outcome = OutcomeUnknown
	e.frozen = Result{}
}

func classifySignal(sig Signal) (Outcome, bool) {
	if sig.FromServer && sig.RST {
		return OutcomeDefiniteFailure, true
	}
	if sig.FIN || sig.Alert || sig.RST {
		return OutcomeProbableFailure, true
	}
	return OutcomeUnknown, false
}
