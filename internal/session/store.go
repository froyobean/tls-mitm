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

// Reassembly 返回连接对应的出站重组状态，不存在时按初始序号创建。
// 调用方应串行使用返回的内部可变状态。
func (s *Store) Reassembly(key Key, initialSeq uint32) *reassembly.State {
	s.mu.Lock()
	defer s.mu.Unlock()

	e := s.ensureEntryLocked(key)
	if e.reassembly == nil {
		e.reassembly = reassembly.NewState(initialSeq)
	}
	return e.reassembly
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

// AddMutationPoint 记录一个待确认的篡改点。
func (s *Store) AddMutationPoint(key Key, point reassembly.MutationPoint) {
	s.mu.Lock()
	defer s.mu.Unlock()

	e := s.ensureEntryLocked(key)
	if e.lastAck > point.TargetSeq {
		return
	}
	e.pendingPoints = append(e.pendingPoints, point)
}

// PendingMutationPoints 返回连接当前尚未被 ACK 覆盖的篡改点副本。
func (s *Store) PendingMutationPoints(key Key) []reassembly.MutationPoint {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.data[key]
	if !ok || len(e.pendingPoints) == 0 {
		return nil
	}

	points := make([]reassembly.MutationPoint, len(e.pendingPoints))
	copy(points, e.pendingPoints)
	return points
}

// AckUpTo 清理所有已经被 ACK 覆盖的待确认篡改点。
func (s *Store) AckUpTo(key Key, ack uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.data[key]
	if !ok {
		return
	}
	effectiveAck := e.lastAck
	if ack > effectiveAck {
		effectiveAck = ack
	}
	e.lastAck = effectiveAck

	filtered := e.pendingPoints[:0]
	for _, point := range e.pendingPoints {
		if effectiveAck <= point.TargetSeq {
			filtered = append(filtered, point)
		}
	}
	if len(filtered) == 0 {
		e.pendingPoints = nil
		return
	}
	e.pendingPoints = filtered
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
	e.hasMutation = true
	e.mutatedAt = s.now()
	e.observeFor = observe
	e.byteIndex = byteIndex
	e.done = false
	e.outcome = OutcomeUnknown
	e.frozen = Result{}
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

func (s *Store) buildResultLocked(e *entry, outcome Outcome, observedFor time.Duration) Result {
	return Result{
		Outcome:     outcome,
		ObservedFor: observedFor,
		ByteIndex:   e.byteIndex,
	}
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
