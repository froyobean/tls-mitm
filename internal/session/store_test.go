package session

import (
	"sync"
	"testing"
	"time"

	"tls-mitm/internal/reassembly"
)

func testSessionKey() Key {
	return Key{
		ClientIP:   "10.0.0.2",
		ClientPort: 50000,
		ServerIP:   "93.184.216.34",
		ServerPort: 443,
	}
}

func TestStoreSupportsMatchStateTransitions(t *testing.T) {
	store := NewStore(func() time.Time { return time.Unix(100, 0) })
	key := testSessionKey()

	if got := store.MatchState(key); got != MatchStateUnknown {
		t.Fatalf("unexpected initial match state: %s", got)
	}

	store.MarkMatched(key)
	if got := store.MatchState(key); got != MatchStateMatched {
		t.Fatalf("unexpected matched state: %s", got)
	}

	store.MarkExcluded(key)
	if got := store.MatchState(key); got != MatchStateExcluded {
		t.Fatalf("unexpected excluded state: %s", got)
	}
}

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

func TestStoreExcludeStatePreventsMutation(t *testing.T) {
	store := NewStore(func() time.Time { return time.Unix(100, 0) })
	key := testSessionKey()

	store.MarkExcluded(key)

	if got := store.MatchState(key); got != MatchStateExcluded {
		t.Fatalf("unexpected match state: %s", got)
	}
	if store.ShouldMutate(key) {
		t.Fatal("excluded connection should not mutate")
	}
}

func TestStoreForgetClearsConnectionState(t *testing.T) {
	store := NewStore(func() time.Time { return time.Unix(100, 0) })
	key := testSessionKey()

	store.MarkMatched(key)
	store.MarkMutated(key, 5*time.Second, 8)
	if !store.HasMutation(key) {
		t.Fatal("mutated connection should report mutation")
	}
	store.Forget(key)

	if got := store.MatchState(key); got != MatchStateUnknown {
		t.Fatalf("forgotten connection should return to unknown state, got %s", got)
	}
	if store.ShouldMutate(key) {
		t.Fatal("forgotten connection should not mutate")
	}
	if store.HasMutation(key) {
		t.Fatal("forgotten connection should not report mutation")
	}
}

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

func TestStoreResetObservationClearsTerminalRoundBeforeRestart(t *testing.T) {
	now := time.Unix(100, 0)
	store := NewStore(func() time.Time { return now })
	key := testSessionKey()

	if !store.TryMarkMutated(key, 5*time.Second, 45) {
		t.Fatal("expected first mutation to report first observation")
	}

	first := store.Observe(key, Signal{FromServer: true, RST: true})
	if first.Outcome != OutcomeDefiniteFailure {
		t.Fatalf("expected terminal result before reset, got %s", first.Outcome)
	}
	if first.ByteIndex != 45 {
		t.Fatalf("expected first round byte index 45, got %d", first.ByteIndex)
	}

	store.ResetObservation(key)

	if got := store.Observe(key, Signal{FromServer: true, RST: true}); got.Outcome != OutcomeNoConclusion {
		t.Fatalf("expected reset to clear terminal round before restart, got %s", got.Outcome)
	}

	if !store.TryMarkMutated(key, 3*time.Second, 99) {
		t.Fatal("expected new round to report first observation")
	}
	now = now.Add(2 * time.Second)

	second := store.Observe(key, Signal{FromServer: true, RST: true})
	if second.Outcome != OutcomeDefiniteFailure {
		t.Fatalf("expected restarted round to classify terminal signal, got %s", second.Outcome)
	}
	if second.ObservedFor != 2*time.Second {
		t.Fatalf("expected restarted round to use new observe window, got %s", second.ObservedFor)
	}
	if second.ByteIndex != 99 {
		t.Fatalf("expected restarted round to use new byte index 99, got %d", second.ByteIndex)
	}
}

func TestStoreMutatesOnlyOncePerConnection(t *testing.T) {
	store := NewStore(func() time.Time { return time.Unix(100, 0) })
	key := testSessionKey()

	store.MarkMatched(key)

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
	key := testSessionKey()

	store.MarkMutated(key, 5*time.Second, 8)
	got := store.Observe(key, Signal{FromServer: true, RST: true})
	if got.Outcome != OutcomeDefiniteFailure {
		t.Fatalf("unexpected outcome: %s", got.Outcome)
	}
}

func TestObserveTimeoutReturnsNoConclusion(t *testing.T) {
	now := time.Unix(100, 0)
	store := NewStore(func() time.Time { return now })
	key := testSessionKey()

	store.MarkMutated(key, 5*time.Second, 8)
	now = now.Add(6 * time.Second)

	got := store.Observe(key, Signal{})
	if got.Outcome != OutcomeNoConclusion {
		t.Fatalf("unexpected outcome: %s", got.Outcome)
	}
}

func TestLateFINDoesNotReclassifyAfterTimeout(t *testing.T) {
	now := time.Unix(100, 0)
	store := NewStore(func() time.Time { return now })
	key := testSessionKey()

	store.MarkMutated(key, 5*time.Second, 8)
	now = now.Add(6 * time.Second)
	first := store.Observe(key, Signal{})
	if first.Outcome != OutcomeNoConclusion {
		t.Fatalf("unexpected first outcome: %s", first.Outcome)
	}

	second := store.Observe(key, Signal{FromServer: true, FIN: true})
	if second.Outcome != OutcomeNoConclusion {
		t.Fatalf("late FIN should not reclassify: %s", second.Outcome)
	}
}

func TestFINAlertAndClientRSTAreProbableFailure(t *testing.T) {
	cases := []Signal{
		{FIN: true},
		{Alert: true},
		{RST: true},
	}

	for _, sig := range cases {
		store := NewStore(func() time.Time { return time.Unix(100, 0) })
		key := testSessionKey()

		store.MarkMutated(key, 5*time.Second, 8)
		got := store.Observe(key, sig)
		if got.Outcome != OutcomeProbableFailure {
			t.Fatalf("unexpected outcome for %+v: %s", sig, got.Outcome)
		}
	}
}

func TestObserveIsTerminalAndIdempotent(t *testing.T) {
	now := time.Unix(100, 0)
	store := NewStore(func() time.Time { return now })
	key := testSessionKey()

	store.MarkMutated(key, 5*time.Second, 8)
	first := store.Observe(key, Signal{FromServer: true, RST: true})
	if first.Outcome != OutcomeDefiniteFailure {
		t.Fatalf("unexpected first outcome: %s", first.Outcome)
	}
	if first.ObservedFor != 0 {
		t.Fatalf("unexpected first observed duration: %s", first.ObservedFor)
	}

	now = now.Add(10 * time.Second)
	second := store.Observe(key, Signal{})
	if second.Outcome != OutcomeDefiniteFailure {
		t.Fatalf("terminal outcome changed: %s", second.Outcome)
	}
	if second.ObservedFor != first.ObservedFor {
		t.Fatalf("terminal observed duration changed: first=%s second=%s", first.ObservedFor, second.ObservedFor)
	}
}

func TestObserveNoConclusionIsTerminalAndIdempotent(t *testing.T) {
	now := time.Unix(100, 0)
	store := NewStore(func() time.Time { return now })
	key := testSessionKey()

	store.MarkMutated(key, 5*time.Second, 8)
	now = now.Add(6 * time.Second)
	first := store.Observe(key, Signal{})
	if first.Outcome != OutcomeNoConclusion {
		t.Fatalf("unexpected first outcome: %s", first.Outcome)
	}

	now = now.Add(10 * time.Second)
	second := store.Observe(key, Signal{FromServer: true, RST: true})
	if second.Outcome != OutcomeNoConclusion {
		t.Fatalf("terminal outcome changed: %s", second.Outcome)
	}
	if second.ObservedFor != first.ObservedFor {
		t.Fatalf("terminal observed duration changed: first=%s second=%s", first.ObservedFor, second.ObservedFor)
	}
}

func TestTryMarkMutatedIsAtomic(t *testing.T) {
	store := NewStore(func() time.Time { return time.Unix(100, 0) })
	key := testSessionKey()

	var wg sync.WaitGroup
	successes := 0
	var mu sync.Mutex
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if store.TryMarkMutated(key, 5*time.Second, 8) {
				mu.Lock()
				successes++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if successes != 1 {
		t.Fatalf("expected exactly one successful mutation, got %d", successes)
	}
}

func TestRepeatedMutationRefreshesObserveWindow(t *testing.T) {
	now := time.Unix(100, 0)
	store := NewStore(func() time.Time { return now })
	key := testSessionKey()

	if !store.TryMarkMutated(key, 5*time.Second, 8) {
		t.Fatal("expected first mutation to report first-time success")
	}

	now = now.Add(4 * time.Second)
	if store.TryMarkMutated(key, 5*time.Second, 9) {
		t.Fatal("expected repeated mutation to refresh window without reporting first-time success")
	}

	now = now.Add(2 * time.Second)
	got := store.Observe(key, Signal{FromServer: true, RST: true})
	if got.Outcome != OutcomeDefiniteFailure {
		t.Fatalf("expected refreshed mutation window to classify later RST as definite failure, got %s", got.Outcome)
	}
	if got.ObservedFor != 2*time.Second {
		t.Fatalf("expected observation duration to be measured from second mutation, got %s", got.ObservedFor)
	}
	if got.ByteIndex != 9 {
		t.Fatalf("expected latest mutation byte index to be observed, got %d", got.ByteIndex)
	}
}

func TestStoreDropsMutationPointsAfterAckCoversTargetSeq(t *testing.T) {
	store := NewStore(func() time.Time { return time.Unix(100, 0) })
	key := testSessionKey()

	store.AddMutationPoint(key, reassembly.MutationPoint{TargetSeq: 2002})
	if got := len(store.PendingMutationPoints(key)); got != 1 {
		t.Fatalf("expected one pending point, got %d", got)
	}

	store.AckUpTo(key, 2003)
	if got := len(store.PendingMutationPoints(key)); got != 0 {
		t.Fatalf("expected mutation point to be cleared after ack, got %d", got)
	}
}

func TestStoreSeparatesOutboundAndInboundReassemblyState(t *testing.T) {
	store := NewStore(func() time.Time { return time.Unix(100, 0) })
	key := testSessionKey()

	outbound := store.OutboundReassembly(key, 1000)
	if outbound == nil {
		t.Fatal("expected outbound reassembly state to be created")
	}
	inbound := store.InboundReassembly(key, 2000)
	if inbound == nil {
		t.Fatal("expected inbound reassembly state to be created")
	}

	if outbound == inbound {
		t.Fatal("expected outbound and inbound reassembly states to be different instances")
	}
	if got := outbound.NextSeq(); got != 1000 {
		t.Fatalf("expected outbound next seq 1000, got %d", got)
	}
	if got := inbound.NextSeq(); got != 2000 {
		t.Fatalf("expected inbound next seq 2000, got %d", got)
	}
}

func TestStoreSeparatesOutboundAndInboundPendingMutationPoints(t *testing.T) {
	store := NewStore(func() time.Time { return time.Unix(100, 0) })
	key := testSessionKey()

	outboundPoint := reassembly.MutationPoint{TargetSeq: 2002}
	inboundPoint := reassembly.MutationPoint{TargetSeq: 3002}

	store.AddOutboundMutationPoint(key, outboundPoint)
	store.AddInboundMutationPoint(key, inboundPoint)

	outbound := store.OutboundPendingMutationPoints(key)
	if got := len(outbound); got != 1 {
		t.Fatalf("expected one outbound pending point, got %d", got)
	}
	if outbound[0] != outboundPoint {
		t.Fatalf("unexpected outbound pending point: %+v", outbound[0])
	}

	inbound := store.InboundPendingMutationPoints(key)
	if got := len(inbound); got != 1 {
		t.Fatalf("expected one inbound pending point, got %d", got)
	}
	if inbound[0] != inboundPoint {
		t.Fatalf("unexpected inbound pending point: %+v", inbound[0])
	}
}

func TestStoreInboundAckClearsOutboundPointsOnly(t *testing.T) {
	store := NewStore(func() time.Time { return time.Unix(100, 0) })
	key := testSessionKey()

	store.AddOutboundMutationPoint(key, reassembly.MutationPoint{TargetSeq: 2002})
	store.AddInboundMutationPoint(key, reassembly.MutationPoint{TargetSeq: 3002})

	store.AckOutboundUpTo(key, 2003)

	if got := len(store.OutboundPendingMutationPoints(key)); got != 0 {
		t.Fatalf("expected outbound pending points to be cleared, got %d", got)
	}
	if got := len(store.InboundPendingMutationPoints(key)); got != 1 {
		t.Fatalf("expected inbound pending point to remain, got %d", got)
	}
}

func TestStoreOutboundAckClearsInboundPointsOnly(t *testing.T) {
	store := NewStore(func() time.Time { return time.Unix(100, 0) })
	key := testSessionKey()

	store.AddOutboundMutationPoint(key, reassembly.MutationPoint{TargetSeq: 2002})
	store.AddInboundMutationPoint(key, reassembly.MutationPoint{TargetSeq: 3002})

	store.AckInboundUpTo(key, 3003)

	if got := len(store.OutboundPendingMutationPoints(key)); got != 1 {
		t.Fatalf("expected outbound pending point to remain, got %d", got)
	}
	if got := len(store.InboundPendingMutationPoints(key)); got != 0 {
		t.Fatalf("expected inbound pending points to be cleared, got %d", got)
	}
}

func TestStoreKeepsMutationPointWhenAckDoesNotCoverTargetSeq(t *testing.T) {
	store := NewStore(func() time.Time { return time.Unix(100, 0) })
	key := testSessionKey()

	store.AddMutationPoint(key, reassembly.MutationPoint{TargetSeq: 2002})
	store.AckUpTo(key, 2002)

	if got := len(store.PendingMutationPoints(key)); got != 1 {
		t.Fatalf("expected pending point to remain before full coverage, got %d", got)
	}
}

func TestStoreForgetClearsReassemblyAndMutationPoints(t *testing.T) {
	store := NewStore(func() time.Time { return time.Unix(100, 0) })
	key := testSessionKey()

	state := store.Reassembly(key, 1000)
	if state == nil {
		t.Fatal("expected reassembly state to be created")
	}
	store.AddMutationPoint(key, reassembly.MutationPoint{TargetSeq: 2002})

	store.Forget(key)

	if got := len(store.PendingMutationPoints(key)); got != 0 {
		t.Fatalf("expected no pending mutation points after forget, got %d", got)
	}

	fresh := store.Reassembly(key, 2000)
	if fresh == nil {
		t.Fatal("expected reassembly state to be recreated")
	}
	if got := fresh.NextSeq(); got != 2000 {
		t.Fatalf("expected forgotten reassembly state to be removed, got next seq %d", got)
	}
}

func TestStoreAckUpToUnknownKeyDoesNotCreateState(t *testing.T) {
	store := NewStore(func() time.Time { return time.Unix(100, 0) })
	key := testSessionKey()

	store.AckUpTo(key, 2003)
	store.AddMutationPoint(key, reassembly.MutationPoint{TargetSeq: 2002})

	if got := len(store.PendingMutationPoints(key)); got != 1 {
		t.Fatalf("expected unknown-key ACK not to suppress later mutation point, got %d", got)
	}
}

func TestStoreIgnoresMutationPointAfterAckAlreadyCoveredTargetSeqOnExistingEntry(t *testing.T) {
	store := NewStore(func() time.Time { return time.Unix(100, 0) })
	key := testSessionKey()

	store.MarkMatched(key)
	store.AckUpTo(key, 2003)
	store.AddMutationPoint(key, reassembly.MutationPoint{TargetSeq: 2002})

	if got := len(store.PendingMutationPoints(key)); got != 0 {
		t.Fatalf("expected covered mutation point to be ignored, got %d", got)
	}
}

func TestStoreHighAckThenLowAckDoesNotReopenPendingMutationPoint(t *testing.T) {
	store := NewStore(func() time.Time { return time.Unix(100, 0) })
	key := testSessionKey()

	store.AddMutationPoint(key, reassembly.MutationPoint{TargetSeq: 2002})
	store.AckUpTo(key, 2003)

	if got := len(store.PendingMutationPoints(key)); got != 0 {
		t.Fatalf("expected mutation point to be cleared by high ack, got %d", got)
	}

	store.AckUpTo(key, 2002)
	store.AddMutationPoint(key, reassembly.MutationPoint{TargetSeq: 2002})

	if got := len(store.PendingMutationPoints(key)); got != 0 {
		t.Fatalf("expected low ack not to reopen cleared state, got %d", got)
	}
}
