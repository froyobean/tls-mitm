package capture

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

func TestBuildFilters(t *testing.T) {
	cfg := config.Config{TargetIP: netip.MustParseAddr("93.184.216.34"), TargetPort: 443}
	outbound, inbound := BuildFilters(cfg)
	if !strings.Contains(outbound, "outbound") || !strings.Contains(inbound, "inbound") {
		t.Fatalf("unexpected filters: %s / %s", outbound, inbound)
	}
}

func TestBuildFiltersFallsBackToPortOnlyWithoutTargetIP(t *testing.T) {
	cfg := config.Config{TargetHost: "example.com", TargetPort: 443}
	outbound, inbound := BuildFilters(cfg)

	if strings.Contains(outbound, "ip.DstAddr == ") {
		t.Fatalf("expected outbound filter to fall back to port-only matching, got: %s", outbound)
	}
	if strings.Contains(inbound, "ip.SrcAddr == ") {
		t.Fatalf("expected inbound filter to fall back to port-only matching, got: %s", inbound)
	}
	if !strings.Contains(outbound, "tcp.DstPort == 443") || !strings.Contains(inbound, "tcp.SrcPort == 443") {
		t.Fatalf("unexpected port filters: %s / %s", outbound, inbound)
	}
}

func TestDynamicHostOnlyModeDoesNotBlockMismatchedConnection(t *testing.T) {
	cfg := config.Config{
		TargetHost:     "example.com",
		TargetPort:     443,
		ObserveTimeout: 50 * time.Millisecond,
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

	if err := runLoopWithHandles(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), observe, nil, nil, nil, factory); err != nil {
		t.Fatalf("runLoopWithHandles returned error: %v", err)
	}

	if factoryCalls != 0 {
		t.Fatalf("expected mismatched host not to create blocker handle, got %d", factoryCalls)
	}
	if len(observe.sent) != 0 {
		t.Fatalf("expected sniff observe handle not to reinject mismatched packets, got %d sends", len(observe.sent))
	}
}

func TestDynamicHostOnlyModeMutatesThroughDedicatedBlocker(t *testing.T) {
	cfg := config.Config{
		TargetHost:     "example.com",
		TargetPort:     443,
		ObserveTimeout: 50 * time.Millisecond,
		MutateOffset:   0,
	}

	hello := outboundClientHelloPacket("example.com")
	observe := &scriptedHandle{steps: []recvStep{
		{packet: hello},
	}}

	blocker := &scriptedHandle{steps: []recvStep{
		{packet: outboundTLSPacketWithSeq(uint32(len(hello) - 40))},
	}}
	factoryCalls := 0
	factory := func(key session.Key) (packetHandle, error) {
		factoryCalls++
		return blocker, nil
	}

	if err := runLoopWithHandles(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), observe, nil, nil, nil, factory); err != nil {
		t.Fatalf("runLoopWithHandles returned error: %v", err)
	}

	if factoryCalls != 1 {
		t.Fatalf("expected exactly one blocker handle for matched host, got %d", factoryCalls)
	}
	if len(observe.sent) != 0 {
		t.Fatalf("expected sniff observe handle not to reinject matched packets, got %d sends", len(observe.sent))
	}
	if len(blocker.sent) != 1 {
		t.Fatalf("expected blocker handle to reinject one mutated packet, got %d", len(blocker.sent))
	}
	if got := blocker.sent[0].packet[45]; got != 0x55 {
		t.Fatalf("expected dedicated blocker to mutate ciphertext byte to 0x55, got 0x%02x", got)
	}
}

func TestHostOnlyOutUsesRunHostMatchLoopWithHandles(t *testing.T) {
	cfg := config.Config{
		TargetHost:      "example.com",
		TargetPort:      443,
		ObserveTimeout:  100 * time.Millisecond,
		MutateOffset:    0,
		MutateDirection: "out",
	}

	hello := outboundClientHelloPacket("example.com")
	outObserve := &scriptedHandle{steps: []recvStep{
		{packet: hello},
	}}
	inObserve := &scriptedHandle{}
	blocker := &scriptedHandle{steps: []recvStep{
		{packet: outboundTLSPacketWithSeq(uint32(len(hello) - 40))},
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
		t.Fatalf("expected one outbound blocker, got %d", factoryCalls)
	}
	if len(outObserve.sent) != 0 {
		t.Fatalf("expected outbound sniff handle to remain observe-only, got %d sends", len(outObserve.sent))
	}
	if len(blocker.sent) != 1 {
		t.Fatalf("expected outbound blocker to reinject one packet, got %d", len(blocker.sent))
	}
	if got := blocker.sent[0].packet[45]; got != 0x55 {
		t.Fatalf("expected outbound blocker to mutate ciphertext byte to 0x55, got 0x%02x", got)
	}
}

func TestDynamicHostOnlyModeMutatesInboundThroughDedicatedBlocker(t *testing.T) {
	cfg := config.Config{
		TargetHost:      "example.com",
		TargetPort:      443,
		ObserveTimeout:  50 * time.Millisecond,
		MutateOffset:    0,
		MutateDirection: "in",
	}

	hello := outboundClientHelloPacket("example.com")
	outObserve := &scriptedHandle{steps: []recvStep{
		{packet: hello},
		{delay: 20 * time.Millisecond, packet: outboundFINPacketWithSeq(uint32(len(hello) - 40))},
	}}
	inObserve := &scriptedHandle{steps: []recvStep{
		{delay: 5 * time.Millisecond, packet: inboundApplicationDataPacketWithSeq(1000, []byte{0x17, 0x03, 0x03, 0x00, 0x04, 0xaa, 0xbb, 0xcc, 0xdd})},
	}}
	blocker := &scriptedHandle{steps: []recvStep{
		{delay: 5 * time.Millisecond, packet: inboundApplicationDataPacketWithSeq(1000, []byte{0x17, 0x03, 0x03, 0x00, 0x04, 0xaa, 0xbb, 0xcc, 0xdd})},
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
		t.Fatalf("expected exactly one inbound blocker handle for matched host, got %d", factoryCalls)
	}
	if len(outObserve.sent) != 0 {
		t.Fatalf("expected outbound observe handle not to reinject packets, got %d sends", len(outObserve.sent))
	}
	if len(inObserve.sent) != 0 {
		t.Fatalf("expected inbound observe handle to stay sniff-only, got %d sends", len(inObserve.sent))
	}
	if len(blocker.sent) != 1 {
		t.Fatalf("expected dedicated inbound blocker to reinject one packet, got %d", len(blocker.sent))
	}
	if got := blocker.sent[0].packet[45]; got != 0x55 {
		t.Fatalf("expected dedicated inbound blocker to mutate ciphertext byte to 0x55, got 0x%02x", got)
	}
}

func TestDynamicHostOnlyModeMutatesThroughBidirectionalBlocker(t *testing.T) {
	cfg := config.Config{
		TargetHost:      "example.com",
		TargetPort:      443,
		ObserveTimeout:  50 * time.Millisecond,
		MutateOffset:    0,
		MutateDirection: "both",
	}

	hello := outboundClientHelloPacket("example.com")
	outObserve := &scriptedHandle{steps: []recvStep{
		{packet: hello},
	}}
	inObserve := &scriptedHandle{}
	blocker := &scriptedHandle{steps: []recvStep{
		{packet: outboundTLSPacketWithSeq(uint32(len(hello) - 40))},
		{packet: inboundApplicationDataPacketWithSeq(1000, []byte{0x17, 0x03, 0x03, 0x00, 0x04, 0xaa, 0xbb, 0xcc, 0xdd})},
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
		t.Fatalf("expected one bidirectional blocker, got %d", factoryCalls)
	}
	if len(blocker.sent) != 2 {
		t.Fatalf("expected bidirectional blocker to reinject two packets, got %d", len(blocker.sent))
	}
	if got := blocker.sent[0].packet[45]; got != 0x55 {
		t.Fatalf("expected outbound packet to be mutated by bidirectional blocker, got 0x%02x", got)
	}
	if got := blocker.sent[1].packet[45]; got != 0x55 {
		t.Fatalf("expected inbound packet to be mutated by bidirectional blocker, got 0x%02x", got)
	}
}

func TestHostOnlyInboundBlockerHandlesTerminalPacketBeforeSniffCleanup(t *testing.T) {
	cfg := config.Config{
		TargetHost:      "example.com",
		TargetPort:      443,
		ObserveTimeout:  50 * time.Millisecond,
		MutateOffset:    0,
		MutateDirection: "in",
	}

	hello := outboundClientHelloPacket("example.com")
	outObserve := &scriptedHandle{steps: []recvStep{
		{packet: hello},
	}}
	terminalPacket := inboundFINApplicationDataPacketWithSeq(1000, []byte{0x17, 0x03, 0x03, 0x00, 0x04, 0xaa, 0xbb, 0xcc, 0xdd})
	inObserve := &scriptedHandle{steps: []recvStep{
		{delay: 5 * time.Millisecond, packet: terminalPacket},
	}}
	blocker := &scriptedHandle{steps: []recvStep{
		{packet: terminalPacket},
	}}
	factory := func(key session.Key) (packetHandle, error) {
		return blocker, nil
	}

	if err := runHostMatchLoopWithHandles(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), outObserve, inObserve, factory); err != nil {
		t.Fatalf("runHostMatchLoopWithHandles returned error: %v", err)
	}

	if len(inObserve.sent) != 0 {
		t.Fatalf("expected inbound sniff handle not to reinject terminal packet, got %d sends", len(inObserve.sent))
	}
	if len(blocker.sent) != 1 {
		t.Fatalf("expected inbound blocker to reinject terminal packet once, got %d sends", len(blocker.sent))
	}
	if got := blocker.sent[0].packet[45]; got != 0x55 {
		t.Fatalf("expected inbound blocker to mutate and reinject terminal packet, got 0x%02x", got)
	}
	if !blocker.IsClosed() {
		t.Fatal("expected inbound blocker to be cleaned up after terminal packet handling")
	}
}

func TestHostOnlyMatchedConnectionMutatesMultipleApplicationDataRounds(t *testing.T) {
	cfg := config.Config{
		TargetHost:      "example.com",
		TargetPort:      443,
		ObserveTimeout:  100 * time.Millisecond,
		MutateOffset:    0,
		MutateDirection: "out",
	}

	hello := outboundClientHelloPacket("example.com")
	firstSeq := uint32(len(hello) - 40)
	secondSeq := firstSeq + 9

	outObserve := &scriptedHandle{steps: []recvStep{{packet: hello}}}
	inObserve := &scriptedHandle{steps: []recvStep{{delay: 2 * time.Millisecond, packet: inboundFINPacket()}}}
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
	matches := regexp.MustCompile(`trace_id=t\d{6}`).FindAllString(logOutput, -1)
	if len(matches) < 2 || matches[0] != matches[1] {
		t.Fatalf("expected multiple rounds to reuse same trace id, got: %v", matches)
	}
}

func TestHostOnlyLifecycleTreatsFirstFINAsRoundEndUntilPeerAlsoCloses(t *testing.T) {
	state := &hostOnlyConnectionState{}

	lifecycle := advanceHostOnlyLifecycle(state, session.Signal{FIN: true}, session.Result{Outcome: session.OutcomeProbableFailure})
	if lifecycle != hostOnlyLifecycleRoundEnd {
		t.Fatalf("expected first FIN to end observation round only, got %v", lifecycle)
	}
	if !state.clientFINSeen || state.serverFINSeen {
		t.Fatalf("expected first FIN to mark only client half-close, got %+v", *state)
	}

	lifecycle = advanceHostOnlyLifecycle(state, session.Signal{FromServer: true, FIN: true}, session.Result{})
	if lifecycle != hostOnlyLifecycleConnectionEnd {
		t.Fatalf("expected peer FIN to end connection, got %v", lifecycle)
	}
}

func TestProcessHostOnlyInboundReturnsAlertResultWithoutDroppingConnectionState(t *testing.T) {
	cfg := config.Config{
		TargetHost:      "example.com",
		TargetPort:      443,
		ObserveTimeout:  20 * time.Millisecond,
		MutateOffset:    0,
		MutateDirection: "out",
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store := session.NewStore(func() time.Time { return time.Unix(100, 0) })
	key := session.Key{
		ClientIP:   "10.0.0.2",
		ClientPort: 50000,
		ServerIP:   "93.184.216.34",
		ServerPort: 443,
	}

	store.MarkMatched(key)
	store.MarkMutated(key, cfg.ObserveTimeout, 45)

	result, err := processHostOnlyInbound(logger, store, cfg, inboundTLSAlertPacketWithSeq(1000), nil, nil, "out")
	if err != nil {
		t.Fatalf("processHostOnlyInbound returned error: %v", err)
	}
	if !result.observed {
		t.Fatal("expected alert packet to produce an observation result")
	}
	if result.result.Outcome != session.OutcomeProbableFailure {
		t.Fatalf("expected alert packet to produce probable_failure, got %s", result.result.Outcome)
	}
	if !store.HasMutation(key) {
		t.Fatal("expected host-only inbound alert processing not to forget connection state")
	}
}

func TestHostOnlyMatchedConnectionMutatesAgainAfterAlertRoundWithSameTraceID(t *testing.T) {
	cfg := config.Config{
		TargetHost:      "example.com",
		TargetPort:      443,
		ObserveTimeout:  50 * time.Millisecond,
		MutateOffset:    0,
		MutateDirection: "out",
	}

	hello := outboundClientHelloPacket("example.com")
	firstSeq := uint32(len(hello) - 40)
	secondSeq := firstSeq + 9

	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	outObserve := &scriptedHandle{steps: []recvStep{{packet: hello}}}
	inObserve := &scriptedHandle{steps: []recvStep{
		{delay: 25 * time.Millisecond, packet: inboundTLSAlertPacketWithSeq(1000)},
	}}
	blocker := &scriptedHandle{steps: []recvStep{
		{packet: outboundTLSPacketWithSeq(firstSeq)},
		{delay: 130 * time.Millisecond, packet: outboundTLSPacketWithSeq(secondSeq)},
	}}
	factory := func(key session.Key) (packetHandle, error) { return blocker, nil }

	if err := runHostMatchLoopWithHandles(context.Background(), cfg, logger, outObserve, inObserve, factory); err != nil {
		t.Fatalf("runHostMatchLoopWithHandles returned error: %v", err)
	}

	if len(blocker.sent) != 2 {
		t.Fatalf("expected blocker to mutate both rounds after alert, got %d sends", len(blocker.sent))
	}
	if got := blocker.sent[0].packet[45]; got != 0x55 {
		t.Fatalf("expected first application data packet to be mutated, got 0x%02x", got)
	}
	if got := blocker.sent[1].packet[45]; got != 0x55 {
		t.Fatalf("expected second application data packet to be mutated, got 0x%02x", got)
	}

	logOutput := logs.String()
	if !strings.Contains(logOutput, "reason=alert") {
		t.Fatalf("expected first round to be logged as alert result, got: %s", logOutput)
	}
	if !strings.Contains(logOutput, "reason=timeout") {
		t.Fatalf("expected later round to end by timeout, got: %s", logOutput)
	}
	resultMatches := regexp.MustCompile(`msg=连接观察结果[^\n]*trace_id=(t\d{6})`).FindAllStringSubmatch(logOutput, -1)
	if len(resultMatches) < 2 || resultMatches[0][1] != resultMatches[1][1] {
		t.Fatalf("expected alert round and later round to reuse same trace id, got: %v", resultMatches)
	}
}

func TestHostOnlyTerminalCleanupClosesBlockerAndReleasesConnectionState(t *testing.T) {
	cfg := config.Config{
		TargetHost:      "example.com",
		TargetPort:      443,
		ObserveTimeout:  20 * time.Millisecond,
		MutateOffset:    0,
		MutateDirection: "out",
	}

	hello := outboundClientHelloPacket("example.com")
	firstSeq := uint32(len(hello) - 40)
	secondSeq := firstSeq + 9

	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	outObserve := &scriptedHandle{steps: []recvStep{
		{packet: hello},
		{delay: 150 * time.Millisecond, packet: hello},
	}}
	inObserve := &scriptedHandle{steps: []recvStep{
		{delay: 25 * time.Millisecond, packet: inboundTLSAlertPacketWithSeq(1000)},
		{delay: 55 * time.Millisecond, packet: inboundRSTPacket()},
	}}
	blockerOne := &scriptedHandle{steps: []recvStep{
		{packet: outboundTLSPacketWithSeq(firstSeq)},
		{delay: 60 * time.Millisecond, packet: outboundTLSPacketWithSeq(secondSeq)},
	}}
	blockerTwo := &scriptedHandle{steps: []recvStep{
		{packet: outboundTLSPacketWithSeq(firstSeq)},
	}}
	blockers := []*scriptedHandle{blockerOne, blockerTwo}
	factoryCalls := 0
	factory := func(key session.Key) (packetHandle, error) {
		handle := blockers[factoryCalls]
		factoryCalls++
		return handle, nil
	}

	if err := runHostMatchLoopWithHandles(context.Background(), cfg, logger, outObserve, inObserve, factory); err != nil {
		t.Fatalf("runHostMatchLoopWithHandles returned error: %v", err)
	}

	if factoryCalls != 2 {
		t.Fatalf("expected terminal cleanup to allow same tuple to create a second blocker, got %d calls", factoryCalls)
	}
	if !blockerOne.IsClosed() {
		t.Fatal("expected first blocker to be closed after terminal cleanup")
	}
	if len(blockerOne.sent) != 2 {
		t.Fatalf("expected first blocker to forward both pre-terminal rounds, got %d sends", len(blockerOne.sent))
	}
	if len(blockerTwo.sent) != 1 {
		t.Fatalf("expected released connection state to allow a new blocker, got %d sends", len(blockerTwo.sent))
	}
	if got := blockerTwo.sent[0].packet[45]; got != 0x55 {
		t.Fatalf("expected second blocker to mutate new connection packet, got 0x%02x", got)
	}

	matchLogs := regexp.MustCompile(`msg="SNI 命中目标域名"[^\n]*trace_id=(t\d{6})`).FindAllStringSubmatch(logs.String(), -1)
	if len(matchLogs) < 2 || matchLogs[0][1] == matchLogs[1][1] {
		t.Fatalf("expected terminal cleanup to release state and allocate a new trace id, got: %v", matchLogs)
	}
}

func TestHostOnlyRetainsConnectionAfterLongTimeoutSilence(t *testing.T) {
	cfg := config.Config{
		TargetHost:      "example.com",
		TargetPort:      443,
		ObserveTimeout:  5 * time.Millisecond,
		MutateOffset:    0,
		MutateDirection: "out",
	}

	hello := outboundClientHelloPacket("example.com")
	firstSeq := uint32(len(hello) - 40)
	secondSeq := firstSeq + 9
	outObserve := &scriptedHandle{steps: []recvStep{{packet: hello}}}
	inObserve := &scriptedHandle{}
	blocker := &scriptedHandle{steps: []recvStep{
		{packet: outboundTLSPacketWithSeq(firstSeq)},
		{delay: 40 * time.Millisecond, packet: outboundTLSPacketWithSeq(secondSeq)},
	}}
	factory := func(key session.Key) (packetHandle, error) { return blocker, nil }

	if err := runHostMatchLoopWithHandles(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), outObserve, inObserve, factory); err != nil {
		t.Fatalf("runHostMatchLoopWithHandles returned error: %v", err)
	}

	if len(blocker.sent) != 2 {
		t.Fatalf("expected long-idle live connection to keep mutating later application data, got %d sends", len(blocker.sent))
	}
	if got := blocker.sent[1].packet[45]; got != 0x55 {
		t.Fatalf("expected second application data packet after long idle to be mutated, got 0x%02x", got)
	}
}

func TestHostOnlyRetainsConnectionAfterLongAlertSilence(t *testing.T) {
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
	outObserve := &scriptedHandle{steps: []recvStep{{packet: hello}}}
	inObserve := &scriptedHandle{steps: []recvStep{{delay: 5 * time.Millisecond, packet: inboundTLSAlertPacketWithSeq(1000)}}}
	blocker := &scriptedHandle{steps: []recvStep{
		{packet: outboundTLSPacketWithSeq(firstSeq)},
		{delay: 70 * time.Millisecond, packet: outboundTLSPacketWithSeq(secondSeq)},
	}}
	factory := func(key session.Key) (packetHandle, error) { return blocker, nil }

	if err := runHostMatchLoopWithHandles(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), outObserve, inObserve, factory); err != nil {
		t.Fatalf("runHostMatchLoopWithHandles returned error: %v", err)
	}

	if len(blocker.sent) != 2 {
		t.Fatalf("expected alert-observed live connection to keep mutating later application data, got %d sends", len(blocker.sent))
	}
	if got := blocker.sent[1].packet[45]; got != 0x55 {
		t.Fatalf("expected second application data packet after alert silence to be mutated, got 0x%02x", got)
	}
}

func TestHostOnlyHalfCloseCleanupClosesBlockerAfterSingleFINSilence(t *testing.T) {
	cfg := config.Config{
		TargetHost:      "example.com",
		TargetPort:      443,
		ObserveTimeout:  10 * time.Millisecond,
		MutateOffset:    0,
		MutateDirection: "out",
	}

	hello := outboundClientHelloPacket("example.com")
	firstSeq := uint32(len(hello) - 40)
	outObserve := &scriptedHandle{steps: []recvStep{{packet: hello}}}
	inObserve := &scriptedHandle{}
	blocker := &scriptedHandle{steps: []recvStep{
		{packet: outboundTLSPacketWithSeq(firstSeq)},
		{delay: 5 * time.Millisecond, packet: outboundFINPacketWithSeq(firstSeq + 9)},
		{blockUntilClose: true},
	}}
	factory := func(key session.Key) (packetHandle, error) { return blocker, nil }

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	if err := runHostMatchLoopWithHandles(ctx, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), outObserve, inObserve, factory); err != nil {
		t.Fatalf("runHostMatchLoopWithHandles returned error: %v", err)
	}

	if !blocker.IsClosed() {
		t.Fatal("expected half-close cleanup to close blocker after single FIN goes silent")
	}
}

func TestHostOnlyHalfCloseTrafficRefreshesCleanupDeadline(t *testing.T) {
	cfg := config.Config{
		TargetHost:      "example.com",
		TargetPort:      443,
		ObserveTimeout:  10 * time.Millisecond,
		MutateOffset:    0,
		MutateDirection: "in",
	}

	hello := outboundClientHelloPacket("example.com")
	firstSeq := uint32(len(hello) - 40)
	outObserve := &scriptedHandle{steps: []recvStep{
		{packet: hello},
		{delay: 5 * time.Millisecond, packet: outboundFINPacketWithSeq(firstSeq)},
	}}
	inObserve := &scriptedHandle{}
	blocker := &scriptedHandle{steps: []recvStep{
		{delay: 20 * time.Millisecond, packet: inboundPlainPacketWithSeq(1000)},
		{delay: 40 * time.Millisecond, packet: inboundPlainPacketWithSeq(1000)},
		{delay: 40 * time.Millisecond, packet: inboundApplicationDataPacketWithSeq(1000, []byte{0x17, 0x03, 0x03, 0x00, 0x04, 0xaa, 0xbb, 0xcc, 0xdd})},
	}}
	factory := func(key session.Key) (packetHandle, error) { return blocker, nil }

	if err := runHostMatchLoopWithHandles(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), outObserve, inObserve, factory); err != nil {
		t.Fatalf("runHostMatchLoopWithHandles returned error: %v", err)
	}

	if len(blocker.sent) != 3 {
		t.Fatalf("expected half-closed connection traffic to keep blocker alive, got %d sends", len(blocker.sent))
	}
	if got := blocker.sent[2].packet[45]; got != 0x55 {
		t.Fatalf("expected inbound application data after half-close activity to be mutated, got 0x%02x", got)
	}
}

func TestLoopStillMutatesSinglePacketApplicationData(t *testing.T) {
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
	if got := out.sent[0].packet[45]; got != 0x55 {
		t.Fatalf("expected mutated ciphertext byte 0x55, got 0x%02x", got)
	}
}

func TestLoopStillMutatesSinglePacketApplicationDataWithMutateOffset(t *testing.T) {
	cfg := config.Config{
		TargetIP:       netip.MustParseAddr("93.184.216.34"),
		TargetPort:     443,
		ObserveTimeout: 5 * time.Second,
		MutateOffset:   2,
	}
	out := &fakeHandle{recv: []packetWithAddr{{packet: outboundTLSPacket()}}}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	if err := RunLoop(context.Background(), cfg, logger, out, nil); err != nil {
		t.Fatalf("RunLoop returned error: %v", err)
	}
	if len(out.sent) != 1 {
		t.Fatalf("expected one outbound mutated send, got %d", len(out.sent))
	}
	if got := out.sent[0].packet[47]; got != 0x33 {
		t.Fatalf("expected mutate-offset 2 to flip third ciphertext byte to 0x33, got 0x%02x", got)
	}
}

func TestLoopMatchesTargetHostBeforeMutation(t *testing.T) {
	cfg := config.Config{
		TargetHost:     "example.com",
		TargetPort:     443,
		ObserveTimeout: 50 * time.Millisecond,
		MutateOffset:   0,
	}

	hello := outboundClientHelloPacketToWithSeq("93.184.216.34", 0, "example.com")
	out := &scriptedHandle{steps: []recvStep{
		{packet: hello},
		{packet: outboundTLSPacketWithSeq(uint32(len(hello) - 40))},
	}}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	if err := RunLoop(context.Background(), cfg, logger, out, nil); err != nil {
		t.Fatalf("RunLoop returned error: %v", err)
	}

	if len(out.sent) != 2 {
		t.Fatalf("expected two outbound sends, got %d", len(out.sent))
	}
	if got := out.sent[1].packet[45]; got != 0x55 {
		t.Fatalf("expected mutated ciphertext byte 0x55 after host match, got 0x%02x", got)
	}
}

func TestLoopLogsHostMatchBeforeMutation(t *testing.T) {
	cfg := config.Config{
		TargetHost:     "example.com",
		TargetPort:     443,
		ObserveTimeout: 50 * time.Millisecond,
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
	if !regexp.MustCompile(`trace_id=t\d{6}`).MatchString(logOutput) {
		t.Fatalf("expected exclusion log to include trace_id, got: %s", logOutput)
	}
}

func TestLoopLogsHostExclusionWhenSNIMismatches(t *testing.T) {
	cfg := config.Config{
		TargetHost:     "example.com",
		TargetPort:     443,
		ObserveTimeout: 50 * time.Millisecond,
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
	if !strings.Contains(logOutput, "observed_host=other.example") {
		t.Fatalf("expected exclusion log to include observed_host, got: %s", logOutput)
	}
}

func TestRunLoopReturnsOnContextCancelWithoutBlocking(t *testing.T) {
	cfg := config.Config{
		TargetIP:       netip.MustParseAddr("93.184.216.34"),
		TargetPort:     443,
		ObserveTimeout: time.Second,
		MutateOffset:   0,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	out := &scriptedHandle{steps: []recvStep{
		{packet: outboundTLSPacket()},
		{blockUntilClose: true},
	}}
	in := &scriptedHandle{steps: []recvStep{{blockUntilClose: true}}}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	errCh := make(chan error, 1)
	go func() {
		errCh <- RunLoop(ctx, cfg, logger, out, in)
	}()

	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context cancellation, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("RunLoop did not exit after context cancellation")
	}

	if !out.IsClosed() || !in.IsClosed() {
		t.Fatalf("expected handles to be closed on cancellation: out=%v in=%v", out.IsClosed(), in.IsClosed())
	}
}

func TestLoopWaitsForPendingTimeoutAfterHandlesEOF(t *testing.T) {
	cfg := config.Config{
		TargetIP:       netip.MustParseAddr("93.184.216.34"),
		TargetPort:     443,
		ObserveTimeout: 10 * time.Millisecond,
		MutateOffset:   0,
	}

	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	out := &scriptedHandle{steps: []recvStep{{packet: outboundTLSPacket()}}}
	in := &scriptedHandle{}

	if err := RunLoop(context.Background(), cfg, logger, out, in); err != nil {
		t.Fatalf("RunLoop returned error: %v", err)
	}

	if !strings.Contains(logs.String(), "outcome=no_conclusion") {
		t.Fatalf("expected no_conclusion after pending timeout, got: %s", logs.String())
	}
}

func TestTimeoutStaysNoConclusionAfterLaterInboundRST(t *testing.T) {
	cfg := config.Config{
		TargetIP:       netip.MustParseAddr("93.184.216.34"),
		TargetPort:     443,
		ObserveTimeout: 10 * time.Millisecond,
		MutateOffset:   0,
	}

	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	out := &scriptedHandle{steps: []recvStep{{packet: outboundTLSPacket()}}}
	in := &scriptedHandle{steps: []recvStep{
		{delay: 30 * time.Millisecond, packet: inboundRSTPacket()},
	}}

	if err := RunLoop(context.Background(), cfg, logger, out, in); err != nil {
		t.Fatalf("RunLoop returned error: %v", err)
	}

	logOutput := logs.String()
	if !strings.Contains(logOutput, "outcome=no_conclusion") {
		t.Fatalf("expected timeout no_conclusion log, got: %s", logOutput)
	}
	if strings.Contains(logOutput, "outcome=probable_failure") || strings.Contains(logOutput, "outcome=definite_failure") {
		t.Fatalf("timeout result should not be reclassified by later inbound RST, logs: %s", logOutput)
	}
}

func TestLoopLogsMatchedConnectionWaitingForMutationPoint(t *testing.T) {
	cfg := config.Config{
		TargetHost:     "example.com",
		TargetPort:     443,
		ObserveTimeout: 50 * time.Millisecond,
		MutateOffset:   0,
	}

	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	hello := outboundClientHelloPacketToWithSeq("93.184.216.34", 0, "example.com")
	out := &scriptedHandle{steps: []recvStep{
		{packet: hello},
		{packet: outboundApplicationDataFragmentWithSeq(uint32(len(hello)-40), []byte{0x17, 0x03, 0x03, 0x00, 0x04})},
		{packet: outboundApplicationDataFragmentWithSeq(uint32(len(hello)-35), []byte{0xaa, 0xbb, 0xcc, 0xdd})},
	}}

	if err := RunLoop(context.Background(), cfg, logger, out, nil); err != nil {
		t.Fatalf("RunLoop returned error: %v", err)
	}

	logOutput := logs.String()
	if !strings.Contains(logOutput, "目标连接已命中，但当前包尚未覆盖破坏点") {
		t.Fatalf("expected matched host flow to log waiting-for-mutation-point, got: %s", logOutput)
	}
	if !strings.Contains(logOutput, "target_host=example.com") {
		t.Fatalf("expected waiting log to include target_host, got: %s", logOutput)
	}
}

func TestLoopMutatesCrossPacketApplicationDataAfterReassemblyWithMutateOffset(t *testing.T) {
	cfg := config.Config{
		TargetIP:       netip.MustParseAddr("93.184.216.34"),
		TargetPort:     443,
		ObserveTimeout: 50 * time.Millisecond,
		MutateOffset:   2,
	}

	out := &scriptedHandle{steps: []recvStep{
		{packet: outboundApplicationDataFragmentWithSeq(1000, []byte{0x17, 0x03, 0x03, 0x00, 0x04, 0xaa, 0xbb})},
		{delay: 10 * time.Millisecond, packet: outboundApplicationDataFragmentWithSeq(1007, []byte{0xcc, 0xdd})},
	}}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	if err := RunLoop(context.Background(), cfg, logger, out, nil); err != nil {
		t.Fatalf("RunLoop returned error: %v", err)
	}

	if len(out.sent) != 2 {
		t.Fatalf("expected two outbound sends, got %d", len(out.sent))
	}
	if !bytes.Equal(out.sent[0].packet, outboundApplicationDataFragmentWithSeq(1000, []byte{0x17, 0x03, 0x03, 0x00, 0x04, 0xaa, 0xbb})) {
		t.Fatalf("expected first packet to stay unchanged before reassembly, got %x", out.sent[0].packet)
	}
	if got := out.sent[1].packet[40]; got != 0x33 {
		t.Fatalf("expected mutate-offset 2 to hit the first byte of second fragment, got 0x%02x", got)
	}
}

func TestLoopReappliesMutationOnRetransmission(t *testing.T) {
	cfg := config.Config{
		TargetIP:       netip.MustParseAddr("93.184.216.34"),
		TargetPort:     443,
		ObserveTimeout: 50 * time.Millisecond,
		MutateOffset:   0,
	}

	out := &scriptedHandle{steps: []recvStep{
		{packet: outboundApplicationDataFragmentWithSeq(1000, []byte{0x17, 0x03, 0x03, 0x00, 0x04})},
		{packet: outboundApplicationDataFragmentWithSeq(1005, []byte{0xaa, 0xbb, 0xcc, 0xdd})},
		{delay: 10 * time.Millisecond, packet: outboundApplicationDataFragmentWithSeq(1005, []byte{0xaa, 0xbb, 0xcc, 0xdd})},
	}}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	if err := RunLoop(context.Background(), cfg, logger, out, nil); err != nil {
		t.Fatalf("RunLoop returned error: %v", err)
	}

	if len(out.sent) != 3 {
		t.Fatalf("expected three outbound sends, got %d", len(out.sent))
	}
	if !bytes.Equal(out.sent[0].packet, outboundApplicationDataFragmentWithSeq(1000, []byte{0x17, 0x03, 0x03, 0x00, 0x04})) {
		t.Fatalf("expected first fragment to stay unchanged before record completion, got %x", out.sent[0].packet)
	}
	if got := out.sent[1].packet[40]; got != 0x55 {
		t.Fatalf("expected first tail fragment to be mutated, got 0x%02x", got)
	}
	if got := out.sent[2].packet[40]; got != 0x55 {
		t.Fatalf("expected retransmitted tail fragment to receive the same mutation, got 0x%02x", got)
	}
}

func TestLoopReappliesMutationOnRetransmissionWithMutateOffset(t *testing.T) {
	cfg := config.Config{
		TargetIP:       netip.MustParseAddr("93.184.216.34"),
		TargetPort:     443,
		ObserveTimeout: 50 * time.Millisecond,
		MutateOffset:   2,
	}

	out := &scriptedHandle{steps: []recvStep{
		{packet: outboundApplicationDataFragmentWithSeq(1000, []byte{0x17, 0x03, 0x03, 0x00, 0x04, 0xaa, 0xbb})},
		{packet: outboundApplicationDataFragmentWithSeq(1007, []byte{0xcc, 0xdd})},
		{delay: 10 * time.Millisecond, packet: outboundApplicationDataFragmentWithSeq(1007, []byte{0xcc, 0xdd})},
	}}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	if err := RunLoop(context.Background(), cfg, logger, out, nil); err != nil {
		t.Fatalf("RunLoop returned error: %v", err)
	}

	if len(out.sent) != 3 {
		t.Fatalf("expected three outbound sends, got %d", len(out.sent))
	}
	if got := out.sent[1].packet[40]; got != 0x33 {
		t.Fatalf("expected first send of target fragment to honor mutate-offset 2, got 0x%02x", got)
	}
	if got := out.sent[2].packet[40]; got != 0x33 {
		t.Fatalf("expected retransmission to keep same mutate-offset 2 mutation, got 0x%02x", got)
	}
}

func TestProcessOutboundReturnsMutatedForRetransmittedTailFragment(t *testing.T) {
	cfg := config.Config{
		TargetIP:       netip.MustParseAddr("93.184.216.34"),
		TargetPort:     443,
		ObserveTimeout: 40 * time.Millisecond,
		MutateOffset:   0,
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store := session.NewStore(time.Now)
	handle := &fakeHandle{}

	firstPacket := outboundApplicationDataFragmentWithSeq(1000, []byte{0x17, 0x03, 0x03, 0x00, 0x04})
	key, mutated, cleanup, err := processOutbound(cfg, logger, store, handle, firstPacket, nil)
	if err != nil {
		t.Fatalf("first fragment returned error: %v", err)
	}
	if mutated {
		t.Fatal("expected first fragment not to mutate before record completion")
	}
	if cleanup {
		t.Fatal("expected first fragment not to trigger cleanup")
	}

	firstTail := outboundApplicationDataFragmentWithSeq(1005, []byte{0xaa, 0xbb, 0xcc, 0xdd})
	tailKey, tailMutated, cleanup, err := processOutbound(cfg, logger, store, handle, firstTail, nil)
	if err != nil {
		t.Fatalf("first tail fragment returned error: %v", err)
	}
	if key != tailKey {
		t.Fatalf("expected same session key across fragments: first=%+v tail=%+v", key, tailKey)
	}
	if !tailMutated {
		t.Fatal("expected first tail fragment to report mutated=true")
	}
	if cleanup {
		t.Fatal("expected first tail fragment not to trigger cleanup")
	}

	retransmittedTail := outboundApplicationDataFragmentWithSeq(1005, []byte{0xaa, 0xbb, 0xcc, 0xdd})
	retransmitKey, retransmitMutated, cleanup, err := processOutbound(cfg, logger, store, handle, retransmittedTail, nil)
	if err != nil {
		t.Fatalf("retransmitted tail fragment returned error: %v", err)
	}
	if key != retransmitKey {
		t.Fatalf("expected same session key across retransmission: first=%+v retransmit=%+v", key, retransmitKey)
	}
	if !retransmitMutated {
		t.Fatal("expected retransmitted tail fragment to report mutated=true")
	}
	if cleanup {
		t.Fatal("expected retransmitted tail fragment not to trigger cleanup")
	}

	if len(handle.sent) != 3 {
		t.Fatalf("expected three outbound sends, got %d", len(handle.sent))
	}
	if got := handle.sent[1].packet[40]; got != 0x55 {
		t.Fatalf("expected first tail fragment send to be mutated, got 0x%02x", got)
	}
	if got := handle.sent[2].packet[40]; got != 0x55 {
		t.Fatalf("expected retransmitted tail fragment send to be mutated, got 0x%02x", got)
	}
}

func TestLoopRepeatedMutationRefreshesInternalObserveWindow(t *testing.T) {
	cfg := config.Config{
		TargetIP:       netip.MustParseAddr("93.184.216.34"),
		TargetPort:     443,
		ObserveTimeout: 40 * time.Millisecond,
		MutateOffset:   0,
	}

	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	packet := outboundTLSPacketWithSeq(1000)
	out := &scriptedHandle{steps: []recvStep{
		{packet: packet},
		{delay: 30 * time.Millisecond, packet: packet},
	}}
	in := &scriptedHandle{steps: []recvStep{
		{delay: 55 * time.Millisecond, packet: inboundRSTPacket()},
	}}

	if err := RunLoop(context.Background(), cfg, logger, out, in); err != nil {
		t.Fatalf("RunLoop returned error: %v", err)
	}

	logOutput := logs.String()
	if !strings.Contains(logOutput, "outcome=definite_failure") {
		t.Fatalf("expected second mutation to refresh internal observe window before inbound RST, got: %s", logOutput)
	}
	if strings.Contains(logOutput, "outcome=no_conclusion") {
		t.Fatalf("expected refreshed internal observe window to avoid early no_conclusion, logs: %s", logOutput)
	}
	if got := strings.Count(logOutput, "first_observation="); got < 2 {
		t.Fatalf("expected each actually mutated packet to be logged, got %d logs: %s", got, logOutput)
	}
}

func TestLoopRespectsMutateDirectionOutOnly(t *testing.T) {
	cfg := config.Config{
		TargetIP:        netip.MustParseAddr("93.184.216.34"),
		TargetPort:      443,
		ObserveTimeout:  50 * time.Millisecond,
		MutateOffset:    0,
		MutateDirection: "out",
	}

	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	out := &scriptedHandle{steps: []recvStep{
		{packet: outboundTLSPacket()},
	}}
	in := &scriptedHandle{steps: []recvStep{
		{packet: inboundApplicationDataPacketWithSeq(1000, []byte{0x17, 0x03, 0x03, 0x00, 0x04, 0xaa, 0xbb, 0xcc, 0xdd})},
	}}

	if err := RunDirectLoop(context.Background(), cfg, logger, nil, out, in, nil); err != nil {
		t.Fatalf("RunLoop returned error: %v", err)
	}

	if len(out.sent) != 1 {
		t.Fatalf("expected one outbound send, got %d", len(out.sent))
	}
	if got := out.sent[0].packet[45]; got != 0x55 {
		t.Fatalf("expected outbound packet to be mutated, got 0x%02x", got)
	}
	if len(in.sent) != 0 {
		t.Fatalf("expected inbound packet to stay unmodified in out-only mode, got %d sends", len(in.sent))
	}
}

func TestLoopRespectsMutateDirectionInOnly(t *testing.T) {
	cfg := config.Config{
		TargetIP:        netip.MustParseAddr("93.184.216.34"),
		TargetPort:      443,
		ObserveTimeout:  50 * time.Millisecond,
		MutateOffset:    0,
		MutateDirection: "in",
	}

	out := &scriptedHandle{steps: []recvStep{
		{packet: outboundTLSPacket()},
	}}
	in := &scriptedHandle{steps: []recvStep{
		{packet: inboundApplicationDataPacketWithSeq(1000, []byte{0x17, 0x03, 0x03, 0x00, 0x04, 0xaa, 0xbb, 0xcc, 0xdd})},
	}}

	if err := RunDirectLoop(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), out, nil, nil, in); err != nil {
		t.Fatalf("RunLoop returned error: %v", err)
	}

	if len(out.sent) != 0 {
		t.Fatalf("expected outbound observe handle not to reinject packets in in-only mode, got %d sends", len(out.sent))
	}
	if len(in.sent) != 1 {
		t.Fatalf("expected one inbound reinjected packet, got %d", len(in.sent))
	}
	if got := in.sent[0].packet[45]; got != 0x55 {
		t.Fatalf("expected inbound packet to be mutated, got 0x%02x", got)
	}
}

func TestLoopReinjectsInboundMutationWithOriginalAddr(t *testing.T) {
	cfg := config.Config{
		TargetIP:        netip.MustParseAddr("93.184.216.34"),
		TargetPort:      443,
		ObserveTimeout:  50 * time.Millisecond,
		MutateOffset:    0,
		MutateDirection: "in",
	}

	addrToken := &struct{ name string }{name: "divert-address"}
	out := &scriptedHandle{steps: []recvStep{
		{packet: outboundTLSPacket()},
	}}
	in := &strictAddrHandle{
		expectedSendAddr: addrToken,
		recv: []packetWithAddr{
			{packet: inboundApplicationDataPacketWithSeq(1000, []byte{0x17, 0x03, 0x03, 0x00, 0x04, 0xaa, 0xbb, 0xcc, 0xdd}), addr: addrToken},
		},
	}

	if err := RunDirectLoop(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), out, nil, nil, in); err != nil {
		t.Fatalf("RunLoop returned error: %v", err)
	}

	if len(out.sent) != 0 {
		t.Fatalf("expected outbound observe handle not to reinject packets, got %d sends", len(out.sent))
	}
	if len(in.sent) != 1 {
		t.Fatalf("expected one inbound reinjected packet, got %d", len(in.sent))
	}
	if in.sent[0].addr != addrToken {
		t.Fatalf("expected reinjected inbound packet to preserve original addr pointer")
	}
}

func TestLoopMutateDirectionInWaitsForTimeoutAfterInboundMutationEOF(t *testing.T) {
	cfg := config.Config{
		TargetIP:        netip.MustParseAddr("93.184.216.34"),
		TargetPort:      443,
		ObserveTimeout:  10 * time.Millisecond,
		MutateOffset:    0,
		MutateDirection: "in",
	}

	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	out := &scriptedHandle{steps: []recvStep{
		{packet: outboundTLSPacket()},
	}}
	in := &scriptedHandle{steps: []recvStep{
		{packet: inboundApplicationDataPacketWithSeq(1000, []byte{0x17, 0x03, 0x03, 0x00, 0x04, 0xaa, 0xbb, 0xcc, 0xdd})},
	}}

	if err := RunDirectLoop(context.Background(), cfg, logger, out, nil, nil, in); err != nil {
		t.Fatalf("RunLoop returned error: %v", err)
	}

	logOutput := logs.String()
	if !strings.Contains(logOutput, "direction=in") {
		t.Fatalf("expected timeout/result log to keep direction=in, got: %s", logOutput)
	}
	if !strings.Contains(logOutput, "reason=timeout") {
		t.Fatalf("expected inbound-only mutation to wait for timeout after EOF, got: %s", logOutput)
	}
	if !strings.Contains(logOutput, "outcome=no_conclusion") {
		t.Fatalf("expected inbound-only mutation to produce no_conclusion on timeout, got: %s", logOutput)
	}
}

func TestLoopMutateDirectionInKeepsInboundDirectionWhenFirstMutationEndsConnection(t *testing.T) {
	cfg := config.Config{
		TargetIP:        netip.MustParseAddr("93.184.216.34"),
		TargetPort:      443,
		ObserveTimeout:  50 * time.Millisecond,
		MutateOffset:    0,
		MutateDirection: "in",
	}

	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	in := &scriptedHandle{steps: []recvStep{
		{packet: inboundFINApplicationDataPacketWithSeq(1000, []byte{0x17, 0x03, 0x03, 0x00, 0x04, 0xaa, 0xbb, 0xcc, 0xdd})},
	}}

	if err := RunDirectLoop(context.Background(), cfg, logger, nil, nil, nil, in); err != nil {
		t.Fatalf("RunLoop returned error: %v", err)
	}

	logOutput := logs.String()
	if !strings.Contains(logOutput, "msg=连接观察结果 direction=in") {
		t.Fatalf("expected result log to keep direction=in when first inbound mutation ends connection, got: %s", logOutput)
	}
	if strings.Contains(logOutput, "msg=连接观察结果 direction=out") {
		t.Fatalf("expected result log not to fall back to direction=out for first inbound terminal mutation, got: %s", logOutput)
	}
}

func TestLoopRespectsMutateDirectionBoth(t *testing.T) {
	cfg := config.Config{
		TargetIP:        netip.MustParseAddr("93.184.216.34"),
		TargetPort:      443,
		ObserveTimeout:  50 * time.Millisecond,
		MutateOffset:    0,
		MutateDirection: "both",
	}

	out := &scriptedHandle{steps: []recvStep{
		{packet: outboundTLSPacket()},
	}}
	in := &scriptedHandle{steps: []recvStep{
		{packet: inboundApplicationDataPacketWithSeq(1000, []byte{0x17, 0x03, 0x03, 0x00, 0x04, 0xaa, 0xbb, 0xcc, 0xdd})},
	}}

	if err := RunDirectLoop(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), nil, out, nil, in); err != nil {
		t.Fatalf("RunLoop returned error: %v", err)
	}

	if len(out.sent) != 1 {
		t.Fatalf("expected one outbound send, got %d", len(out.sent))
	}
	if got := out.sent[0].packet[45]; got != 0x55 {
		t.Fatalf("expected outbound packet to be mutated in both mode, got 0x%02x", got)
	}
	if len(in.sent) != 1 {
		t.Fatalf("expected one inbound reinjected packet, got %d", len(in.sent))
	}
	if got := in.sent[0].packet[45]; got != 0x55 {
		t.Fatalf("expected inbound packet to be mutated in both mode, got 0x%02x", got)
	}
}

func TestProcessInboundBlockerForwardsPureACK(t *testing.T) {
	cfg := config.Config{
		TargetIP:        netip.MustParseAddr("93.184.216.34"),
		TargetPort:      443,
		ObserveTimeout:  50 * time.Millisecond,
		MutateDirection: "in",
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store := session.NewStore(time.Now)
	reported := make(map[session.Key]struct{})
	handle := &fakeHandle{}

	key, result, observed, mutated, cleanup, err := processInbound(logger, store, reported, cfg, inboundAckPacket(1003), nil, handle, "in")
	if err != nil {
		t.Fatalf("processInbound returned error: %v", err)
	}
	if key == (session.Key{}) {
		t.Fatal("expected inbound ACK to resolve connection key")
	}
	if observed {
		t.Fatal("expected pure ACK not to count as observation without active mutation window")
	}
	if mutated {
		t.Fatal("expected pure ACK not to count as mutation")
	}
	if cleanup {
		t.Fatal("expected pure ACK not to trigger cleanup")
	}
	if result.Outcome != "" {
		t.Fatalf("expected pure ACK not to produce observation outcome, got %q", result.Outcome)
	}
	if len(handle.sent) != 1 {
		t.Fatalf("expected inbound blocker to forward pure ACK once, got %d sends", len(handle.sent))
	}
}

func TestProcessInboundBlockerForwardsNonMutatedHandshakePacket(t *testing.T) {
	cfg := config.Config{
		TargetIP:        netip.MustParseAddr("93.184.216.34"),
		TargetPort:      443,
		ObserveTimeout:  50 * time.Millisecond,
		MutateDirection: "in",
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store := session.NewStore(time.Now)
	reported := make(map[session.Key]struct{})
	handle := &fakeHandle{}

	key, result, observed, mutated, cleanup, err := processInbound(logger, store, reported, cfg, inboundHandshakePacketWithSeq(1000), nil, handle, "in")
	if err != nil {
		t.Fatalf("processInbound returned error: %v", err)
	}
	if key == (session.Key{}) {
		t.Fatal("expected handshake packet to resolve connection key")
	}
	if observed {
		t.Fatal("expected handshake packet without active mutation window not to count as observation")
	}
	if mutated {
		t.Fatal("expected handshake packet not to count as mutation")
	}
	if cleanup {
		t.Fatal("expected handshake packet not to trigger cleanup")
	}
	if result.Outcome != "" {
		t.Fatalf("expected handshake packet not to produce observation outcome, got %q", result.Outcome)
	}
	if len(handle.sent) != 1 {
		t.Fatalf("expected inbound blocker to forward non-mutated handshake packet once, got %d sends", len(handle.sent))
	}
}

func TestProcessInboundBlockerForwardsTerminalResultPacket(t *testing.T) {
	cfg := config.Config{
		TargetIP:        netip.MustParseAddr("93.184.216.34"),
		TargetPort:      443,
		ObserveTimeout:  50 * time.Millisecond,
		MutateDirection: "in",
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store := session.NewStore(time.Now)
	reported := make(map[session.Key]struct{})
	handle := &fakeHandle{}
	key := session.Key{
		ClientIP:   "10.0.0.2",
		ClientPort: 50000,
		ServerIP:   "93.184.216.34",
		ServerPort: 443,
	}
	store.MarkMatched(key)

	packet := inboundFINApplicationDataPacketWithSeq(1000, []byte{0x17, 0x03, 0x03, 0x00, 0x04, 0xaa, 0xbb, 0xcc, 0xdd})
	gotKey, result, observed, mutated, cleanup, err := processInbound(logger, store, reported, cfg, packet, nil, handle, "in")
	if err != nil {
		t.Fatalf("processInbound returned error: %v", err)
	}
	if gotKey != key {
		t.Fatalf("unexpected key: got=%+v want=%+v", gotKey, key)
	}
	if !observed {
		t.Fatal("expected terminal packet to be observed")
	}
	if !mutated {
		t.Fatal("expected terminal application-data packet to be mutated")
	}
	if !cleanup {
		t.Fatal("expected terminal packet to trigger cleanup")
	}
	if len(handle.sent) != 1 {
		t.Fatalf("expected inbound blocker to reinject terminal packet once, got %d sends", len(handle.sent))
	}
	if got := handle.sent[0].packet[45]; got != 0x55 {
		t.Fatalf("expected terminal packet to be mutated before reinjection, got 0x%02x", got)
	}
	if result.Outcome == session.OutcomeUnknown {
		t.Fatal("expected terminal packet to produce a concrete observation result after reinjection")
	}
}

func TestProcessInboundAckClearsOutboundPendingMutationPoints(t *testing.T) {
	cfg := config.Config{
		TargetIP:       netip.MustParseAddr("93.184.216.34"),
		TargetPort:     443,
		ObserveTimeout: 50 * time.Millisecond,
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store := session.NewStore(time.Now)
	reported := make(map[session.Key]struct{})
	key := session.Key{
		ClientIP:   "10.0.0.2",
		ClientPort: 50000,
		ServerIP:   "93.184.216.34",
		ServerPort: 443,
	}

	store.AddOutboundMutationPoint(key, reassembly.MutationPoint{
		TargetSeq: 2002,
		OldByte:   0xaa,
		NewByte:   0x55,
	})

	gotKey, result, observed, mutated, cleanup, err := processInbound(logger, store, reported, cfg, inboundAckPacket(2003), nil, nil, "out")
	if err != nil {
		t.Fatalf("processInbound returned error: %v", err)
	}
	if gotKey != key {
		t.Fatalf("unexpected key: got=%+v want=%+v", gotKey, key)
	}
	if observed {
		t.Fatal("expected pure ACK not to count as observation")
	}
	if mutated {
		t.Fatal("expected pure ACK not to count as mutation")
	}
	if cleanup {
		t.Fatal("expected pure ACK not to trigger cleanup")
	}
	if result.Outcome != "" {
		t.Fatalf("expected pure ACK not to produce observation outcome, got %q", result.Outcome)
	}
	if got := len(store.OutboundPendingMutationPoints(key)); got != 0 {
		t.Fatalf("expected inbound ACK to clear outbound pending points, got %d", got)
	}
}

func TestProcessOutboundAckClearsInboundPendingMutationPoints(t *testing.T) {
	cfg := config.Config{
		TargetIP:       netip.MustParseAddr("93.184.216.34"),
		TargetPort:     443,
		ObserveTimeout: 50 * time.Millisecond,
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store := session.NewStore(time.Now)
	handle := &fakeHandle{}
	key := session.Key{
		ClientIP:   "10.0.0.2",
		ClientPort: 50000,
		ServerIP:   "93.184.216.34",
		ServerPort: 443,
	}

	store.AddInboundMutationPoint(key, reassembly.MutationPoint{
		TargetSeq: 3002,
		OldByte:   0xaa,
		NewByte:   0x55,
	})

	gotKey, mutated, cleanup, err := processOutbound(cfg, logger, store, handle, outboundAckPacket(3003), nil)
	if err != nil {
		t.Fatalf("processOutbound returned error: %v", err)
	}
	if gotKey != key {
		t.Fatalf("unexpected key: got=%+v want=%+v", gotKey, key)
	}
	if mutated {
		t.Fatal("expected pure ACK not to mutate packet")
	}
	if cleanup {
		t.Fatal("expected pure ACK not to trigger cleanup")
	}
	if got := len(store.InboundPendingMutationPoints(key)); got != 0 {
		t.Fatalf("expected outbound ACK to clear inbound pending points, got %d", got)
	}
	if len(handle.sent) != 1 {
		t.Fatalf("expected pure ACK to be forwarded once, got %d sends", len(handle.sent))
	}
}

func TestLoopLogsMutateDirectionsForOutboundAndInbound(t *testing.T) {
	cfg := config.Config{
		TargetIP:        netip.MustParseAddr("93.184.216.34"),
		TargetPort:      443,
		ObserveTimeout:  50 * time.Millisecond,
		MutateOffset:    0,
		MutateDirection: "both",
	}

	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	out := &scriptedHandle{steps: []recvStep{
		{packet: outboundTLSPacket()},
	}}
	in := &scriptedHandle{steps: []recvStep{
		{packet: inboundApplicationDataPacketWithSeq(1000, []byte{0x17, 0x03, 0x03, 0x00, 0x04, 0xaa, 0xbb, 0xcc, 0xdd})},
	}}

	if err := RunLoop(context.Background(), cfg, logger, out, in); err != nil {
		t.Fatalf("RunLoop returned error: %v", err)
	}

	logOutput := logs.String()
	if !strings.Contains(logOutput, "direction=out") {
		t.Fatalf("expected outbound mutation log to include direction=out, got: %s", logOutput)
	}
	if !strings.Contains(logOutput, "direction=in") {
		t.Fatalf("expected inbound mutation log to include direction=in, got: %s", logOutput)
	}
}

func TestLoopContinuesAfterReassemblyBufferLimitExceeded(t *testing.T) {
	cfg := config.Config{
		TargetIP:       netip.MustParseAddr("93.184.216.34"),
		TargetPort:     443,
		ObserveTimeout: 20 * time.Millisecond,
		MutateOffset:   0,
	}

	steps := []recvStep{
		{packet: outboundApplicationDataFragmentWithSeq(1000, []byte{0x00})},
	}
	for i := 0; i < 17; i++ {
		steps = append(steps, recvStep{
			packet: outboundApplicationDataFragmentWithSeq(uint32(2000+i*2), []byte{byte(0x80 + i)}),
		})
	}
	steps = append(steps, recvStep{
		packet: outboundTLSPacketWithSeq(1001),
	})

	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	out := &scriptedHandle{steps: steps}

	if err := RunLoop(context.Background(), cfg, logger, out, nil); err != nil {
		t.Fatalf("RunLoop returned error: %v", err)
	}

	if len(out.sent) != len(steps) {
		t.Fatalf("expected all packets to be sent despite buffer limit, got %d want %d", len(out.sent), len(steps))
	}
	if got := out.sent[len(steps)-1].packet[45]; got != 0x55 {
		t.Fatalf("expected later contiguous packet to still mutate after conservative reset, got 0x%02x", got)
	}
	if !strings.Contains(logs.String(), "出站最小重组触发保守放行") {
		t.Fatalf("expected conservative reassembly failure to be logged, got: %s", logs.String())
	}
}

func TestProcessOutboundKeepsPendingMutationWhenReassemblyBufferLimitExceeded(t *testing.T) {
	cfg := config.Config{
		TargetIP:       netip.MustParseAddr("93.184.216.34"),
		TargetPort:     443,
		ObserveTimeout: 20 * time.Millisecond,
		MutateOffset:   0,
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug}))
	store := session.NewStore(time.Now)
	handle := &fakeHandle{}
	key := session.Key{
		ClientIP:   "10.0.0.2",
		ClientPort: 50000,
		ServerIP:   "93.184.216.34",
		ServerPort: 443,
	}

	store.MarkMatched(key)
	store.MarkMutated(key, cfg.ObserveTimeout, 45)
	store.AddMutationPoint(key, reassembly.MutationPoint{
		TargetSeq: 2032,
		OldByte:   0xaa,
		NewByte:   0x55,
	})

	state := store.Reassembly(key, 1000)
	for i := 0; i < 16; i++ {
		if _, err := state.Push(reassembly.Segment{
			Seq:  uint32(2000 + i*2),
			Data: []byte{byte(0x80 + i)},
		}, 0); err != nil {
			t.Fatalf("failed to prefill future segments: %v", err)
		}
	}

	packet := outboundApplicationDataFragmentWithSeq(2032, []byte{0xaa})
	gotKey, mutated, cleanup, err := processOutbound(cfg, logger, store, handle, packet, nil)
	if err != nil {
		t.Fatalf("processOutbound returned error: %v", err)
	}
	if gotKey != key {
		t.Fatalf("unexpected key: got=%+v want=%+v", gotKey, key)
	}
	if !mutated {
		t.Fatal("expected packet with pending mutation to report mutated=true")
	}
	if cleanup {
		t.Fatal("expected packet not to trigger cleanup")
	}

	if len(handle.sent) != 1 {
		t.Fatalf("expected one outbound send, got %d", len(handle.sent))
	}
	if got := handle.sent[0].packet[40]; got != 0x55 {
		t.Fatalf("expected sent packet to preserve pending mutation after conservative reassembly failure, got 0x%02x", got)
	}
}

func TestProcessOutboundBufferLimitRefreshesInternalObserveWindow(t *testing.T) {
	cfg := config.Config{
		TargetIP:       netip.MustParseAddr("93.184.216.34"),
		TargetPort:     443,
		ObserveTimeout: 5 * time.Second,
		MutateOffset:   0,
	}

	now := time.Unix(100, 0)
	store := session.NewStore(func() time.Time { return now })
	handle := &fakeHandle{}
	reported := make(map[session.Key]struct{})
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	key := session.Key{
		ClientIP:   "10.0.0.2",
		ClientPort: 50000,
		ServerIP:   "93.184.216.34",
		ServerPort: 443,
	}

	store.MarkMatched(key)
	store.MarkMutated(key, cfg.ObserveTimeout, 45)
	store.AddMutationPoint(key, reassembly.MutationPoint{
		TargetSeq: 2032,
		OldByte:   0xaa,
		NewByte:   0x55,
	})

	state := store.Reassembly(key, 1000)
	for i := 0; i < 16; i++ {
		if _, err := state.Push(reassembly.Segment{
			Seq:  uint32(2000 + i*2),
			Data: []byte{byte(0x80 + i)},
		}, 0); err != nil {
			t.Fatalf("failed to prefill future segments: %v", err)
		}
	}

	now = now.Add(4 * time.Second)
	packet := outboundApplicationDataFragmentWithSeq(2032, []byte{0xaa})
	gotKey, mutated, cleanup, err := processOutbound(cfg, logger, store, handle, packet, nil)
	if err != nil {
		t.Fatalf("processOutbound returned error: %v", err)
	}
	if gotKey != key {
		t.Fatalf("unexpected key: got=%+v want=%+v", gotKey, key)
	}
	if !mutated {
		t.Fatal("expected packet with pending mutation to report mutated=true")
	}
	if cleanup {
		t.Fatal("expected packet not to trigger cleanup")
	}

	if len(handle.sent) != 1 {
		t.Fatalf("expected one outbound send, got %d", len(handle.sent))
	}
	if got := handle.sent[0].packet[40]; got != 0x55 {
		t.Fatalf("expected conservative send to keep pending mutation, got 0x%02x", got)
	}

	now = now.Add(2 * time.Second)
	inboundKey, result, observed, mutated, cleanup, err := processInbound(logger, store, reported, cfg, inboundRSTPacket(), nil, nil, "out")
	if err != nil {
		t.Fatalf("processInbound returned error: %v", err)
	}
	if inboundKey != key {
		t.Fatalf("unexpected inbound key: got=%+v want=%+v", inboundKey, key)
	}
	if !observed {
		t.Fatal("expected inbound RST to observe refreshed mutation window")
	}
	if mutated {
		t.Fatal("expected inbound RST observation path not to report mutation")
	}
	if !cleanup {
		t.Fatal("expected inbound RST to trigger cleanup")
	}
	if result.Outcome != session.OutcomeDefiniteFailure {
		t.Fatalf("expected refreshed internal observe window to classify inbound RST as definite_failure, got %s", result.Outcome)
	}
	if result.ObservedFor != 2*time.Second {
		t.Fatalf("expected observation duration to be measured from conservative-branch mutation, got %s", result.ObservedFor)
	}
	if result.ByteIndex != 40 {
		t.Fatalf("expected byte index to match conservative-branch mutation, got %d", result.ByteIndex)
	}
	if !strings.Contains(logs.String(), "direction=out") {
		t.Fatalf("expected conservative-branch mutation to include direction=out, got: %s", logs.String())
	}
	if !strings.Contains(logs.String(), "first_observation=false") {
		t.Fatalf("expected conservative-branch mutation to be logged, got: %s", logs.String())
	}
}

func TestProcessBlockedOutboundSkipsStaleEventWhenHandleMissing(t *testing.T) {
	cfg := config.Config{
		TargetHost:     "example.com",
		TargetPort:     443,
		ObserveTimeout: 5 * time.Second,
		MutateOffset:   0,
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store := session.NewStore(time.Now)
	key := session.Key{
		ClientIP:   "10.0.0.2",
		ClientPort: 50000,
		ServerIP:   "93.184.216.34",
		ServerPort: 443,
	}

	gotKey, mutated, cleanup, err := processBlockedOutbound(cfg, logger, store, key, outboundTLSPacket(), nil, nil, "out")
	if err != nil {
		t.Fatalf("processBlockedOutbound returned error: %v", err)
	}
	if gotKey != key {
		t.Fatalf("unexpected key: got=%+v want=%+v", gotKey, key)
	}
	if mutated {
		t.Fatal("expected stale outbound block event not to report mutation")
	}
	if cleanup {
		t.Fatal("expected stale outbound block event not to trigger cleanup")
	}
}

func TestRunLoopIgnoresAbortedIOFromClosedDynamicBlocker(t *testing.T) {
	cfg := config.Config{
		TargetHost:     "example.com",
		TargetPort:     443,
		ObserveTimeout: 50 * time.Millisecond,
		MutateOffset:   0,
	}

	hello := outboundClientHelloPacket("example.com")
	observe := &scriptedHandle{steps: []recvStep{
		{packet: hello},
	}}
	blocker := &abortingOnCloseHandle{
		firstPacket: outboundTLSPacketWithSeq(uint32(len(hello) - 40)),
	}
	in := &scriptedHandle{steps: []recvStep{
		{delay: 10 * time.Millisecond, packet: inboundRSTPacket()},
	}}
	factory := func(key session.Key) (packetHandle, error) {
		return blocker, nil
	}

	err := runLoopWithHandles(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), observe, nil, in, nil, factory)
	if err != nil {
		t.Fatalf("expected closed dynamic blocker abort to be ignored, got %v", err)
	}
}

type packetWithAddr struct {
	packet []byte
	addr   any
}

type fakeHandle struct {
	recv []packetWithAddr
	sent []packetWithAddr
}

func (h *fakeHandle) Recv() ([]byte, any, error) {
	if len(h.recv) == 0 {
		return nil, nil, io.EOF
	}
	got := h.recv[0]
	h.recv = h.recv[1:]
	return append([]byte(nil), got.packet...), got.addr, nil
}

func (h *fakeHandle) Send(packet []byte, addr any) error {
	h.sent = append(h.sent, packetWithAddr{
		packet: append([]byte(nil), packet...),
		addr:   addr,
	})
	return nil
}

func (h *fakeHandle) Close() error {
	return nil
}

type strictAddrHandle struct {
	recv             []packetWithAddr
	sent             []packetWithAddr
	expectedSendAddr any
}

func (h *strictAddrHandle) Recv() ([]byte, any, error) {
	if len(h.recv) == 0 {
		return nil, nil, io.EOF
	}
	got := h.recv[0]
	h.recv = h.recv[1:]
	return append([]byte(nil), got.packet...), got.addr, nil
}

func (h *strictAddrHandle) Send(packet []byte, addr any) error {
	if addr != h.expectedSendAddr {
		return errors.New("reinject addr mismatch")
	}
	h.sent = append(h.sent, packetWithAddr{
		packet: append([]byte(nil), packet...),
		addr:   addr,
	})
	return nil
}

func (h *strictAddrHandle) Close() error {
	return nil
}

type recvStep struct {
	packet          []byte
	addr            any
	err             error
	delay           time.Duration
	blockUntilClose bool
}

type scriptedHandle struct {
	mu        sync.Mutex
	steps     []recvStep
	sent      []packetWithAddr
	closed    chan struct{}
	closeOnce sync.Once
	isClosed  bool
}

func (h *scriptedHandle) Recv() ([]byte, any, error) {
	h.mu.Lock()
	if h.closed == nil {
		h.closed = make(chan struct{})
	}
	if len(h.steps) == 0 {
		h.mu.Unlock()
		return nil, nil, io.EOF
	}
	step := h.steps[0]
	h.steps = h.steps[1:]
	closed := h.closed
	h.mu.Unlock()

	if step.blockUntilClose {
		<-closed
		return nil, nil, io.EOF
	}
	if step.delay > 0 {
		timer := time.NewTimer(step.delay)
		defer timer.Stop()
		select {
		case <-closed:
			return nil, nil, io.EOF
		case <-timer.C:
		}
	}
	if step.err != nil {
		return nil, nil, step.err
	}
	return append([]byte(nil), step.packet...), step.addr, nil
}

func (h *scriptedHandle) Send(packet []byte, addr any) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sent = append(h.sent, packetWithAddr{
		packet: append([]byte(nil), packet...),
		addr:   addr,
	})
	return nil
}

func (h *scriptedHandle) Close() error {
	h.mu.Lock()
	if h.closed == nil {
		h.closed = make(chan struct{})
	}
	closed := h.closed
	h.mu.Unlock()

	h.closeOnce.Do(func() {
		close(closed)
		h.mu.Lock()
		h.isClosed = true
		h.mu.Unlock()
	})
	return nil
}

func (h *scriptedHandle) IsClosed() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.isClosed
}

type abortingOnCloseHandle struct {
	firstPacket []byte
	closed      chan struct{}
	closeOnce   sync.Once
	mu          sync.Mutex
	sent        []packetWithAddr
	readCount   int
}

func (h *abortingOnCloseHandle) Recv() ([]byte, any, error) {
	h.mu.Lock()
	if h.closed == nil {
		h.closed = make(chan struct{})
	}
	closed := h.closed
	h.readCount++
	readCount := h.readCount
	packet := append([]byte(nil), h.firstPacket...)
	h.mu.Unlock()

	if readCount == 1 {
		return packet, nil, nil
	}

	<-closed
	return nil, nil, errors.New("The I/O operation has been aborted because of either a thread exit or an application request")
}

func (h *abortingOnCloseHandle) Send(packet []byte, addr any) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sent = append(h.sent, packetWithAddr{
		packet: append([]byte(nil), packet...),
		addr:   addr,
	})
	return nil
}

func (h *abortingOnCloseHandle) Close() error {
	h.mu.Lock()
	if h.closed == nil {
		h.closed = make(chan struct{})
	}
	closed := h.closed
	h.mu.Unlock()

	h.closeOnce.Do(func() {
		close(closed)
	})
	return nil
}

func outboundTLSPacket() []byte {
	payload := []byte{0x17, 0x03, 0x03, 0x00, 0x04, 0xaa, 0xbb, 0xcc, 0xdd}
	return outboundTLSPacketWithSeqPayload(0, payload)
}

func outboundTLSPacketTo(dst string) []byte {
	return outboundTLSPacketToWithSeq(dst, 0)
}

func outboundClientHelloPacket(serverName string) []byte {
	return outboundClientHelloPacketTo("93.184.216.34", serverName)
}

func outboundClientHelloPacketTo(dst string, serverName string) []byte {
	return outboundClientHelloPacketToWithSeq(dst, 0, serverName)
}

func outboundNonClientHelloPacket() []byte {
	packet := outboundClientHelloPacket("example.com")
	packet[45] = 0x02
	return packet
}

func outboundFINPacket() []byte {
	return outboundFINPacketWithSeq(0)
}

func outboundFINPacketWithSeq(seq uint32) []byte {
	return makeIPv4TCPPacketWithSeqAck(
		[4]byte{10, 0, 0, 2},
		[4]byte{93, 184, 216, 34},
		50000,
		443,
		seq,
		0,
		0x11,
		nil,
	)
}

func inboundRSTPacket() []byte {
	return makeIPv4TCPPacketWithSeqAck(
		[4]byte{93, 184, 216, 34},
		[4]byte{10, 0, 0, 2},
		443,
		50000,
		0,
		0,
		0x14,
		nil,
	)
}

func inboundFINPacket() []byte {
	return makeIPv4TCPPacketWithSeqAck(
		[4]byte{93, 184, 216, 34},
		[4]byte{10, 0, 0, 2},
		443,
		50000,
		0,
		0,
		0x11,
		nil,
	)
}

func inboundTLSAlertPacketWithSeq(seq uint32) []byte {
	return makeIPv4TCPPacketWithSeqAck(
		[4]byte{93, 184, 216, 34},
		[4]byte{10, 0, 0, 2},
		443,
		50000,
		seq,
		0,
		0x18,
		[]byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28},
	)
}

func inboundPlainPacket() []byte {
	return inboundPlainPacketWithSeq(0)
}

func inboundPlainPacketWithSeq(seq uint32) []byte {
	return makeIPv4TCPPacketWithSeqAck(
		[4]byte{93, 184, 216, 34},
		[4]byte{10, 0, 0, 2},
		443,
		50000,
		seq,
		0,
		0x10,
		nil,
	)
}

func inboundApplicationDataPacketWithSeq(seq uint32, payload []byte) []byte {
	return makeIPv4TCPPacketWithSeqAck(
		[4]byte{93, 184, 216, 34},
		[4]byte{10, 0, 0, 2},
		443,
		50000,
		seq,
		0,
		0x18,
		payload,
	)
}

func inboundHandshakePacketWithSeq(seq uint32) []byte {
	return makeIPv4TCPPacketWithSeqAck(
		[4]byte{93, 184, 216, 34},
		[4]byte{10, 0, 0, 2},
		443,
		50000,
		seq,
		0,
		0x18,
		[]byte{0x16, 0x03, 0x03, 0x00, 0x01, 0x01},
	)
}

func inboundFINApplicationDataPacketWithSeq(seq uint32, payload []byte) []byte {
	return makeIPv4TCPPacketWithSeqAck(
		[4]byte{93, 184, 216, 34},
		[4]byte{10, 0, 0, 2},
		443,
		50000,
		seq,
		0,
		0x19,
		payload,
	)
}

func makeIPv4TCPPacket(srcIP, dstIP [4]byte, srcPort, dstPort uint16, flags byte, payload []byte) []byte {
	return makeIPv4TCPPacketWithSeqAck(srcIP, dstIP, srcPort, dstPort, 0, 0, flags, payload)
}

func makeIPv4TCPPacketWithSeqAck(srcIP, dstIP [4]byte, srcPort, dstPort uint16, seq, ack uint32, flags byte, payload []byte) []byte {
	packet := make([]byte, 40+len(payload))
	packet[0] = 0x45
	totalLen := len(packet)
	packet[2] = byte(totalLen >> 8)
	packet[3] = byte(totalLen)
	packet[8] = 64
	packet[9] = 6
	copy(packet[12:16], srcIP[:])
	copy(packet[16:20], dstIP[:])
	packet[20] = byte(srcPort >> 8)
	packet[21] = byte(srcPort)
	packet[22] = byte(dstPort >> 8)
	packet[23] = byte(dstPort)
	binary.BigEndian.PutUint32(packet[24:28], seq)
	binary.BigEndian.PutUint32(packet[28:32], ack)
	packet[32] = 0x50
	packet[33] = flags
	copy(packet[40:], payload)
	return packet
}

func outboundTLSPacketWithSeq(seq uint32) []byte {
	return outboundTLSPacketWithSeqPayload(seq, []byte{0x17, 0x03, 0x03, 0x00, 0x04, 0xaa, 0xbb, 0xcc, 0xdd})
}

func outboundTLSPacketToWithSeq(dst string, seq uint32) []byte {
	return makeIPv4TCPPacketWithSeqAck(
		[4]byte{10, 0, 0, 2},
		parseIPv4ForTest(dst),
		50000,
		443,
		seq,
		0,
		0x18,
		[]byte{0x17, 0x03, 0x03, 0x00, 0x04, 0xaa, 0xbb, 0xcc, 0xdd},
	)
}

func outboundTLSPacketWithSeqPayload(seq uint32, payload []byte) []byte {
	return makeIPv4TCPPacketWithSeqAck(
		[4]byte{10, 0, 0, 2},
		[4]byte{93, 184, 216, 34},
		50000,
		443,
		seq,
		0,
		0x18,
		payload,
	)
}

func outboundClientHelloPacketToWithSeq(dst string, seq uint32, serverName string) []byte {
	return makeIPv4TCPPacketWithSeqAck(
		[4]byte{10, 0, 0, 2},
		parseIPv4ForTest(dst),
		50000,
		443,
		seq,
		0,
		0x18,
		buildClientHelloPayload(serverName),
	)
}

func outboundApplicationDataFragmentWithSeq(seq uint32, payload []byte) []byte {
	return makeIPv4TCPPacketWithSeqAck(
		[4]byte{10, 0, 0, 2},
		[4]byte{93, 184, 216, 34},
		50000,
		443,
		seq,
		0,
		0x18,
		payload,
	)
}

func inboundAckPacket(ack uint32) []byte {
	return makeIPv4TCPPacketWithSeqAck(
		[4]byte{93, 184, 216, 34},
		[4]byte{10, 0, 0, 2},
		443,
		50000,
		0,
		ack,
		0x10,
		nil,
	)
}

func outboundAckPacket(ack uint32) []byte {
	return makeIPv4TCPPacketWithSeqAck(
		[4]byte{10, 0, 0, 2},
		[4]byte{93, 184, 216, 34},
		50000,
		443,
		0,
		ack,
		0x10,
		nil,
	)
}

func buildClientHelloPayload(serverName string) []byte {
	nameBytes := []byte(serverName)

	serverNameExt := make([]byte, 0, 5+len(nameBytes))
	if len(nameBytes) > 0 {
		listLen := 3 + len(nameBytes)
		serverNameExt = append(serverNameExt,
			byte(listLen>>8), byte(listLen),
			0x00,
			byte(len(nameBytes)>>8), byte(len(nameBytes)),
		)
		serverNameExt = append(serverNameExt, nameBytes...)
	}

	extensions := make([]byte, 0, 4+len(serverNameExt))
	if len(serverNameExt) > 0 {
		extensions = append(extensions,
			0x00, 0x00,
			byte(len(serverNameExt)>>8), byte(len(serverNameExt)),
		)
		extensions = append(extensions, serverNameExt...)
	}

	body := make([]byte, 0, 2+32+1+2+2+1+1+2+len(extensions))
	body = append(body, 0x03, 0x03)
	body = append(body, bytes.Repeat([]byte{0x11}, 32)...)
	body = append(body, 0x00)
	body = append(body, 0x00, 0x02, 0x13, 0x01)
	body = append(body, 0x01, 0x00)
	body = append(body, byte(len(extensions)>>8), byte(len(extensions)))
	body = append(body, extensions...)

	handshake := make([]byte, 0, 4+len(body))
	handshake = append(handshake, 0x01, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
	handshake = append(handshake, body...)

	record := make([]byte, 0, 5+len(handshake))
	record = append(record, 0x16, 0x03, 0x03, byte(len(handshake)>>8), byte(len(handshake)))
	record = append(record, handshake...)
	return record
}

func parseIPv4ForTest(addr string) [4]byte {
	return netip.MustParseAddr(addr).As4()
}
