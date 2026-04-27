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
		ObserveTimeout: 10 * time.Millisecond,
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

	if err := runLoopWithHandles(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), observe, nil, nil, factory); err != nil {
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
		ObserveTimeout: 10 * time.Millisecond,
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

	if err := runLoopWithHandles(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), observe, nil, nil, factory); err != nil {
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
		ObserveTimeout: 10 * time.Millisecond,
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

	if err := RunLoop(context.Background(), cfg, logger, out, nil); err != nil {
		t.Fatalf("RunLoop returned error: %v", err)
	}

	logOutput := logs.String()
	if !strings.Contains(logOutput, "SNI 命中目标域名") {
		t.Fatalf("expected host-only flow to log SNI match, got: %s", logOutput)
	}
	if !strings.Contains(logOutput, "matched_host=example.com") {
		t.Fatalf("expected SNI match log to include matched_host, got: %s", logOutput)
	}
}

func TestLoopKeepsHostMatchAfterNormalInboundPacket(t *testing.T) {
	cfg := config.Config{
		TargetHost:     "example.com",
		TargetPort:     443,
		ObserveTimeout: 10 * time.Millisecond,
		MutateOffset:   0,
	}

	hello := outboundClientHelloPacket("example.com")
	out := &scriptedHandle{steps: []recvStep{
		{packet: hello},
		{delay: 20 * time.Millisecond, packet: outboundTLSPacketWithSeq(uint32(len(hello) - 40))},
	}}
	in := &scriptedHandle{steps: []recvStep{
		{delay: 5 * time.Millisecond, packet: inboundPlainPacket()},
	}}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	if err := RunLoop(context.Background(), cfg, logger, out, in); err != nil {
		t.Fatalf("RunLoop returned error: %v", err)
	}

	if len(out.sent) != 2 {
		t.Fatalf("expected two outbound sends, got %d", len(out.sent))
	}
	if got := out.sent[1].packet[45]; got != 0x55 {
		t.Fatalf("expected ciphertext to be mutated after normal inbound packet, got 0x%02x", got)
	}
}

func TestLoopSkipsMutationWhenSNIIsDifferent(t *testing.T) {
	cfg := config.Config{
		TargetHost:     "example.com",
		TargetPort:     443,
		ObserveTimeout: 10 * time.Millisecond,
		MutateOffset:   0,
	}

	hello := outboundClientHelloPacket("other.example")
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
	if got := out.sent[1].packet[45]; got != 0xaa {
		t.Fatalf("expected ciphertext to remain unchanged when SNI mismatches, got 0x%02x", got)
	}
}

func TestLoopLogsHostExclusionWhenSNIMismatches(t *testing.T) {
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
		t.Fatalf("expected mismatched host flow to log exclusion, got: %s", logOutput)
	}
	if !strings.Contains(logOutput, "observed_host=other.example") {
		t.Fatalf("expected exclusion log to include observed_host, got: %s", logOutput)
	}
}

func TestLoopKeepsUnknownAndSkipsMutationWhenSNICannotBeParsed(t *testing.T) {
	cfg := config.Config{
		TargetHost:     "example.com",
		TargetPort:     443,
		ObserveTimeout: 10 * time.Millisecond,
		MutateOffset:   0,
	}

	first := outboundNonClientHelloPacket()
	second := outboundClientHelloPacketToWithSeq("93.184.216.34", uint32(len(first)-40), "example.com")
	out := &scriptedHandle{steps: []recvStep{
		{packet: first},
		{packet: second},
		{packet: outboundTLSPacketWithSeq(uint32(len(first)-40) + uint32(len(second)-40))},
	}}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	if err := RunLoop(context.Background(), cfg, logger, out, nil); err != nil {
		t.Fatalf("RunLoop returned error: %v", err)
	}

	if len(out.sent) != 3 {
		t.Fatalf("expected three outbound sends, got %d", len(out.sent))
	}
	if got := out.sent[2].packet[45]; got != 0x55 {
		t.Fatalf("expected ciphertext to be mutated after later SNI match, got 0x%02x", got)
	}
}

func TestLoopReparsesHostAfterExcludedConnectionEnds(t *testing.T) {
	cfg := config.Config{
		TargetHost:     "example.com",
		TargetPort:     443,
		ObserveTimeout: 10 * time.Millisecond,
		MutateOffset:   0,
	}

	first := outboundClientHelloPacket("other.example")
	second := outboundClientHelloPacket("example.com")
	out := &scriptedHandle{steps: []recvStep{
		{packet: first},
		{packet: outboundFINPacketWithSeq(uint32(len(first) - 40))},
		{packet: second},
		{packet: outboundTLSPacketWithSeq(uint32(len(second) - 40))},
	}}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	if err := RunLoop(context.Background(), cfg, logger, out, nil); err != nil {
		t.Fatalf("RunLoop returned error: %v", err)
	}

	if len(out.sent) != 4 {
		t.Fatalf("expected four outbound sends, got %d", len(out.sent))
	}
	if got := out.sent[3].packet[45]; got != 0x55 {
		t.Fatalf("expected new connection to mutate after excluded state was cleared, got 0x%02x", got)
	}
}

func TestLoopMatchesTargetIPAndHostIntersection(t *testing.T) {
	cfg := config.Config{
		TargetIP:       netip.MustParseAddr("93.184.216.34"),
		TargetHost:     "example.com",
		TargetPort:     443,
		ObserveTimeout: 10 * time.Millisecond,
		MutateOffset:   0,
	}

	hello := outboundClientHelloPacketToWithSeq("93.184.216.34", 0, "example.com")
	out := &scriptedHandle{steps: []recvStep{
		{packet: hello},
		{packet: outboundTLSPacketToWithSeq("93.184.216.34", uint32(len(hello)-40))},
	}}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	if err := RunLoop(context.Background(), cfg, logger, out, nil); err != nil {
		t.Fatalf("RunLoop returned error: %v", err)
	}

	if len(out.sent) != 2 {
		t.Fatalf("expected two outbound sends, got %d", len(out.sent))
	}
	if got := out.sent[1].packet[45]; got != 0x55 {
		t.Fatalf("expected mutated ciphertext byte 0x55 for intersected match, got 0x%02x", got)
	}
}

func TestLoopIgnoresClientFINAfterMutation(t *testing.T) {
	cfg := config.Config{
		TargetIP:       netip.MustParseAddr("93.184.216.34"),
		TargetPort:     443,
		ObserveTimeout: 10 * time.Millisecond,
		MutateOffset:   0,
	}

	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	first := outboundTLSPacket()
	out := &scriptedHandle{steps: []recvStep{
		{packet: first},
		{packet: outboundFINPacketWithSeq(uint32(len(first) - 40))},
	}}
	in := &scriptedHandle{}

	if err := RunLoop(context.Background(), cfg, logger, out, in); err != nil {
		t.Fatalf("RunLoop returned error: %v", err)
	}

	if len(out.sent) != 2 {
		t.Fatalf("expected two outbound sends, got %d", len(out.sent))
	}

	logOutput := logs.String()
	if strings.Contains(logOutput, "outcome=probable_failure") || strings.Contains(logOutput, "outcome=definite_failure") {
		t.Fatalf("client-side FIN should not classify failure, logs: %s", logOutput)
	}
	if !strings.Contains(logOutput, "outcome=no_conclusion") {
		t.Fatalf("expected timeout no_conclusion log, got: %s", logOutput)
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

func TestLoopMutatesCrossPacketApplicationDataAfterReassembly(t *testing.T) {
	cfg := config.Config{
		TargetIP:       netip.MustParseAddr("93.184.216.34"),
		TargetPort:     443,
		ObserveTimeout: 50 * time.Millisecond,
		MutateOffset:   0,
	}

	out := &scriptedHandle{steps: []recvStep{
		{packet: outboundApplicationDataFragmentWithSeq(1000, []byte{0x17, 0x03, 0x03, 0x00, 0x04})},
		{delay: 10 * time.Millisecond, packet: outboundApplicationDataFragmentWithSeq(1005, []byte{0xaa, 0xbb, 0xcc, 0xdd})},
	}}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	if err := RunLoop(context.Background(), cfg, logger, out, nil); err != nil {
		t.Fatalf("RunLoop returned error: %v", err)
	}

	if len(out.sent) != 2 {
		t.Fatalf("expected two outbound sends, got %d", len(out.sent))
	}
	if !bytes.Equal(out.sent[0].packet, outboundApplicationDataFragmentWithSeq(1000, []byte{0x17, 0x03, 0x03, 0x00, 0x04})) {
		t.Fatalf("expected first packet to stay unchanged before reassembly, got %x", out.sent[0].packet)
	}
	if got := out.sent[1].packet[40]; got != 0x55 {
		t.Fatalf("expected second packet to be mutated after reassembly, got 0x%02x", got)
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
	matches := regexp.MustCompile(`trace_id=t\d{6}`).FindAllString(logOutput, -1)
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
	if !regexp.MustCompile(`trace_id=t\d{6}`).MatchString(logOutput) {
		t.Fatalf("expected exclusion log to include trace_id, got: %s", logOutput)
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
	if got := strings.Count(logOutput, "命中完整 application data 破坏点"); got < 2 {
		t.Fatalf("expected each actually mutated packet to be logged, got %d logs: %s", got, logOutput)
	}
}

func TestLoopAckClearsPendingMutationPoint(t *testing.T) {
	cfg := config.Config{
		TargetIP:       netip.MustParseAddr("93.184.216.34"),
		TargetPort:     443,
		ObserveTimeout: 50 * time.Millisecond,
		MutateOffset:   0,
	}

	packet := outboundTLSPacketWithSeq(1000)
	out := &scriptedHandle{steps: []recvStep{
		{packet: packet},
		{delay: 20 * time.Millisecond, packet: packet},
	}}
	in := &scriptedHandle{steps: []recvStep{
		{delay: 5 * time.Millisecond, packet: inboundAckPacket(1006)},
	}}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	if err := RunLoop(context.Background(), cfg, logger, out, in); err != nil {
		t.Fatalf("RunLoop returned error: %v", err)
	}

	if len(out.sent) != 2 {
		t.Fatalf("expected two outbound sends, got %d", len(out.sent))
	}
	if got := out.sent[0].packet[45]; got != 0x55 {
		t.Fatalf("expected first transmission to be mutated, got 0x%02x", got)
	}
	if got := out.sent[1].packet[45]; got != 0xaa {
		t.Fatalf("expected retransmission to stay unchanged after ACK, got 0x%02x", got)
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
	inboundKey, result, observed, cleanup, err := processInbound(logger, store, reported, cfg, inboundRSTPacket())
	if err != nil {
		t.Fatalf("processInbound returned error: %v", err)
	}
	if inboundKey != key {
		t.Fatalf("unexpected inbound key: got=%+v want=%+v", inboundKey, key)
	}
	if !observed {
		t.Fatal("expected inbound RST to observe refreshed mutation window")
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
	if !strings.Contains(logs.String(), "命中完整 application data 破坏点") {
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

	gotKey, mutated, cleanup, err := processBlockedOutbound(cfg, logger, store, key, outboundTLSPacket(), nil, nil)
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

	err := runLoopWithHandles(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), observe, nil, in, factory)
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

func inboundPlainPacket() []byte {
	return makeIPv4TCPPacketWithSeqAck(
		[4]byte{93, 184, 216, 34},
		[4]byte{10, 0, 0, 2},
		443,
		50000,
		0,
		0,
		0x10,
		nil,
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
