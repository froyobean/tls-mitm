package reassembly

import (
	"errors"
	"testing"
)

func TestStateAssemblesCrossPacketApplicationData(t *testing.T) {
	state := NewState(1000)

	points, err := state.Push(Segment{
		Seq: 1000,
		Data: []byte{
			0x17, 0x03, 0x03, 0x00, 0x08,
			0xaa, 0xbb,
		},
	}, 0)
	if err != nil {
		t.Fatalf("Push returned error: %v", err)
	}
	if len(points) != 0 {
		t.Fatalf("expected no mutation point before record is complete, got %d", len(points))
	}

	points, err = state.Push(Segment{
		Seq:  1007,
		Data: []byte{0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22},
	}, 0)
	if err != nil {
		t.Fatalf("Push returned error: %v", err)
	}
	if len(points) != 1 {
		t.Fatalf("expected one mutation point after record completion, got %d", len(points))
	}
	if points[0].TargetSeq != 1005 {
		t.Fatalf("unexpected target seq: %d", points[0].TargetSeq)
	}
	if points[0].RecordStartSeq != 1000 {
		t.Fatalf("unexpected record start seq: %d", points[0].RecordStartSeq)
	}
	if points[0].OldByte != 0xaa || points[0].NewByte != 0x55 {
		t.Fatalf("unexpected mutation bytes: %+v", points[0])
	}
	if points[0].CreatedAt.IsZero() {
		t.Fatal("expected mutation point creation time to be recorded")
	}
}

func TestStateBuffersLightOutOfOrderSegment(t *testing.T) {
	state := NewState(1000)

	if _, err := state.Push(Segment{Seq: 1007, Data: []byte{0xcc, 0xdd}}, 0); err != nil {
		t.Fatalf("Push returned error: %v", err)
	}
	if state.NextSeq() != 1000 {
		t.Fatalf("unexpected next seq after out-of-order buffer: %d", state.NextSeq())
	}

	if _, err := state.Push(Segment{
		Seq:  1000,
		Data: []byte{0x17, 0x03, 0x03, 0x00, 0x04, 0xaa, 0xbb},
	}, 0); err != nil {
		t.Fatalf("Push returned error: %v", err)
	}
	if state.NextSeq() <= 1000 {
		t.Fatalf("expected next seq to advance, got %d", state.NextSeq())
	}
}

func TestStateSkipsNonApplicationDataRecord(t *testing.T) {
	state := NewState(1000)
	points, err := state.Push(Segment{
		Seq:  1000,
		Data: []byte{0x16, 0x03, 0x03, 0x00, 0x02, 0x01, 0x02},
	}, 0)
	if err != nil {
		t.Fatalf("Push returned error: %v", err)
	}
	if len(points) != 0 {
		t.Fatalf("expected no mutation point for handshake record, got %d", len(points))
	}
}

func TestStatePreservesIncompletePlausibleHeaderBeforeLaterPseudoHeader(t *testing.T) {
	state := NewState(1000)

	points, err := state.Push(Segment{
		Seq:  1000,
		Data: []byte{0x00, 0x17, 0x03, 0x03, 0x00, 0x17, 0x03, 0x03, 0x00, 0x02, 0xaa, 0xbb},
	}, 0)
	if err != nil {
		t.Fatalf("Push returned error: %v", err)
	}
	if len(points) != 0 {
		t.Fatalf("expected no mutation point while true header is incomplete, got %d", len(points))
	}

	points, err = state.Push(Segment{
		Seq:  1012,
		Data: []byte{0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd},
	}, 0)
	if err != nil {
		t.Fatalf("Push returned error: %v", err)
	}
	if len(points) != 1 {
		t.Fatalf("expected one mutation point after completing preserved header, got %d", len(points))
	}
	if points[0].TargetSeq != 1006 {
		t.Fatalf("unexpected target seq after preserving incomplete header: %d", points[0].TargetSeq)
	}
	if points[0].CreatedAt.IsZero() {
		t.Fatal("expected mutation point creation time to be recorded")
	}
}

func TestStateReturnsErrorWhenBufferLimitExceeded(t *testing.T) {
	state := NewState(1000)

	for i := 0; i <= maxBufferedSegments; i++ {
		points, err := state.Push(Segment{
			Seq:  uint32(2000 + i*2),
			Data: []byte{byte(i)},
		}, 0)
		if i < maxBufferedSegments {
			if err != nil {
				t.Fatalf("unexpected error before limit: %v", err)
			}
			if len(points) != 0 {
				t.Fatalf("expected no mutation point before limit, got %d", len(points))
			}
			continue
		}
		if !errors.Is(err, ErrBufferLimitExceeded) {
			t.Fatalf("expected ErrBufferLimitExceeded, got %v", err)
		}
		if len(points) != 0 {
			t.Fatalf("expected no mutation point when limit exceeded, got %d", len(points))
		}
	}

	points, err := state.Push(Segment{
		Seq:  1000,
		Data: []byte{0x17, 0x03, 0x03, 0x00, 0x04, 0xaa, 0xbb, 0xcc, 0xdd},
	}, 0)
	if err != nil {
		t.Fatalf("Push returned error after reset: %v", err)
	}
	if len(points) != 1 {
		t.Fatalf("expected one mutation point after reset and fresh record, got %d", len(points))
	}
	if points[0].TargetSeq != 1005 {
		t.Fatalf("unexpected target seq after reset: %d", points[0].TargetSeq)
	}
	if points[0].CreatedAt.IsZero() {
		t.Fatal("expected mutation point creation time to be recorded")
	}
}

func TestStateLargeRecordWithTrailingPrefixStillYieldsPoint(t *testing.T) {
	state := NewState(1000)
	data := make([]byte, 16384)
	for i := range data {
		data[i] = byte(i)
	}

	payload := append([]byte{0x17, 0x03, 0x03, 0x40, 0x00}, data...)
	payload = append(payload, 0x16, 0x03)

	points, err := state.Push(Segment{
		Seq:  1000,
		Data: payload,
	}, 0)
	if err != nil {
		t.Fatalf("Push returned error: %v", err)
	}
	if len(points) != 1 {
		t.Fatalf("expected one mutation point for max-size record with trailing prefix, got %d", len(points))
	}
	if points[0].TargetSeq != 1005 {
		t.Fatalf("unexpected target seq for max-size record with trailing prefix: %d", points[0].TargetSeq)
	}
	if points[0].CreatedAt.IsZero() {
		t.Fatal("expected mutation point creation time to be recorded")
	}
}

func TestStateDuplicateFutureSegmentDoesNotDoubleCount(t *testing.T) {
	state := NewState(1000)
	future := make([]byte, 3000)

	if _, err := state.Push(Segment{Seq: 5000, Data: future}, 0); err != nil {
		t.Fatalf("Push returned error: %v", err)
	}
	if _, err := state.Push(Segment{Seq: 5000, Data: future}, 0); err != nil {
		t.Fatalf("duplicate future segment should not trigger error: %v", err)
	}
}

func TestStatePartialOverlapFutureSegmentDoesNotDoubleCount(t *testing.T) {
	state := NewState(1000)
	first := make([]byte, 3000)
	second := make([]byte, 2000)

	if _, err := state.Push(Segment{Seq: 5000, Data: first}, 0); err != nil {
		t.Fatalf("Push returned error: %v", err)
	}
	if _, err := state.Push(Segment{Seq: 7000, Data: second}, 0); err != nil {
		t.Fatalf("partial overlap future segment should not trigger error: %v", err)
	}
}

func TestStateUsesMutateOffsetForSinglePacketApplicationData(t *testing.T) {
	state := NewState(1000)

	points, err := state.Push(Segment{
		Seq:  1000,
		Data: []byte{0x17, 0x03, 0x03, 0x00, 0x04, 0xaa, 0xbb, 0xcc, 0xdd},
	}, 2)
	if err != nil {
		t.Fatalf("Push returned error: %v", err)
	}
	if len(points) != 1 {
		t.Fatalf("expected one mutation point, got %d", len(points))
	}
	if points[0].TargetSeq != 1007 {
		t.Fatalf("expected target seq 1007 for mutate offset 2, got %d", points[0].TargetSeq)
	}
	if points[0].OldByte != 0xcc || points[0].NewByte != 0x33 {
		t.Fatalf("unexpected mutation bytes for mutate offset 2: %+v", points[0])
	}
}

func TestStateUsesMutateOffsetAcrossPackets(t *testing.T) {
	state := NewState(1000)

	points, err := state.Push(Segment{
		Seq:  1000,
		Data: []byte{0x17, 0x03, 0x03, 0x00, 0x04, 0xaa, 0xbb},
	}, 2)
	if err != nil {
		t.Fatalf("Push returned error: %v", err)
	}
	if len(points) != 0 {
		t.Fatalf("expected no mutation point before record is complete, got %d", len(points))
	}

	points, err = state.Push(Segment{
		Seq:  1007,
		Data: []byte{0xcc, 0xdd},
	}, 2)
	if err != nil {
		t.Fatalf("Push returned error: %v", err)
	}
	if len(points) != 1 {
		t.Fatalf("expected one mutation point after record completion, got %d", len(points))
	}
	if points[0].TargetSeq != 1007 {
		t.Fatalf("expected target seq 1007 for cross-packet mutate offset 2, got %d", points[0].TargetSeq)
	}
	if points[0].OldByte != 0xcc || points[0].NewByte != 0x33 {
		t.Fatalf("unexpected mutation bytes for cross-packet mutate offset 2: %+v", points[0])
	}
}

func TestStateSkipsTooShortApplicationDataForMutateOffset(t *testing.T) {
	state := NewState(1000)

	points, err := state.Push(Segment{
		Seq:  1000,
		Data: []byte{0x17, 0x03, 0x03, 0x00, 0x04, 0xaa, 0xbb, 0xcc, 0xdd},
	}, 4)
	if err != nil {
		t.Fatalf("Push returned error: %v", err)
	}
	if len(points) != 0 {
		t.Fatalf("expected too-short record to be skipped for mutate offset 4, got %d", len(points))
	}
}

func TestStateCanResyncAfterMiddleOfRecordPrefix(t *testing.T) {
	state := NewState(1000)

	// 模拟动态阻断句柄在连接中途接入：先看到一段非记录边界的密文前缀。
	points, err := state.Push(Segment{
		Seq:  1000,
		Data: []byte{0x88, 0x99, 0xaa, 0xbb, 0xcc},
	}, 0)
	if err != nil {
		t.Fatalf("Push returned error: %v", err)
	}
	if len(points) != 0 {
		t.Fatalf("expected no mutation point for middle-of-record prefix, got %d", len(points))
	}

	// 后续到达一个完整 application data record，重组器应能重新同步并产出破坏点。
	points, err = state.Push(Segment{
		Seq:  1005,
		Data: []byte{0x17, 0x03, 0x03, 0x00, 0x04, 0xaa, 0xbb, 0xcc, 0xdd},
	}, 0)
	if err != nil {
		t.Fatalf("Push returned error: %v", err)
	}
	if len(points) != 1 {
		t.Fatalf("expected one mutation point after resync, got %d", len(points))
	}
	if points[0].TargetSeq != 1010 {
		t.Fatalf("expected target seq 1010 after resync, got %d", points[0].TargetSeq)
	}
}
