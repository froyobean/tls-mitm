package mutate

import (
	"testing"

	"tls-mitm/internal/reassembly"
	"tls-mitm/internal/tlsrecord"
)

func TestFlipCiphertextByte(t *testing.T) {
	payload := []byte{0x17, 0x03, 0x03, 0x00, 0x04, 0xaa, 0xbb, 0xcc, 0xdd}
	rec, _ := tlsrecord.FindFirstCompleteApplicationData(payload)
	m, err := FlipCiphertextByte(payload, rec, 1)
	if err != nil || m.PayloadIndex != 6 || payload[6] != 0x44 {
		t.Fatalf("unexpected mutation: %+v err=%v payload=%x", m, err, payload)
	}
}

func TestFlipCiphertextByteRejectsNegativeOffset(t *testing.T) {
	payload := []byte{0x17, 0x03, 0x03, 0x00, 0x04, 0xaa, 0xbb, 0xcc, 0xdd}
	rec, _ := tlsrecord.FindFirstCompleteApplicationData(payload)
	if _, err := FlipCiphertextByte(payload, rec, -1); err == nil {
		t.Fatal("expected negative offset to fail")
	}
}

func TestFlipCiphertextByteRejectsOutOfRangeOffset(t *testing.T) {
	payload := []byte{0x17, 0x03, 0x03, 0x00, 0x04, 0xaa, 0xbb, 0xcc, 0xdd}
	rec, _ := tlsrecord.FindFirstCompleteApplicationData(payload)
	if _, err := FlipCiphertextByte(payload, rec, rec.DataLen); err == nil {
		t.Fatal("expected out-of-range offset to fail")
	}
}

func TestApplyMutationPointMutatesCoveredSequence(t *testing.T) {
	payload := []byte{0xaa, 0xbb, 0xcc, 0xdd}
	point := reassembly.MutationPoint{
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
	point := reassembly.MutationPoint{
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

func TestApplyMutationPointSkipsPacketWithoutTargetSequence(t *testing.T) {
	payload := []byte{0xaa, 0xbb}
	point := reassembly.MutationPoint{
		TargetSeq: 2005,
		OldByte:   0xcc,
		NewByte:   0x33,
	}

	if _, ok := ApplyMutationPoint(payload, 2000, point); ok {
		t.Fatal("expected packet without target sequence to remain untouched")
	}
}
