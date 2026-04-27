package tcpmeta

import "testing"

func TestParseIPv4TCP(t *testing.T) {
	packet := makeIPv4TCPPacket([]byte("hello"))
	meta, err := ParseIPv4TCP(packet)
	if err != nil {
		t.Fatalf("ParseIPv4TCP returned error: %v", err)
	}
	if meta.PayloadOffset != 40 || string(meta.Payload) != "hello" {
		t.Fatalf("unexpected meta: %+v", meta)
	}
}

func TestParseIPv4TCPRejectsTruncatedIPv4Header(t *testing.T) {
	packet := []byte{0x45, 0x00, 0x00, 0x14}
	if _, err := ParseIPv4TCP(packet); err == nil {
		t.Fatal("expected error for truncated IPv4 header")
	}
}

func TestParseIPv4TCPRejectsTruncatedTCPHeader(t *testing.T) {
	packet := makeIPv4TCPPacket([]byte("hello"))
	packet = packet[:30]
	packet[2] = 0x00
	packet[3] = byte(len(packet))
	if _, err := ParseIPv4TCP(packet); err == nil {
		t.Fatal("expected error for truncated TCP header")
	}
}

func TestParseIPv4TCPRejectsFragmentedPacket(t *testing.T) {
	packet := makeIPv4TCPPacket([]byte("hello"))
	packet[6] = 0x20
	packet[7] = 0x00
	if _, err := ParseIPv4TCP(packet); err == nil {
		t.Fatal("expected error for IPv4 fragment")
	}
}

func TestParseIPv4TCPRejectsNonTCPPacket(t *testing.T) {
	packet := makeIPv4TCPPacket([]byte("hello"))
	packet[9] = 17
	if _, err := ParseIPv4TCP(packet); err == nil {
		t.Fatal("expected error for non-TCP packet")
	}
}

func makeIPv4TCPPacket(payload []byte) []byte {
	packet := make([]byte, 40+len(payload))
	packet[0] = 0x45
	totalLen := 40 + len(payload)
	packet[2] = byte(totalLen >> 8)
	packet[3] = byte(totalLen)
	packet[9] = 6
	packet[12] = 10
	packet[13] = 0
	packet[14] = 0
	packet[15] = 1
	packet[16] = 10
	packet[17] = 0
	packet[18] = 0
	packet[19] = 2
	packet[20] = 0xc3
	packet[21] = 0x50
	packet[22] = 0x01
	packet[23] = 0xbb
	packet[32] = 0x50
	copy(packet[40:], payload)
	return packet
}
