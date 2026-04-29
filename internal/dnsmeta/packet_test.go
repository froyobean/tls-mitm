package dnsmeta

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

func TestParseIPv4UDPResponseExtractsARecord(t *testing.T) {
	packet := ipv4UDPDNSResponseForTest("www.example.com", "93.184.216.34", 300)
	answers, err := ParseIPv4UDPResponse(packet)
	if err != nil {
		t.Fatalf("ParseIPv4UDPResponse returned error: %v", err)
	}
	if len(answers) != 1 {
		t.Fatalf("expected one answer, got %d", len(answers))
	}
	if answers[0].Name != "www.example.com" || answers[0].IP != netip.MustParseAddr("93.184.216.34") || answers[0].TTL != 300*time.Second {
		t.Fatalf("unexpected answer: %+v", answers[0])
	}
}

func TestParseIPv4UDPResponseSupportsCompressedAnswerName(t *testing.T) {
	packet := ipv4UDPDNSResponseForTest("WWW.Example.COM.", "93.184.216.34", 60)
	answers, err := ParseIPv4UDPResponse(packet)
	if err != nil {
		t.Fatalf("ParseIPv4UDPResponse returned error: %v", err)
	}
	if answers[0].Name != "www.example.com" {
		t.Fatalf("expected normalized host, got %q", answers[0].Name)
	}
}

func TestParseIPv4UDPResponseIgnoresQueryPacket(t *testing.T) {
	packet := ipv4UDPQueryForTest("www.example.com")
	answers, err := ParseIPv4UDPResponse(packet)
	if err != nil {
		t.Fatalf("ParseIPv4UDPResponse returned error: %v", err)
	}
	if len(answers) != 0 {
		t.Fatalf("expected no answers for query packet, got %+v", answers)
	}
}

func TestParseIPv4UDPResponseRejectsMalformedPacket(t *testing.T) {
	if _, err := ParseIPv4UDPResponse([]byte{0x45, 0x00}); err == nil {
		t.Fatal("expected malformed packet error")
	}
}

func TestParseIPv4UDPResponseRejectsTruncatedAnswerRData(t *testing.T) {
	packet := ipv4UDPDNSTruncatedAnswerForTest("www.example.com", "93.184.216.34", 300)
	if _, err := ParseIPv4UDPResponse(packet); err == nil {
		t.Fatal("expected truncated answer error")
	}
}

func TestParseIPv4UDPResponseRejectsOutOfRangeCompressionPointer(t *testing.T) {
	packet := ipv4UDPDNSBadCompressionPointerForTest()
	if _, err := ParseIPv4UDPResponse(packet); err == nil {
		t.Fatal("expected bad compression pointer error")
	}
}

func TestParseIPv4UDPResponseRejectsCompressionPointerLoop(t *testing.T) {
	packet := ipv4UDPDNSCompressionPointerLoopForTest()
	if _, err := ParseIPv4UDPResponse(packet); err == nil {
		t.Fatal("expected compression pointer loop error")
	}
}

func TestParseIPv4UDPResponseRejectsNonResponseSourcePort(t *testing.T) {
	packet := ipv4UDPQueryForNonResponseSourcePortTest("www.example.com")
	if _, err := ParseIPv4UDPResponse(packet); err == nil {
		t.Fatal("expected non-DNS-response source port error")
	}
}

func TestParseIPv4UDPResponseResolvesCNAMEChain(t *testing.T) {
	packet := ipv4UDPDNSCNAMEForTest("www.example.com", "cdn.example.net", "93.184.216.34", 120)
	answers, err := ParseIPv4UDPResponse(packet)
	if err != nil {
		t.Fatalf("ParseIPv4UDPResponse returned error: %v", err)
	}
	if len(answers) != 2 {
		t.Fatalf("expected cname target and alias answer, got %+v", answers)
	}
	if answers[0].Name != "cdn.example.net" || answers[1].Name != "www.example.com" {
		t.Fatalf("expected cname chain answers, got %+v", answers)
	}
}

func TestParseIPv4UDPResponseResolvesMultiHopCNAMEChain(t *testing.T) {
	packet := ipv4UDPDNSMultiHopCNAMEForTest("www.example.com", "edge.example.net", "origin.example.net", "93.184.216.34", 180, 90, 300)
	answers, err := ParseIPv4UDPResponse(packet)
	if err != nil {
		t.Fatalf("ParseIPv4UDPResponse returned error: %v", err)
	}
	if len(answers) != 3 {
		t.Fatalf("expected three answers for multi-hop cname chain, got %+v", answers)
	}
	if answers[0].Name != "origin.example.net" || answers[1].Name != "edge.example.net" || answers[2].Name != "www.example.com" {
		t.Fatalf("expected full cname chain answers, got %+v", answers)
	}
}

func TestParseIPv4UDPResponseUsesMinimumTTLAcrossCNAMEChain(t *testing.T) {
	packet := ipv4UDPDNSCNAMEForTestWithTTLs("www.example.com", "cdn.example.net", "93.184.216.34", 60, 300)
	answers, err := ParseIPv4UDPResponse(packet)
	if err != nil {
		t.Fatalf("ParseIPv4UDPResponse returned error: %v", err)
	}
	if len(answers) != 2 {
		t.Fatalf("expected cname target and alias answer, got %+v", answers)
	}
	if answers[0].TTL != 300*time.Second {
		t.Fatalf("expected canonical A TTL 300s, got %s", answers[0].TTL)
	}
	if answers[1].TTL != 60*time.Second {
		t.Fatalf("expected alias TTL 60s, got %s", answers[1].TTL)
	}
}

func ipv4UDPDNSResponseForTest(host, ip string, ttl uint32) []byte {
	question := encodeDNSNameForTest(host)
	question = append(question, 0x00, 0x01, 0x00, 0x01)
	answer := []byte{0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, byte(ttl >> 24), byte(ttl >> 16), byte(ttl >> 8), byte(ttl), 0x00, 0x04}
	as4 := netip.MustParseAddr(ip).As4()
	answer = append(answer, as4[:]...)
	dns := []byte{0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}
	dns = append(dns, question...)
	dns = append(dns, answer...)
	return ipv4UDPForTest([4]byte{8, 8, 8, 8}, [4]byte{10, 0, 0, 2}, 53, 53000, dns)
}

func ipv4UDPDNSCNAMEForTest(alias, canonical, ip string, ttl uint32) []byte {
	return ipv4UDPDNSCNAMEForTestWithTTLs(alias, canonical, ip, ttl, ttl)
}

func ipv4UDPDNSCNAMEForTestWithTTLs(alias, canonical, ip string, cnameTTL, aTTL uint32) []byte {
	question := encodeDNSNameForTest(alias)
	question = append(question, 0x00, 0x01, 0x00, 0x01)

	cnameRData := encodeDNSNameForTest(canonical)
	cname := []byte{0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, byte(cnameTTL >> 24), byte(cnameTTL >> 16), byte(cnameTTL >> 8), byte(cnameTTL)}
	cname = append(cname, byte(len(cnameRData)>>8), byte(len(cnameRData)))
	cname = append(cname, cnameRData...)

	canonicalName := encodeDNSNameForTest(canonical)
	a := append([]byte{}, canonicalName...)
	a = append(a, 0x00, 0x01, 0x00, 0x01, byte(aTTL>>24), byte(aTTL>>16), byte(aTTL>>8), byte(aTTL), 0x00, 0x04)
	as4 := netip.MustParseAddr(ip).As4()
	a = append(a, as4[:]...)

	dns := []byte{0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00}
	dns = append(dns, question...)
	dns = append(dns, cname...)
	dns = append(dns, a...)
	return ipv4UDPForTest([4]byte{8, 8, 8, 8}, [4]byte{10, 0, 0, 2}, 53, 53000, dns)
}

func ipv4UDPDNSMultiHopCNAMEForTest(alias, middle, canonical, ip string, aliasTTL, middleTTL, aTTL uint32) []byte {
	question := encodeDNSNameForTest(alias)
	question = append(question, 0x00, 0x01, 0x00, 0x01)

	firstRData := encodeDNSNameForTest(middle)
	first := []byte{0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, byte(aliasTTL >> 24), byte(aliasTTL >> 16), byte(aliasTTL >> 8), byte(aliasTTL)}
	first = append(first, byte(len(firstRData)>>8), byte(len(firstRData)))
	first = append(first, firstRData...)

	middleName := encodeDNSNameForTest(middle)
	second := append([]byte{}, middleName...)
	secondRData := encodeDNSNameForTest(canonical)
	second = append(second, 0x00, 0x05, 0x00, 0x01, byte(middleTTL>>24), byte(middleTTL>>16), byte(middleTTL>>8), byte(middleTTL))
	second = append(second, byte(len(secondRData)>>8), byte(len(secondRData)))
	second = append(second, secondRData...)

	canonicalName := encodeDNSNameForTest(canonical)
	a := append([]byte{}, canonicalName...)
	a = append(a, 0x00, 0x01, 0x00, 0x01, byte(aTTL>>24), byte(aTTL>>16), byte(aTTL>>8), byte(aTTL), 0x00, 0x04)
	as4 := netip.MustParseAddr(ip).As4()
	a = append(a, as4[:]...)

	dns := []byte{0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00}
	dns = append(dns, question...)
	dns = append(dns, first...)
	dns = append(dns, second...)
	dns = append(dns, a...)
	return ipv4UDPForTest([4]byte{8, 8, 8, 8}, [4]byte{10, 0, 0, 2}, 53, 53000, dns)
}

func ipv4UDPQueryForTest(host string) []byte {
	question := encodeDNSNameForTest(host)
	question = append(question, 0x00, 0x01, 0x00, 0x01)
	dns := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	dns = append(dns, question...)
	return ipv4UDPForTest([4]byte{8, 8, 8, 8}, [4]byte{10, 0, 0, 2}, 53, 53000, dns)
}

func ipv4UDPQueryForNonResponseSourcePortTest(host string) []byte {
	question := encodeDNSNameForTest(host)
	question = append(question, 0x00, 0x01, 0x00, 0x01)
	dns := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	dns = append(dns, question...)
	return ipv4UDPForTest([4]byte{10, 0, 0, 2}, [4]byte{8, 8, 8, 8}, 53000, 53, dns)
}

func ipv4UDPDNSTruncatedAnswerForTest(host, ip string, ttl uint32) []byte {
	packet := ipv4UDPDNSResponseForTest(host, ip, ttl)
	return packet[:len(packet)-1]
}

func ipv4UDPDNSBadCompressionPointerForTest() []byte {
	dns := []byte{
		0x12, 0x34, 0x81, 0x80,
		0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00,
		0xc0, 0xff,
		0x00, 0x01, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x3c,
		0x00, 0x04,
		93, 184, 216, 34,
	}
	return ipv4UDPForTest([4]byte{8, 8, 8, 8}, [4]byte{10, 0, 0, 2}, 53, 53000, dns)
}

func ipv4UDPDNSCompressionPointerLoopForTest() []byte {
	dns := []byte{
		0x12, 0x34, 0x81, 0x80,
		0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00,
		0xc0, 0x0c,
		0x00, 0x01, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x3c,
		0x00, 0x04,
		93, 184, 216, 34,
	}
	return ipv4UDPForTest([4]byte{8, 8, 8, 8}, [4]byte{10, 0, 0, 2}, 53, 53000, dns)
}

func ipv4UDPForTest(srcIP, dstIP [4]byte, srcPort, dstPort uint16, payload []byte) []byte {
	const ipHeaderLen = 20
	const udpHeaderLen = 8

	packet := make([]byte, ipHeaderLen+udpHeaderLen+len(payload))
	packet[0] = 0x45
	packet[8] = 64
	packet[9] = 17
	copy(packet[12:16], srcIP[:])
	copy(packet[16:20], dstIP[:])
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	binary.BigEndian.PutUint16(packet[ipHeaderLen:ipHeaderLen+2], srcPort)
	binary.BigEndian.PutUint16(packet[ipHeaderLen+2:ipHeaderLen+4], dstPort)
	binary.BigEndian.PutUint16(packet[ipHeaderLen+4:ipHeaderLen+6], uint16(udpHeaderLen+len(payload)))
	copy(packet[ipHeaderLen+udpHeaderLen:], payload)
	return packet
}

func encodeDNSNameForTest(host string) []byte {
	host = normalizeNameForTest(host)
	if host == "" {
		return []byte{0x00}
	}
	var encoded []byte
	labelStart := 0
	for i := 0; i <= len(host); i++ {
		if i != len(host) && host[i] != '.' {
			continue
		}
		label := host[labelStart:i]
		encoded = append(encoded, byte(len(label)))
		encoded = append(encoded, label...)
		labelStart = i + 1
	}
	return append(encoded, 0x00)
}

func normalizeNameForTest(name string) string {
	for len(name) > 0 && name[len(name)-1] == '.' {
		name = name[:len(name)-1]
	}
	return stringLowerForTest(name)
}

func stringLowerForTest(name string) string {
	buf := []byte(name)
	for i, b := range buf {
		if 'A' <= b && b <= 'Z' {
			buf[i] = b + ('a' - 'A')
		}
	}
	return string(buf)
}
