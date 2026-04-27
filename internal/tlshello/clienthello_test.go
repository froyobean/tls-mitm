package tlshello

import (
	"bytes"
	"testing"
)

func TestParseClientHelloExtractsSNI(t *testing.T) {
	payload := buildClientHelloRecord(t, "Example.COM", true)

	name, ok := ParseServerName(payload)
	if !ok {
		t.Fatal("expected ParseServerName to extract SNI")
	}
	if name != "example.com" {
		t.Fatalf("unexpected server name: got %q want %q", name, "example.com")
	}
}

func TestParseClientHelloRejectsIncompleteRecord(t *testing.T) {
	payload := buildClientHelloRecord(t, "example.com", true)
	payload = payload[:len(payload)-1]

	if name, ok := ParseServerName(payload); ok {
		t.Fatalf("expected ParseServerName to reject incomplete record, got %q", name)
	}
}

func TestParseClientHelloRejectsNonClientHello(t *testing.T) {
	payload := buildHandshakeRecord(t, 0x02, bytes.Repeat([]byte{0x11}, 32))

	if name, ok := ParseServerName(payload); ok {
		t.Fatalf("expected ParseServerName to reject non-ClientHello, got %q", name)
	}
}

func TestParseClientHelloRejectsMissingServerNameExtension(t *testing.T) {
	payload := buildClientHelloRecord(t, "", false)

	if name, ok := ParseServerName(payload); ok {
		t.Fatalf("expected ParseServerName to reject missing server_name extension, got %q", name)
	}
}

func TestParseClientHelloRejectsInvalidRecordVersion(t *testing.T) {
	payload := buildHandshakeRecordWithVersion(t, 0x0100, 0x01, buildClientHelloBody(t, "example.com", true))

	if name, ok := ParseServerName(payload); ok {
		t.Fatalf("expected ParseServerName to reject invalid record version, got %q", name)
	}
}

func buildClientHelloRecord(t *testing.T, serverName string, includeServerName bool) []byte {
	t.Helper()

	body := buildClientHelloBody(t, serverName, includeServerName)
	return buildHandshakeRecord(t, 0x01, body)
}

func buildClientHelloBody(t *testing.T, serverName string, includeServerName bool) []byte {
	t.Helper()

	var body bytes.Buffer
	body.Write([]byte{0x03, 0x03})
	body.Write(bytes.Repeat([]byte{0x42}, 32))
	body.WriteByte(0x00)
	body.Write([]byte{0x00, 0x02})
	body.Write([]byte{0x13, 0x01})
	body.WriteByte(0x01)
	body.WriteByte(0x00)

	extensions := buildExtensions(t, serverName, includeServerName)
	body.WriteByte(byte(len(extensions) >> 8))
	body.WriteByte(byte(len(extensions)))
	body.Write(extensions)

	return body.Bytes()
}

func buildExtensions(t *testing.T, serverName string, includeServerName bool) []byte {
	t.Helper()

	if !includeServerName {
		return nil
	}

	host := []byte(serverName)
	var serverNameList bytes.Buffer
	serverNameList.WriteByte(0x00)
	writeUint16(t, &serverNameList, len(host))
	serverNameList.Write(host)

	var serverNameExtension bytes.Buffer
	writeUint16(t, &serverNameExtension, serverNameList.Len())
	serverNameExtension.Write(serverNameList.Bytes())

	var extensions bytes.Buffer
	writeUint16(t, &extensions, 0x0000)
	writeUint16(t, &extensions, serverNameExtension.Len())
	extensions.Write(serverNameExtension.Bytes())

	return extensions.Bytes()
}

func buildHandshakeRecord(t *testing.T, handshakeType byte, body []byte) []byte {
	t.Helper()

	return buildHandshakeRecordWithVersion(t, 0x0303, handshakeType, body)
}

func buildHandshakeRecordWithVersion(t *testing.T, version uint16, handshakeType byte, body []byte) []byte {
	t.Helper()

	var handshake bytes.Buffer
	handshake.WriteByte(handshakeType)
	writeUint24(t, &handshake, len(body))
	handshake.Write(body)

	var record bytes.Buffer
	record.WriteByte(0x16)
	writeUint16(t, &record, int(version))
	writeUint16(t, &record, handshake.Len())
	record.Write(handshake.Bytes())

	return record.Bytes()
}

func writeUint16(t *testing.T, buf *bytes.Buffer, value int) {
	t.Helper()

	if value < 0 || value > 0xffff {
		t.Fatalf("value out of range for uint16: %d", value)
	}

	buf.WriteByte(byte(value >> 8))
	buf.WriteByte(byte(value))
}

func writeUint24(t *testing.T, buf *bytes.Buffer, value int) {
	t.Helper()

	if value < 0 || value > 0xffffff {
		t.Fatalf("value out of range for uint24: %d", value)
	}

	buf.WriteByte(byte(value >> 16))
	buf.WriteByte(byte(value >> 8))
	buf.WriteByte(byte(value))
}
