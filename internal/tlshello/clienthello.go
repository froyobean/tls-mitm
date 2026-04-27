package tlshello

import "strings"

const (
	tlsRecordTypeHandshake      = 0x16
	tlsHandshakeTypeClientHello = 0x01
	tlsExtensionServerName      = 0x0000
	tlsServerNameHostName       = 0x00
)

// ParseServerName 从单个 TCP payload 中完整可见的 TLS ClientHello 中提取 SNI。
// 当 payload 不包含完整的 Handshake record、不是 ClientHello，或缺少 server_name 扩展时，返回 false。
func ParseServerName(payload []byte) (string, bool) {
	if len(payload) < 5 {
		return "", false
	}
	if payload[0] != tlsRecordTypeHandshake {
		return "", false
	}
	if !isValidTLSRecordVersion(payload[1], payload[2]) {
		return "", false
	}

	recordLen := int(payload[3])<<8 | int(payload[4])
	if len(payload) < 5+recordLen {
		return "", false
	}

	record := payload[5 : 5+recordLen]
	if len(record) < 4 {
		return "", false
	}
	if record[0] != tlsHandshakeTypeClientHello {
		return "", false
	}

	handshakeLen := int(record[1])<<16 | int(record[2])<<8 | int(record[3])
	if len(record) < 4+handshakeLen {
		return "", false
	}

	body := record[4 : 4+handshakeLen]
	name, ok := parseClientHelloBody(body)
	if !ok {
		return "", false
	}
	return strings.ToLower(name), true
}

func isValidTLSRecordVersion(major, minor byte) bool {
	if major != 0x03 {
		return false
	}
	return minor >= 0x01 && minor <= 0x04
}

func parseClientHelloBody(body []byte) (string, bool) {
	if len(body) < 2+32+1+2+1+2 {
		return "", false
	}

	offset := 0
	offset += 2  // legacy_version
	offset += 32 // random

	sessionIDLen := int(body[offset])
	offset++
	if len(body) < offset+sessionIDLen+2+1+2 {
		return "", false
	}
	offset += sessionIDLen

	cipherSuitesLen := int(body[offset])<<8 | int(body[offset+1])
	offset += 2
	if cipherSuitesLen%2 != 0 || len(body) < offset+cipherSuitesLen+1+2 {
		return "", false
	}
	offset += cipherSuitesLen

	compressionMethodsLen := int(body[offset])
	offset++
	if len(body) < offset+compressionMethodsLen+2 {
		return "", false
	}
	offset += compressionMethodsLen

	if len(body) == offset {
		return "", false
	}
	if len(body) < offset+2 {
		return "", false
	}

	extensionsLen := int(body[offset])<<8 | int(body[offset+1])
	offset += 2
	if len(body) < offset+extensionsLen {
		return "", false
	}

	extensions := body[offset : offset+extensionsLen]
	return parseExtensions(extensions)
}

func parseExtensions(extensions []byte) (string, bool) {
	for offset := 0; offset+4 <= len(extensions); {
		extType := int(extensions[offset])<<8 | int(extensions[offset+1])
		extLen := int(extensions[offset+2])<<8 | int(extensions[offset+3])
		offset += 4
		if len(extensions) < offset+extLen {
			return "", false
		}

		if extType == tlsExtensionServerName {
			name, ok := parseServerNameExtension(extensions[offset : offset+extLen])
			if ok {
				return name, true
			}
			return "", false
		}

		offset += extLen
	}

	return "", false
}

func parseServerNameExtension(extension []byte) (string, bool) {
	if len(extension) < 2 {
		return "", false
	}

	listLen := int(extension[0])<<8 | int(extension[1])
	if len(extension) < 2+listLen {
		return "", false
	}

	list := extension[2 : 2+listLen]
	for offset := 0; offset+3 <= len(list); {
		nameType := list[offset]
		nameLen := int(list[offset+1])<<8 | int(list[offset+2])
		offset += 3
		if len(list) < offset+nameLen {
			return "", false
		}

		if nameType == tlsServerNameHostName {
			name := string(list[offset : offset+nameLen])
			if name == "" {
				return "", false
			}
			return name, true
		}

		offset += nameLen
	}

	return "", false
}