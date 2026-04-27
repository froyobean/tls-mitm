// Package tlsrecord 提供最小化的 TLS record 边界识别能力。
package tlsrecord

// Record 描述当前 TCP payload 中一条完整 TLS record 的边界信息。
type Record struct {
	Start, HeaderLen, DataStart, DataLen, TotalLen int
	Type                                           byte
	Version                                        uint16
}

// ScanResult 描述对 payload 的记录扫描结果。
type ScanResult uint8

const (
	// ScanFound 表示找到了完整 record。
	ScanFound ScanResult = iota
	// ScanNeedMore 表示当前看起来存在合法头部，但字节还不够。
	ScanNeedMore
	// ScanInvalidPrefix 表示当前位置没有合法头部，可安全滑动跳过前缀。
	ScanInvalidPrefix
)

// ScanFirstCompleteRecord 扫描 payload，区分完整 record、需要更多字节和无效前缀三种状态。
func ScanFirstCompleteRecord(payload []byte) (Record, ScanResult) {
	const headerLen = 5

	for offset := 0; offset+headerLen <= len(payload); offset++ {
		contentType := payload[offset]
		version := uint16(payload[offset+1])<<8 | uint16(payload[offset+2])
		if !isValidContentType(contentType) || !isValidVersion(version) {
			continue
		}

		recLen := int(payload[offset+3])<<8 | int(payload[offset+4])
		totalLen := headerLen + recLen
		if offset+totalLen > len(payload) {
			return Record{
				Start:     offset,
				HeaderLen: headerLen,
				DataStart: offset + headerLen,
				DataLen:   recLen,
				TotalLen:  totalLen,
				Type:      contentType,
				Version:   version,
			}, ScanNeedMore
		}

		return Record{
			Start:     offset,
			HeaderLen: headerLen,
			DataStart: offset + headerLen,
			DataLen:   recLen,
			TotalLen:  totalLen,
			Type:      contentType,
			Version:   version,
		}, ScanFound
	}

	if len(payload) < headerLen {
		return Record{}, ScanNeedMore
	}

	return Record{Start: len(payload) - (headerLen - 1)}, ScanInvalidPrefix
}

// FindFirstCompleteRecord 返回 payload 中第一条完整的 TLS record。
func FindFirstCompleteRecord(payload []byte) (Record, bool) {
	rec, status := ScanFirstCompleteRecord(payload)
	return rec, status == ScanFound
}

// FindFirstCompleteApplicationData 返回 payload 中第一条完整的 Application Data record。
func FindFirstCompleteApplicationData(payload []byte) (Record, bool) {
	const headerLen = 5

	for offset := 0; offset+headerLen <= len(payload); {
		contentType := payload[offset]
		version := uint16(payload[offset+1])<<8 | uint16(payload[offset+2])
		if !isValidContentType(contentType) || !isValidVersion(version) {
			offset++
			continue
		}

		recLen := int(payload[offset+3])<<8 | int(payload[offset+4])
		totalLen := headerLen + recLen
		if offset+totalLen > len(payload) {
			offset++
			continue
		}

		rec := Record{
			Start:     offset,
			HeaderLen: headerLen,
			DataStart: offset + headerLen,
			DataLen:   recLen,
			TotalLen:  totalLen,
			Type:      contentType,
			Version:   version,
		}
		if rec.Type == 0x17 {
			return rec, true
		}

		offset += totalLen
	}

	return Record{}, false
}

func isValidContentType(contentType byte) bool {
	return contentType >= 20 && contentType <= 24
}

func isValidVersion(version uint16) bool {
	return version >= 0x0300 && version <= 0x0304
}
