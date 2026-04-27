package tlsrecord

import "testing"

func TestFindFirstCompleteApplicationData(t *testing.T) {
	payload := []byte{0x16, 0x03, 0x03, 0x00, 0x02, 0x01, 0x02, 0x17, 0x03, 0x03, 0x00, 0x04, 0xaa, 0xbb, 0xcc, 0xdd}
	rec, ok := FindFirstCompleteApplicationData(payload)
	if !ok || rec.Start != 7 || rec.DataLen != 4 {
		t.Fatalf("unexpected record: %+v", rec)
	}
}

func TestFindFirstCompleteApplicationDataRejectsIncompleteRecord(t *testing.T) {
	payload := []byte{0x17, 0x03, 0x03, 0x00, 0x04, 0xaa, 0xbb}
	if rec, ok := FindFirstCompleteApplicationData(payload); ok {
		t.Fatalf("expected incomplete record to be rejected, got %+v", rec)
	}
}

func TestFindFirstCompleteApplicationDataSkipsInvalidContentType(t *testing.T) {
	payload := []byte{0x7f, 0x03, 0x03, 0x00, 0x01, 0x00, 0x17, 0x03, 0x03, 0x00, 0x02, 0xaa, 0xbb}
	rec, ok := FindFirstCompleteApplicationData(payload)
	if !ok || rec.Start != 6 || rec.DataLen != 2 {
		t.Fatalf("unexpected record after invalid type: %+v", rec)
	}
}

func TestFindFirstCompleteApplicationDataSkipsInvalidVersion(t *testing.T) {
	payload := []byte{0x17, 0x01, 0x01, 0x00, 0x01, 0x00, 0x17, 0x03, 0x03, 0x00, 0x02, 0xaa, 0xbb}
	rec, ok := FindFirstCompleteApplicationData(payload)
	if !ok || rec.Start != 6 || rec.DataLen != 2 {
		t.Fatalf("unexpected record after invalid version: %+v", rec)
	}
}

func TestFindFirstCompleteApplicationDataSkipsOversizedPseudoHeader(t *testing.T) {
	payload := []byte{
		0x17, 0x03, 0x03, 0x00, 0x20,
		0x00, 0x00,
		0x17, 0x03, 0x03, 0x00, 0x02, 0xaa, 0xbb,
	}
	rec, ok := FindFirstCompleteApplicationData(payload)
	if !ok || rec.Start != 7 || rec.DataLen != 2 {
		t.Fatalf("unexpected record after oversized pseudo header: %+v", rec)
	}
}

func TestFindFirstCompleteRecord(t *testing.T) {
	payload := []byte{0x16, 0x03, 0x03, 0x00, 0x02, 0x01, 0x02}
	rec, ok := FindFirstCompleteRecord(payload)
	if !ok || rec.Start != 0 || rec.Type != 0x16 || rec.DataLen != 2 {
		t.Fatalf("unexpected record: %+v", rec)
	}
}

func TestScanFirstCompleteRecordReportsNeedMoreBeforeLaterPseudoHeader(t *testing.T) {
	payload := []byte{0x00, 0x17, 0x03, 0x03, 0x00, 0x17, 0x03, 0x03, 0x00, 0x02, 0xaa, 0xbb}
	rec, status := ScanFirstCompleteRecord(payload)
	if status != ScanNeedMore {
		t.Fatalf("expected need more, got %v", status)
	}
	if rec.Start != 1 {
		t.Fatalf("unexpected incomplete header offset: %+v", rec)
	}
}

func TestScanFirstCompleteRecordReportsNeedMoreForOversizedPseudoHeader(t *testing.T) {
	payload := []byte{
		0x17, 0x03, 0x03, 0x00, 0x20,
		0x00, 0x00,
		0x17, 0x03, 0x03, 0x00, 0x02, 0xaa, 0xbb,
	}
	rec, status := ScanFirstCompleteRecord(payload)
	if status != ScanNeedMore {
		t.Fatalf("expected need more for oversized pseudo header, got %v", status)
	}
	if rec.Start != 0 {
		t.Fatalf("unexpected header offset for oversized pseudo header: %+v", rec)
	}
}

func TestFindFirstCompleteRecordReportsNeedMoreForOversizedPseudoHeader(t *testing.T) {
	payload := []byte{
		0x17, 0x03, 0x03, 0x00, 0x20,
		0x00, 0x00,
		0x17, 0x03, 0x03, 0x00, 0x02, 0xaa, 0xbb,
	}
	rec, ok := FindFirstCompleteRecord(payload)
	if ok {
		t.Fatalf("expected oversized pseudo header to require more data, got %+v", rec)
	}
}
