package reassembly

import (
	"errors"
	"sort"
	"time"

	"tls-mitm/internal/tlsrecord"
)

const (
	maxBufferedSegments = 16
	maxBufferedBytes    = 4096
	maxStreamBytes      = 16384 + 5
)

// ErrBufferLimitExceeded 表示重组缓冲触发了保守上限并已重置。
var ErrBufferLimitExceeded = errors.New("重组缓冲超过上限")

// Segment 描述一段带有绝对序号的出站 TCP 数据。
type Segment struct {
	Seq  uint32
	Data []byte
}

// MutationPoint 描述一条可用于后续 record 级篡改的定位点。
type MutationPoint struct {
	RecordStartSeq uint32
	TargetSeq      uint32
	RecordLength   int
	OldByte        byte
	NewByte        byte
	CreatedAt      time.Time
}

// State 维护最小化的出站重组状态。
type State struct {
	nextSeq     uint32
	queue       []Segment
	stream      []byte
	queueBytes  int
	streamBytes int
}

// NewState 创建一个新的重组状态机。
func NewState(initialSeq uint32) *State {
	return &State{nextSeq: initialSeq}
}

// NextSeq 返回当前期望的下一个序号。
func (s *State) NextSeq() uint32 {
	return s.nextSeq
}

// Push 接收一个分段，先缓冲，再尽量拼成连续流并提取完整 record 的 mutation point。
func (s *State) Push(seg Segment, mutateOffset int) ([]MutationPoint, error) {
	if len(seg.Data) == 0 {
		return nil, nil
	}

	if seg.Seq < s.nextSeq {
		skip := s.nextSeq - seg.Seq
		if skip >= uint32(len(seg.Data)) {
			return s.collectMutationPoints(mutateOffset), nil
		}
		seg.Data = seg.Data[skip:]
		seg.Seq = s.nextSeq
	}

	s.queueBytes += s.insertFutureSegment(seg)
	s.drainContiguousSegments()
	if s.isQueueOverLimit() {
		s.resetBuffers()
		return nil, ErrBufferLimitExceeded
	}

	points := s.collectMutationPoints(mutateOffset)
	if s.isQueueOverLimit() || s.streamBytes > maxStreamBytes {
		s.resetBuffers()
		return nil, ErrBufferLimitExceeded
	}
	return points, nil
}

func (s *State) insertFutureSegment(seg Segment) int {
	if len(seg.Data) == 0 {
		return 0
	}

	start := uint64(seg.Seq)
	end := start + uint64(len(seg.Data))
	idx := sort.Search(len(s.queue), func(i int) bool {
		return segmentEnd(s.queue[i]) >= start
	})

	if idx == len(s.queue) || uint64(s.queue[idx].Seq) > end {
		s.queue = append(s.queue, Segment{})
		copy(s.queue[idx+1:], s.queue[idx:])
		s.queue[idx] = seg
		return len(seg.Data)
	}

	mergeStart := min64(start, uint64(s.queue[idx].Seq))
	mergeEnd := end
	mergeEndIdx := idx
	existingLen := 0
	for mergeEndIdx < len(s.queue) {
		q := s.queue[mergeEndIdx]
		qStart := uint64(q.Seq)
		if qStart > mergeEnd {
			break
		}

		qEnd := segmentEnd(q)
		if qEnd > mergeEnd {
			mergeEnd = qEnd
		}
		if qStart < mergeStart {
			mergeStart = qStart
		}
		existingLen += len(q.Data)
		mergeEndIdx++
	}

	mergedLen := int(mergeEnd - mergeStart)
	mergedData := make([]byte, mergedLen)
	for i := idx; i < mergeEndIdx; i++ {
		q := s.queue[i]
		copy(mergedData[int(uint64(q.Seq)-mergeStart):], q.Data)
	}
	copy(mergedData[int(start-mergeStart):], seg.Data)

	s.queue = append(s.queue[:idx], s.queue[mergeEndIdx:]...)
	s.queue = append(s.queue, Segment{})
	copy(s.queue[idx+1:], s.queue[idx:])
	s.queue[idx] = Segment{Seq: uint32(mergeStart), Data: mergedData}

	return mergedLen - existingLen
}

func (s *State) drainContiguousSegments() {
	for len(s.queue) > 0 {
		seg := s.queue[0]
		if seg.Seq > s.nextSeq {
			return
		}

		originalLen := len(seg.Data)
		if seg.Seq < s.nextSeq {
			skip := s.nextSeq - seg.Seq
			if skip >= uint32(originalLen) {
				s.queueBytes -= originalLen
				s.queue = s.queue[1:]
				continue
			}
			seg.Data = seg.Data[skip:]
			seg.Seq = s.nextSeq
		}

		if seg.Seq != s.nextSeq {
			return
		}

		trimmedLen := len(seg.Data)
		s.stream = append(s.stream, seg.Data...)
		s.streamBytes += trimmedLen
		s.queueBytes -= originalLen
		s.nextSeq += uint32(trimmedLen)
		s.queue = s.queue[1:]
	}
}

func (s *State) collectMutationPoints(mutateOffset int) []MutationPoint {
	var points []MutationPoint

	for len(s.stream) > 0 {
		rec, status := tlsrecord.ScanFirstCompleteRecord(s.stream)
		switch status {
		case tlsrecord.ScanFound:
			if rec.Start > 0 {
				s.consumeStreamPrefix(rec.Start)
				continue
			}
			if rec.Type == 0x17 {
				baseSeq := s.nextSeq - uint32(len(s.stream))
				targetIndex := rec.DataStart + mutateOffset
				if mutateOffset >= 0 && mutateOffset < rec.DataLen && targetIndex >= rec.DataStart && targetIndex < len(s.stream) {
					now := time.Now()
					oldByte := s.stream[targetIndex]
					points = append(points, MutationPoint{
						RecordStartSeq: baseSeq + uint32(rec.Start),
						TargetSeq:      baseSeq + uint32(targetIndex),
						RecordLength:   rec.TotalLen,
						OldByte:        oldByte,
						NewByte:        oldByte ^ 0xff,
						CreatedAt:      now,
					})
				}
			}
			s.consumeStreamPrefix(rec.TotalLen)
		case tlsrecord.ScanNeedMore:
			return points
		case tlsrecord.ScanInvalidPrefix:
			if rec.Start == 0 {
				return points
			}
			s.consumeStreamPrefix(rec.Start)
		}
	}

	return points
}

func (s *State) consumeStreamPrefix(n int) {
	if n <= 0 {
		return
	}
	if n > len(s.stream) {
		n = len(s.stream)
	}
	s.stream = s.stream[n:]
	s.streamBytes -= n
	if s.streamBytes < 0 {
		s.streamBytes = 0
	}
}

func (s *State) isQueueOverLimit() bool {
	if len(s.queue) > maxBufferedSegments {
		return true
	}
	return s.queueBytes > maxBufferedBytes
}

func (s *State) resetBuffers() {
	s.queue = nil
	s.stream = nil
	s.queueBytes = 0
	s.streamBytes = 0
}

func segmentEnd(seg Segment) uint64 {
	return uint64(seg.Seq) + uint64(len(seg.Data))
}

func min64(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}
