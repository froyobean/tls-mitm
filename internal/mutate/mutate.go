// Package mutate 提供 TLS 密文字节翻转策略。
package mutate

import (
	"fmt"

	"tls-mitm/internal/reassembly"
	"tls-mitm/internal/tlsrecord"
)

// Mutation 描述一次对 payload 的实际字节修改结果。
type Mutation struct {
	PayloadIndex int
	OldByte      byte
	NewByte      byte
}

// AppliedMutation 记录一次按绝对序列号施加的篡改结果。
type AppliedMutation struct {
	PayloadIndex int
	TargetSeq    uint32
	OldByte      byte
	NewByte      byte
}

// FlipCiphertextByte 按给定偏移翻转 record 数据区中的一个字节。
func FlipCiphertextByte(payload []byte, record tlsrecord.Record, offset int) (Mutation, error) {
	if offset < 0 {
		return Mutation{}, fmt.Errorf("偏移不能为负数")
	}
	if offset >= record.DataLen {
		return Mutation{}, fmt.Errorf("偏移超出 record 数据区")
	}

	payloadIndex := record.DataStart + offset
	if payloadIndex < 0 || payloadIndex >= len(payload) {
		return Mutation{}, fmt.Errorf("偏移超出 payload 范围")
	}

	oldByte := payload[payloadIndex]
	newByte := oldByte ^ 0xff
	// 通过按位翻转制造确定性的密文破坏，便于复现实验结果。
	payload[payloadIndex] = newByte

	return Mutation{
		PayloadIndex: payloadIndex,
		OldByte:      oldByte,
		NewByte:      newByte,
	}, nil
}

// ApplyMutationPoint 将绝对序列号命中的篡改点施加到当前 payload。
func ApplyMutationPoint(payload []byte, payloadSeq uint32, point reassembly.MutationPoint) (AppliedMutation, bool) {
	if len(payload) == 0 {
		return AppliedMutation{}, false
	}
	if point.TargetSeq < payloadSeq {
		return AppliedMutation{}, false
	}

	offset := int(point.TargetSeq - payloadSeq)
	if offset < 0 || offset >= len(payload) {
		return AppliedMutation{}, false
	}

	payload[offset] = point.NewByte
	return AppliedMutation{
		PayloadIndex: offset,
		TargetSeq:    point.TargetSeq,
		OldByte:      point.OldByte,
		NewByte:      point.NewByte,
	}, true
}
