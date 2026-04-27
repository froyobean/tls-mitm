// Package tcpmeta 负责解析 IPv4/TCP 数据包的元信息。
package tcpmeta

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

// Packet 描述一个 IPv4/TCP 数据包中的关键网络元信息。
type Packet struct {
	SrcIP, DstIP     netip.Addr
	SrcPort, DstPort uint16
	Seq, Ack         uint32
	PayloadOffset    int
	TCPFlags         byte
	Payload          []byte
}

// ParseIPv4TCP 解析原始字节并返回 IPv4/TCP 数据包元信息。
func ParseIPv4TCP(packet []byte) (Packet, error) {
	if len(packet) < 20 {
		return Packet{}, fmt.Errorf("包太短，无法解析 IPv4 头")
	}

	version := packet[0] >> 4
	if version != 4 {
		return Packet{}, fmt.Errorf("不是 IPv4 数据包")
	}

	ihl := int(packet[0]&0x0f) * 4
	if ihl < 20 {
		return Packet{}, fmt.Errorf("IPv4 头长度无效")
	}
	if len(packet) < ihl {
		return Packet{}, fmt.Errorf("包太短，无法解析完整 IPv4 头")
	}

	totalLen := int(binary.BigEndian.Uint16(packet[2:4]))
	if totalLen == 0 {
		totalLen = len(packet)
	}
	if totalLen > len(packet) {
		return Packet{}, fmt.Errorf("IPv4 总长度超出缓冲区")
	}
	if totalLen < ihl+20 {
		return Packet{}, fmt.Errorf("IPv4/TCP 头长度无效")
	}

	flagsAndOffset := binary.BigEndian.Uint16(packet[6:8])
	if flagsAndOffset&0x2000 != 0 || flagsAndOffset&0x1fff != 0 {
		// 第一版不做 IPv4 分片重组，因此直接拒绝分片包，避免把残缺 TCP 头误当成完整载荷。
		return Packet{}, fmt.Errorf("不支持解析 IPv4 分片包")
	}

	if packet[9] != 6 {
		return Packet{}, fmt.Errorf("不是 TCP 数据包")
	}

	srcIP := netip.AddrFrom4([4]byte{packet[12], packet[13], packet[14], packet[15]})
	dstIP := netip.AddrFrom4([4]byte{packet[16], packet[17], packet[18], packet[19]})

	tcpStart := ihl
	if totalLen < tcpStart+20 {
		return Packet{}, fmt.Errorf("包太短，无法解析 TCP 头")
	}

	tcpHeaderLen := int(packet[tcpStart+12]>>4) * 4
	if tcpHeaderLen < 20 {
		return Packet{}, fmt.Errorf("TCP 头长度无效")
	}
	if tcpStart+tcpHeaderLen > totalLen {
		return Packet{}, fmt.Errorf("TCP 头超出包长度")
	}

	payloadOffset := tcpStart + tcpHeaderLen
	return Packet{
		SrcIP:         srcIP,
		DstIP:         dstIP,
		SrcPort:       binary.BigEndian.Uint16(packet[tcpStart : tcpStart+2]),
		DstPort:       binary.BigEndian.Uint16(packet[tcpStart+2 : tcpStart+4]),
		Seq:           binary.BigEndian.Uint32(packet[tcpStart+4 : tcpStart+8]),
		Ack:           binary.BigEndian.Uint32(packet[tcpStart+8 : tcpStart+12]),
		PayloadOffset: payloadOffset,
		TCPFlags:      packet[tcpStart+13],
		Payload:       packet[payloadOffset:totalLen],
	}, nil
}
