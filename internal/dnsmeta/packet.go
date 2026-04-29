// Package dnsmeta 解析明文 DNS 响应中的目标元数据。
package dnsmeta

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"
)

// Answer 描述 DNS answer section 中可用于目标命中的 IPv4 A 记录。
type Answer struct {
	Name string
	IP   netip.Addr
	TTL  time.Duration
}

type cnameRecord struct {
	target string
	ttl    time.Duration
}

type resolvedAlias struct {
	answer Answer
	hops   int
}

// ParseIPv4UDPResponse 从 IPv4 UDP/53 DNS 响应包中提取 A 记录。
func ParseIPv4UDPResponse(packet []byte) ([]Answer, error) {
	payload, err := ipv4UDPPayload(packet)
	if err != nil {
		return nil, err
	}
	return parseDNSResponse(payload)
}

func ipv4UDPPayload(packet []byte) ([]byte, error) {
	const minIPv4HeaderLen = 20
	const udpHeaderLen = 8

	if len(packet) < minIPv4HeaderLen {
		return nil, fmt.Errorf("IPv4 包长度不足")
	}
	if version := packet[0] >> 4; version != 4 {
		return nil, fmt.Errorf("不是 IPv4 包")
	}

	ipHeaderLen := int(packet[0]&0x0f) * 4
	if ipHeaderLen < minIPv4HeaderLen || len(packet) < ipHeaderLen+udpHeaderLen {
		return nil, fmt.Errorf("IPv4 头部长度非法")
	}
	if packet[9] != 17 {
		return nil, fmt.Errorf("不是 UDP 包")
	}
	if binary.BigEndian.Uint16(packet[ipHeaderLen:ipHeaderLen+2]) != 53 {
		return nil, fmt.Errorf("不是 DNS 响应源端口")
	}

	totalLen := int(binary.BigEndian.Uint16(packet[2:4]))
	if totalLen == 0 || totalLen > len(packet) {
		totalLen = len(packet)
	}
	if totalLen < ipHeaderLen+udpHeaderLen {
		return nil, fmt.Errorf("IPv4 总长度非法")
	}

	udpLen := int(binary.BigEndian.Uint16(packet[ipHeaderLen+4 : ipHeaderLen+6]))
	if udpLen < udpHeaderLen || ipHeaderLen+udpLen > totalLen {
		return nil, fmt.Errorf("UDP 长度非法")
	}

	return packet[ipHeaderLen+udpHeaderLen : ipHeaderLen+udpLen], nil
}

func parseDNSResponse(payload []byte) ([]Answer, error) {
	const dnsHeaderLen = 12
	const rrFixedLen = 10

	if len(payload) < dnsHeaderLen {
		return nil, fmt.Errorf("DNS 负载长度不足")
	}

	flags := binary.BigEndian.Uint16(payload[2:4])
	if flags&0x8000 == 0 {
		return nil, nil
	}

	questionCount := int(binary.BigEndian.Uint16(payload[4:6]))
	answerCount := int(binary.BigEndian.Uint16(payload[6:8]))
	offset := dnsHeaderLen

	for i := 0; i < questionCount; i++ {
		_, next, err := readName(payload, offset)
		if err != nil {
			return nil, err
		}
		if next+4 > len(payload) {
			return nil, fmt.Errorf("DNS question 越界")
		}
		offset = next + 4
	}

	answers := make([]Answer, 0, answerCount)
	cnameByOwner := make(map[string]cnameRecord)
	for i := 0; i < answerCount; i++ {
		name, next, err := readName(payload, offset)
		if err != nil {
			return nil, err
		}
		if next+rrFixedLen > len(payload) {
			return nil, fmt.Errorf("DNS answer 越界")
		}

		typ := binary.BigEndian.Uint16(payload[next : next+2])
		class := binary.BigEndian.Uint16(payload[next+2 : next+4])
		ttl := binary.BigEndian.Uint32(payload[next+4 : next+8])
		rdLen := int(binary.BigEndian.Uint16(payload[next+8 : next+10]))
		rdataOffset := next + rrFixedLen
		if rdataOffset+rdLen > len(payload) {
			return nil, fmt.Errorf("DNS rdata 越界")
		}

		if typ == 1 && class == 1 && rdLen == 4 {
			ip, ok := netip.AddrFromSlice(payload[rdataOffset : rdataOffset+rdLen])
			if !ok {
				return nil, fmt.Errorf("A 记录地址非法")
			}
			answers = append(answers, Answer{
				Name: normalizeName(name),
				IP:   ip,
				TTL:  time.Duration(ttl) * time.Second,
			})
		} else if typ == 5 && class == 1 {
			target, _, err := readName(payload, rdataOffset)
			if err != nil {
				return nil, err
			}
			cnameByOwner[normalizeName(name)] = cnameRecord{
				target: normalizeName(target),
				ttl:    time.Duration(ttl) * time.Second,
			}
		}

		offset = rdataOffset + rdLen
	}

	if len(cnameByOwner) == 0 || len(answers) == 0 {
		return answers, nil
	}

	aliasAnswers := make([]resolvedAlias, 0, len(cnameByOwner))
	for _, answer := range answers {
		for owner := range cnameByOwner {
			ttl, hops, ok := resolveCNAMETTL(owner, answer.Name, answer.TTL, cnameByOwner)
			if !ok {
				continue
			}
			aliasAnswers = append(aliasAnswers, resolvedAlias{
				answer: Answer{
					Name: owner,
					IP:   answer.IP,
					TTL:  ttl,
				},
				hops: hops,
			})
		}
	}

	sort.Slice(aliasAnswers, func(i, j int) bool {
		if aliasAnswers[i].hops != aliasAnswers[j].hops {
			return aliasAnswers[i].hops < aliasAnswers[j].hops
		}
		return aliasAnswers[i].answer.Name < aliasAnswers[j].answer.Name
	})
	for _, alias := range aliasAnswers {
		answers = append(answers, alias.answer)
	}
	return answers, nil
}

func readName(message []byte, offset int) (string, int, error) {
	var labels []string
	current := offset
	next := -1
	visited := make(map[int]struct{})

	for {
		if current >= len(message) {
			return "", 0, fmt.Errorf("DNS name 越界")
		}
		if _, seen := visited[current]; seen {
			return "", 0, fmt.Errorf("DNS 压缩指针循环")
		}
		visited[current] = struct{}{}

		length := int(message[current])
		if length == 0 {
			if next == -1 {
				next = current + 1
			}
			break
		}

		if length&0xc0 == 0xc0 {
			if current+1 >= len(message) {
				return "", 0, fmt.Errorf("DNS 压缩指针越界")
			}
			ptr := int(binary.BigEndian.Uint16(message[current:current+2]) & 0x3fff)
			if ptr >= len(message) {
				return "", 0, fmt.Errorf("DNS 压缩指针非法")
			}
			if next == -1 {
				next = current + 2
			}
			current = ptr
			continue
		}

		if length&0xc0 != 0 {
			return "", 0, fmt.Errorf("DNS label 长度非法")
		}
		current++
		if current+length > len(message) {
			return "", 0, fmt.Errorf("DNS label 越界")
		}
		labels = append(labels, string(message[current:current+length]))
		current += length
	}

	return strings.Join(labels, "."), next, nil
}

func normalizeName(name string) string {
	name = strings.TrimSuffix(name, ".")
	return strings.ToLower(name)
}

func resolveCNAMETTL(owner, finalName string, answerTTL time.Duration, cnameByOwner map[string]cnameRecord) (time.Duration, int, bool) {
	current := owner
	minTTL := answerTTL
	hops := 0
	visited := make(map[string]struct{})

	for {
		if _, seen := visited[current]; seen {
			return 0, 0, false
		}
		visited[current] = struct{}{}

		record, ok := cnameByOwner[current]
		if !ok {
			return 0, 0, false
		}
		minTTL = minDuration(minTTL, record.ttl)
		hops++
		if record.target == finalName {
			return minTTL, hops, true
		}
		current = record.target
	}
}

func minDuration(a, b time.Duration) time.Duration {
	if a == 0 {
		return b
	}
	if b == 0 {
		return a
	}
	if a < b {
		return a
	}
	return b
}
