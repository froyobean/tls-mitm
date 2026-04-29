# DNS 域名拦截 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在保留现有 `SNI` 域名命中能力的前提下，新增基于明文 `UDP/53` DNS 响应的域名到 IP 命中能力，并通过 `-host-match sni|dns|both` 控制策略。

**Architecture:** 新增轻量 DNS 响应解析包与目标域名 DNS 缓存包，抓包层只消费“目标域名解析出的 IP 是否命中当前 TCP 连接”这一结果。现有 per-connection blocker、TLS `Application Data record` 重组与篡改链路保持复用，`both` 模式采用 `SNI OR DNS` 语义，同一 TCP 连接最多创建一个 blocker。

**Tech Stack:** Go、标准库 `flag`/`log/slog`/`net/netip`/`encoding/binary`、现有 `imgk/divert-go` WinDivert 适配层、现有 `session.Store`、纯单元测试与 Windows 构建约束测试。

---

## 文件结构

- Modify: `internal/config/config.go`
- Modify: `internal/config/config_test.go`
- Create: `internal/dnsmeta/packet.go`
- Create: `internal/dnsmeta/packet_test.go`
- Create: `internal/dnscache/cache.go`
- Create: `internal/dnscache/cache_test.go`
- Modify: `internal/session/store.go`
- Modify: `internal/session/store_test.go`
- Modify: `internal/capture/loop.go`
- Modify: `internal/capture/loop_test.go`
- Modify: `internal/capture/windivert_windows.go`
- Modify: `internal/app/run.go`
- Modify: `README.md`

## Task 1: 增加 `-host-match` 配置

**Files:**
- Modify: `internal/config/config.go`
- Modify: `internal/config/config_test.go`

- [ ] **Step 1: 写失败测试**

在 `internal/config/config_test.go` 新增：

```go
func TestParseArgsDefaultsHostMatchToSNI(t *testing.T) {
	cfg, err := ParseArgs([]string{"-target-host", "example.com", "-target-port", "443"})
	if err != nil {
		t.Fatalf("ParseArgs returned error: %v", err)
	}
	if cfg.HostMatch != "sni" {
		t.Fatalf("expected default host match sni, got %q", cfg.HostMatch)
	}
}

func TestParseArgsAcceptsHostMatchModes(t *testing.T) {
	for _, mode := range []string{"sni", "dns", "both"} {
		t.Run(mode, func(t *testing.T) {
			cfg, err := ParseArgs([]string{"-target-host", "example.com", "-target-port", "443", "-host-match", mode})
			if err != nil {
				t.Fatalf("ParseArgs returned error: %v", err)
			}
			if cfg.HostMatch != mode {
				t.Fatalf("expected host match %q, got %q", mode, cfg.HostMatch)
			}
		})
	}
}

func TestParseArgsRejectsInvalidHostMatch(t *testing.T) {
	if _, err := ParseArgs([]string{"-target-host", "example.com", "-target-port", "443", "-host-match", "strict"}); err == nil || !strings.Contains(err.Error(), "host-match") {
		t.Fatalf("expected host-match error, got %v", err)
	}
}

func TestParseArgsRejectsDNSHostMatchWithoutTargetHost(t *testing.T) {
	if _, err := ParseArgs([]string{"-target-ip", "93.184.216.34", "-target-port", "443", "-host-match", "dns"}); err == nil || !strings.Contains(err.Error(), "target-host") {
		t.Fatalf("expected target-host error, got %v", err)
	}
}

func TestParseArgsRejectsBothHostMatchWithoutTargetHost(t *testing.T) {
	if _, err := ParseArgs([]string{"-target-ip", "93.184.216.34", "-target-port", "443", "-host-match", "both"}); err == nil || !strings.Contains(err.Error(), "target-host") {
		t.Fatalf("expected target-host error, got %v", err)
	}
}
```

- [ ] **Step 2: 运行测试确认失败**

Run: `go test ./internal/config -run "HostMatch|DNSHostMatch" -v`

Expected: FAIL，提示 `Config.HostMatch` 或 `-host-match` 尚不存在。

- [ ] **Step 3: 最小实现配置字段与校验**

在 `internal/config/config.go` 中新增字段：

```go
type Config struct {
	TargetIP        netip.Addr
	TargetHost      string
	TargetPort      uint16
	ObserveTimeout  time.Duration
	LogFormat       string
	MutateOffset    int
	MutateDirection string
	HostMatch       string
	UnsafeAnyHost   bool
}
```

扩展 `ParseArgs`：

```go
normalizedHostMatch := normalizeHostMatch(*hostMatch)
if normalizedHostMatch == "" {
	normalizedHostMatch = "sni"
}
if normalizedHostMatch != "sni" && normalizedHostMatch != "dns" && normalizedHostMatch != "both" {
	return Config{}, fmt.Errorf("无效的 -host-match: %s（仅支持 sni、dns 或 both）", normalizedHostMatch)
}
if (normalizedHostMatch == "dns" || normalizedHostMatch == "both") && normalizedTargetHost == "" {
	return Config{}, errors.New("-host-match dns 或 both 需要提供 target-host")
}
```

扩展 `bindFlags`：

```go
hostMatch := fs.String("host-match", "sni", "域名命中方式：sni、dns 或 both")
```

新增标准化函数：

```go
func normalizeHostMatch(hostMatch string) string {
	return strings.ToLower(strings.TrimSpace(hostMatch))
}
```

返回 `Config` 时设置：

```go
HostMatch: normalizedHostMatch,
```

- [ ] **Step 4: 更新帮助信息测试**

在 `TestUsageIncludesFlags` 的 `want` 列表中加入 `"-host-match"`，新增：

```go
func TestUsageMentionsHostMatch(t *testing.T) {
	usage := Usage()
	for _, want := range []string{"-host-match <模式>", "sni、dns 或 both", "tls-mitm -target-host example.com -target-port 443 -host-match both"} {
		if !strings.Contains(usage, want) {
			t.Fatalf("usage missing %q: %s", want, usage)
		}
	}
}
```

- [ ] **Step 5: 运行配置测试确认通过**

Run: `go test ./internal/config -v`

Expected: PASS。

- [ ] **Step 6: 提交配置任务**

```bash
git add internal/config/config.go internal/config/config_test.go
git commit -m "feat: 增加域名命中模式配置" -m "- 新增 -host-match sni|dns|both 参数" -m "- 保持默认 SNI 行为不变" -m "- 校验 DNS 模式必须提供 target-host"
```

## Task 2: 实现 `UDP/53` DNS 响应解析

**Files:**
- Create: `internal/dnsmeta/packet.go`
- Create: `internal/dnsmeta/packet_test.go`

- [ ] **Step 1: 写失败测试**

创建 `internal/dnsmeta/packet_test.go`：

```go
package dnsmeta

import (
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
```

测试文件内添加最小构造 helper：

```go
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
```

- [ ] **Step 2: 运行测试确认失败**

Run: `go test ./internal/dnsmeta -v`

Expected: FAIL，提示缺少 `dnsmeta` 包或 `ParseIPv4UDPResponse`。

- [ ] **Step 3: 实现最小解析器**

创建 `internal/dnsmeta/packet.go`：

```go
// Package dnsmeta 解析明文 DNS 响应中的目标元数据。
package dnsmeta

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// Answer 描述 DNS answer section 中可用于目标命中的 IPv4 A 记录。
type Answer struct {
	Name string
	IP   netip.Addr
	TTL  time.Duration
}

// ParseIPv4UDPResponse 从 IPv4 UDP/53 DNS 响应包中提取 A 记录。
func ParseIPv4UDPResponse(packet []byte) ([]Answer, error) {
	payload, err := ipv4UDPPayload(packet)
	if err != nil {
		return nil, err
	}
	return parseDNSResponse(payload)
}
```

实现内部函数：

```go
func ipv4UDPPayload(packet []byte) ([]byte, error)
func parseDNSResponse(payload []byte) ([]Answer, error)
func readName(message []byte, offset int) (string, int, error)
func normalizeName(name string) string
```

关键约束：

```go
if packet[9] != 17 {
	return nil, fmt.Errorf("不是 UDP 包")
}
if binary.BigEndian.Uint16(packet[ipHeaderLen:ipHeaderLen+2]) != 53 {
	return nil, fmt.Errorf("不是 DNS 响应源端口")
}
if flags&0x8000 == 0 {
	return nil, nil
}
```

- [ ] **Step 4: 增加 CNAME 链测试并实现**

新增测试：

```go
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
```

实现方式：先收集 `CNAME owner -> target`，再把最终 `A` 记录额外复制给指向它的 owner。

- [ ] **Step 5: 运行 DNS 解析测试**

Run: `go test ./internal/dnsmeta -v`

Expected: PASS。

- [ ] **Step 6: 提交 DNS 解析任务**

```bash
git add internal/dnsmeta/packet.go internal/dnsmeta/packet_test.go
git commit -m "feat: 解析明文 DNS A 记录响应" -m "- 支持 IPv4 UDP/53 DNS 响应解析" -m "- 支持压缩域名和 CNAME 到 A 记录映射" -m "- 畸形包返回错误且不 panic"
```

## Task 3: 实现目标域名 DNS 命中缓存

**Files:**
- Create: `internal/dnscache/cache.go`
- Create: `internal/dnscache/cache_test.go`

- [ ] **Step 1: 写失败测试**

创建 `internal/dnscache/cache_test.go`：

```go
package dnscache

import (
	"net/netip"
	"testing"
	"time"
)

func TestCacheMatchesStoredTargetIP(t *testing.T) {
	now := time.Unix(100, 0)
	cache := New("www.example.com", func() time.Time { return now })
	cache.Store("www.example.com", netip.MustParseAddr("93.184.216.34"), 300*time.Second)
	entry, ok := cache.Lookup(netip.MustParseAddr("93.184.216.34"))
	if !ok {
		t.Fatal("expected cache hit")
	}
	if entry.Host != "www.example.com" || entry.IP.String() != "93.184.216.34" {
		t.Fatalf("unexpected entry: %+v", entry)
	}
}

func TestCacheIgnoresOtherHost(t *testing.T) {
	now := time.Unix(100, 0)
	cache := New("www.example.com", func() time.Time { return now })
	cache.Store("other.example", netip.MustParseAddr("93.184.216.34"), 300*time.Second)
	if _, ok := cache.Lookup(netip.MustParseAddr("93.184.216.34")); ok {
		t.Fatal("expected other host to be ignored")
	}
}

func TestCacheExpiresEntry(t *testing.T) {
	now := time.Unix(100, 0)
	cache := New("www.example.com", func() time.Time { return now })
	cache.Store("www.example.com", netip.MustParseAddr("93.184.216.34"), time.Second)
	now = now.Add(2 * time.Second)
	if _, ok := cache.Lookup(netip.MustParseAddr("93.184.216.34")); ok {
		t.Fatal("expected expired entry to miss")
	}
}

func TestCacheCapsAndFallbackTTL(t *testing.T) {
	now := time.Unix(100, 0)
	cache := New("www.example.com", func() time.Time { return now })
	cache.Store("www.example.com", netip.MustParseAddr("93.184.216.34"), time.Hour)
	entry, ok := cache.Lookup(netip.MustParseAddr("93.184.216.34"))
	if !ok || entry.TTL != 10*time.Minute {
		t.Fatalf("expected capped TTL, got %+v ok=%v", entry, ok)
	}
	cache.Store("www.example.com", netip.MustParseAddr("93.184.216.35"), 0)
	entry, ok = cache.Lookup(netip.MustParseAddr("93.184.216.35"))
	if !ok || entry.TTL != time.Minute {
		t.Fatalf("expected fallback TTL, got %+v ok=%v", entry, ok)
	}
}
```

- [ ] **Step 2: 运行测试确认失败**

Run: `go test ./internal/dnscache -v`

Expected: FAIL，提示缺少 `dnscache` 包或 `New`。

- [ ] **Step 3: 实现缓存**

创建 `internal/dnscache/cache.go`：

```go
// Package dnscache 维护目标域名到 IP 的短期命中缓存。
package dnscache

import (
	"net/netip"
	"strings"
	"time"
)

// Entry 描述一条可以用于 TCP 连接命中的 DNS 解析结果。
type Entry struct {
	Host      string
	IP        netip.Addr
	ExpiresAt time.Time
	TTL       time.Duration
}

// Cache 保存单个目标域名对应的 DNS 解析 IP。
type Cache struct {
	targetHost  string
	now         func() time.Time
	byIP        map[netip.Addr]Entry
	maxTTL      time.Duration
	fallbackTTL time.Duration
}

// New 创建目标域名 DNS 命中缓存。
func New(targetHost string, now func() time.Time) *Cache {
	if now == nil {
		now = time.Now
	}
	return &Cache{
		targetHost:  normalizeHost(targetHost),
		now:         now,
		byIP:        make(map[netip.Addr]Entry),
		maxTTL:      10 * time.Minute,
		fallbackTTL: time.Minute,
	}
}
```

实现：

```go
func (c *Cache) Store(host string, ip netip.Addr, ttl time.Duration) (Entry, bool)
func (c *Cache) Lookup(ip netip.Addr) (Entry, bool)
func normalizeHost(host string) string
```

`Store` 中只接受 `host == targetHost` 且 `ip.Is4()` 的记录。

- [ ] **Step 4: 运行缓存测试**

Run: `go test ./internal/dnscache -v`

Expected: PASS。

- [ ] **Step 5: 提交缓存任务**

```bash
git add internal/dnscache/cache.go internal/dnscache/cache_test.go
git commit -m "feat: 增加目标域名 DNS 命中缓存" -m "- 仅缓存当前 target-host 的 IPv4 A 记录" -m "- 支持 TTL 上限、fallback TTL 和过期清理"
```

## Task 4: 调整连接匹配来源语义

**Files:**
- Modify: `internal/session/store.go`
- Modify: `internal/session/store_test.go`
- Modify: `internal/capture/loop.go`
- Modify: `internal/capture/loop_test.go`

- [ ] **Step 1: 写失败测试，证明命中后不能被排除覆盖**

在 `internal/session/store_test.go` 新增：

```go
func TestStoreMatchedStateIsNotOverwrittenByExclude(t *testing.T) {
	store := NewStore(func() time.Time { return time.Unix(100, 0) })
	key := testSessionKey()

	store.MarkMatched(key)
	store.MarkExcluded(key)

	if got := store.MatchState(key); got != MatchStateMatched {
		t.Fatalf("expected matched state to win over later exclude, got %s", got)
	}
}
```

在 `internal/capture/loop_test.go` 新增匹配辅助函数测试：

```go
func TestShouldUseSNIByHostMatchMode(t *testing.T) {
	if !usesSNI(config.Config{TargetHost: "example.com", HostMatch: "sni"}) {
		t.Fatal("expected sni mode to use SNI")
	}
	if usesSNI(config.Config{TargetHost: "example.com", HostMatch: "dns"}) {
		t.Fatal("expected dns mode not to use SNI")
	}
	if !usesSNI(config.Config{TargetHost: "example.com", HostMatch: "both"}) {
		t.Fatal("expected both mode to use SNI")
	}
}

func TestShouldUseDNSByHostMatchMode(t *testing.T) {
	if usesDNS(config.Config{TargetHost: "example.com", HostMatch: "sni"}) {
		t.Fatal("expected sni mode not to use DNS")
	}
	if !usesDNS(config.Config{TargetHost: "example.com", HostMatch: "dns"}) {
		t.Fatal("expected dns mode to use DNS")
	}
	if !usesDNS(config.Config{TargetHost: "example.com", HostMatch: "both"}) {
		t.Fatal("expected both mode to use DNS")
	}
}
```

- [ ] **Step 2: 运行测试确认失败**

Run: `go test ./internal/session ./internal/capture -run "MatchedStateIsNotOverwritten|ShouldUse" -v`

Expected: FAIL，`MarkExcluded` 会覆盖命中状态，`usesSNI`/`usesDNS` 尚不存在。

- [ ] **Step 3: 修改状态与匹配辅助函数**

在 `internal/session/store.go` 调整 `MarkExcluded`：

```go
func (s *Store) MarkExcluded(key Key) {
	s.mu.Lock()
	defer s.mu.Unlock()

	e := s.ensureEntryLocked(key)
	if e.matchState == MatchStateMatched {
		return
	}
	e.matchState = MatchStateExcluded
}
```

在 `internal/capture/loop.go` 新增：

```go
func usesSNI(cfg config.Config) bool {
	if cfg.TargetHost == "" {
		return false
	}
	return cfg.HostMatch == "" || cfg.HostMatch == "sni" || cfg.HostMatch == "both"
}

func usesDNS(cfg config.Config) bool {
	if cfg.TargetHost == "" {
		return false
	}
	return cfg.HostMatch == "dns" || cfg.HostMatch == "both"
}
```

调整 `shouldResolveHost`：

```go
func shouldResolveHost(cfg config.Config, store *session.Store, key session.Key) bool {
	if !usesSNI(cfg) {
		return false
	}
	return store.MatchState(key) == session.MatchStateUnknown
}
```

- [ ] **Step 4: 运行相关测试**

Run: `go test ./internal/session ./internal/capture -run "MatchedStateIsNotOverwritten|ShouldUse|HostOnly" -v`

Expected: PASS。

- [ ] **Step 5: 提交匹配语义任务**

```bash
git add internal/session/store.go internal/session/store_test.go internal/capture/loop.go internal/capture/loop_test.go
git commit -m "feat: 调整域名命中来源匹配语义" -m "- both 模式下已命中的连接不会被后续 SNI 不同覆盖" -m "- 增加 SNI 与 DNS 模式判断辅助函数"
```

## Task 5: 集成 DNS observe 与 host-match 主循环

**Files:**
- Modify: `internal/capture/loop.go`
- Modify: `internal/capture/loop_test.go`
- Modify: `internal/capture/windivert_windows.go`
- Modify: `internal/app/run.go`

- [ ] **Step 1: 写过滤器失败测试**

在 `internal/capture/loop_test.go` 新增：

```go
func TestBuildDNSResponseFilter(t *testing.T) {
	filter := BuildDNSResponseFilter()
	for _, want := range []string{"inbound", "udp", "ip", "udp.SrcPort == 53"} {
		if !strings.Contains(filter, want) {
			t.Fatalf("filter missing %q: %s", want, filter)
		}
	}
}
```

- [ ] **Step 2: 写 DNS 命中后创建 blocker 的失败测试**

在 `internal/capture/loop_test.go` 新增：

```go
func TestHostMatchDNSModeCreatesBlockerForResolvedIP(t *testing.T) {
	cfg := config.Config{
		TargetHost:      "www.example.com",
		TargetPort:      443,
		ObserveTimeout:  50 * time.Millisecond,
		MutateOffset:    0,
		MutateDirection: "out",
		HostMatch:       "dns",
	}

	dnsObserve := &scriptedHandle{steps: []recvStep{
		{packet: dnsResponsePacketForCaptureTest("www.example.com", "93.184.216.34", 300)},
	}}
	outObserve := &scriptedHandle{steps: []recvStep{
		{delay: time.Millisecond, packet: outboundTLSPacketTo("93.184.216.34")},
	}}
	inObserve := &scriptedHandle{}
	blocker := &scriptedHandle{steps: []recvStep{
		{packet: outboundTLSPacketTo("93.184.216.34")},
	}}
	factoryCalls := 0
	factory := func(key session.Key) (packetHandle, error) {
		factoryCalls++
		return blocker, nil
	}

	if err := runHostMatchLoopWithHandles(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), outObserve, inObserve, dnsObserve, factory); err != nil {
		t.Fatalf("runHostMatchLoopWithHandles returned error: %v", err)
	}
	if factoryCalls != 1 {
		t.Fatalf("expected one DNS matched blocker, got %d", factoryCalls)
	}
	if got := blocker.sent[0].packet[45]; got != 0x55 {
		t.Fatalf("expected DNS matched connection to mutate, got 0x%02x", got)
	}
}
```

- [ ] **Step 3: 写 `sni` 模式忽略 DNS 的失败测试**

```go
func TestHostMatchSNIModeIgnoresDNSResponse(t *testing.T) {
	cfg := config.Config{
		TargetHost:      "www.example.com",
		TargetPort:      443,
		ObserveTimeout:  50 * time.Millisecond,
		MutateOffset:    0,
		MutateDirection: "out",
		HostMatch:       "sni",
	}
	dnsObserve := &scriptedHandle{steps: []recvStep{{packet: dnsResponsePacketForCaptureTest("www.example.com", "93.184.216.34", 300)}}}
	outObserve := &scriptedHandle{steps: []recvStep{{delay: time.Millisecond, packet: outboundTLSPacketTo("93.184.216.34")}}}
	factoryCalls := 0
	factory := func(key session.Key) (packetHandle, error) {
		factoryCalls++
		return &scriptedHandle{}, nil
	}

	if err := runHostMatchLoopWithHandles(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), outObserve, &scriptedHandle{}, dnsObserve, factory); err != nil {
		t.Fatalf("runHostMatchLoopWithHandles returned error: %v", err)
	}
	if factoryCalls != 0 {
		t.Fatalf("expected sni mode to ignore DNS cache, got %d blocker calls", factoryCalls)
	}
}
```

- [ ] **Step 4: 运行测试确认失败**

Run: `go test ./internal/capture -run "DNS|SNIModeIgnores" -v`

Expected: FAIL，`BuildDNSResponseFilter`、`runHostMatchLoopWithHandles` 新签名或 DNS 处理尚不存在。

- [ ] **Step 5: 扩展事件与主循环**

在 `internal/capture/loop.go` 新增事件类型：

```go
const (
	recvKindOutboundObserve recvKind = iota
	recvKindOutboundBlock
	recvKindInboundObserve
	recvKindInboundBlock
	recvKindBidirectionalBlock
	recvKindDNSObserve
)
```

新增过滤器：

```go
// BuildDNSResponseFilter 构造入站明文 DNS 响应观察过滤表达式。
func BuildDNSResponseFilter() string {
	return "(inbound and udp and ip and udp.SrcPort == 53)"
}
```

在 `runHostMatchLoopWithHandles` 中增加 `dnsObserveHandle packetHandle` 参数，并创建缓存：

```go
dnsCache := dnscache.New(cfg.TargetHost, time.Now)
```

在 reader 初始化中加入：

```go
if dnsObserveHandle != nil && usesDNS(cfg) {
	readers++
	startReader(dnsObserveHandle, recvKindDNSObserve, session.Key{})
}
```

在事件处理里新增：

```go
case recvKindDNSObserve:
	processDNSObserve(cfg, logger, dnsCache, event.packet)
```

新增 DNS 处理函数：

```go
func processDNSObserve(cfg config.Config, logger *slog.Logger, cache *dnscache.Cache, packet []byte) {
	if !usesDNS(cfg) || cache == nil {
		return
	}
	answers, err := dnsmeta.ParseIPv4UDPResponse(packet)
	if err != nil {
		logger.Debug("跳过无法解析的 DNS 响应", "error", err)
		return
	}
	for _, answer := range answers {
		entry, ok := cache.Store(answer.Name, answer.IP, answer.TTL)
		if !ok {
			continue
		}
		logger.Info(
			"DNS 命中目标域名",
			"target_host", cfg.TargetHost,
			"resolved_ip", entry.IP.String(),
			"dns_ttl", answer.TTL.String(),
			"effective_ttl", entry.TTL.String(),
		)
	}
}
```

- [ ] **Step 6: 出站观察包接入 DNS cache**

把 `processHostOnlyObservedOutbound` 扩展为接收 DNS cache：

```go
func processHostOnlyObservedOutbound(
	cfg config.Config,
	logger *slog.Logger,
	store *session.Store,
	dnsCache *dnscache.Cache,
	packet []byte,
) (hostOnlyEventResult, error)
```

在 TCP 端口匹配后、SNI 解析前加入：

```go
if usesDNS(cfg) {
	if entry, ok := dnsCache.Lookup(meta.DstIP); ok {
		store.MarkMatched(key)
		result.matched = true
		logger.Info(
			"DNS 命中目标连接",
			"trace_id", store.TraceID(key),
			"client_ip", key.ClientIP,
			"client_port", key.ClientPort,
			"server_ip", key.ServerIP,
			"server_port", key.ServerPort,
			"target_host", cfg.TargetHost,
			"matched_ip", entry.IP.String(),
			"match_source", "dns",
		)
	}
}
```

SNI 不同且连接已由 DNS 命中时，记录冲突但不排除：

```go
if !hostMatches(cfg, serverName) && store.MatchState(key) == session.MatchStateMatched {
	logger.Info(
		"DNS 命中目标连接但 SNI 不同",
		"trace_id", store.TraceID(key),
		"target_host", cfg.TargetHost,
		"observed_host", serverName,
		"matched_ip", key.ServerIP,
	)
	return result, nil
}
```

- [ ] **Step 7: 扩展 Windows 导出函数与 app 入口**

在 `internal/capture/windivert_windows.go` 保留原导出函数签名兼容：

```go
func RunHostMatchLoop(
	ctx context.Context,
	cfg config.Config,
	logger *slog.Logger,
	outObserveHandle, inObserveHandle *Handle,
	newBlockHandle func(key session.Key) (*Handle, error),
) error {
	return RunDomainMatchLoop(ctx, cfg, logger, outObserveHandle, inObserveHandle, nil, newBlockHandle)
}
```

新增：

```go
// RunDomainMatchLoop 运行基于 SNI、DNS 或二者组合命中的“先观察、后阻断”主循环。
func RunDomainMatchLoop(
	ctx context.Context,
	cfg config.Config,
	logger *slog.Logger,
	outObserveHandle, inObserveHandle, dnsObserveHandle *Handle,
	newBlockHandle func(key session.Key) (*Handle, error),
) error
```

在 `internal/app/run.go` 中，当 `usesDNS` 等价条件满足时打开 DNS observe 句柄：

```go
var dnsObserveHandle *capture.Handle
if cfg.HostMatch == "dns" || cfg.HostMatch == "both" {
	dnsObserveHandle, err = capture.OpenObserveHandleWithPriority(capture.BuildDNSResponseFilter(), divert.PriorityHighest)
	if err != nil {
		return err
	}
	defer dnsObserveHandle.Close()
}
return capture.RunDomainMatchLoop(ctx, cfg, logger, outObserveHandle, inObserveHandle, dnsObserveHandle, blockFactory)
```

- [ ] **Step 8: 运行 capture 测试**

Run: `go test ./internal/capture -v`

Expected: PASS。

- [ ] **Step 9: 提交主循环集成任务**

```bash
git add internal/capture/loop.go internal/capture/loop_test.go internal/capture/windivert_windows.go internal/app/run.go
git commit -m "feat: 接入 DNS 域名命中主循环" -m "- 观察入站 UDP/53 DNS 响应并维护目标域名缓存" -m "- DNS 命中后复用 per-connection blocker 篡改链路" -m "- both 模式下支持 DNS 与 SNI OR 命中语义"
```

## Task 6: 冲突日志、README 与全量验证

**Files:**
- Modify: `internal/capture/loop_test.go`
- Modify: `README.md`

- [ ] **Step 1: 写 DNS 与 SNI 冲突日志测试**

在 `internal/capture/loop_test.go` 新增：

```go
func TestHostMatchBothLogsConflictWhenDNSMatchesButSNIDiffers(t *testing.T) {
	cfg := config.Config{
		TargetHost:      "www.example.com",
		TargetPort:      443,
		ObserveTimeout:  50 * time.Millisecond,
		MutateOffset:    0,
		MutateDirection: "out",
		HostMatch:       "both",
	}
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	dnsObserve := &scriptedHandle{steps: []recvStep{{packet: dnsResponsePacketForCaptureTest("www.example.com", "93.184.216.34", 300)}}}
	outObserve := &scriptedHandle{steps: []recvStep{{delay: time.Millisecond, packet: outboundClientHelloPacketTo("93.184.216.34", "other.example")}}}
	blocker := &scriptedHandle{steps: []recvStep{{packet: outboundTLSPacketTo("93.184.216.34")}}}
	factory := func(key session.Key) (packetHandle, error) { return blocker, nil }

	if err := runHostMatchLoopWithHandles(context.Background(), cfg, logger, outObserve, &scriptedHandle{}, dnsObserve, factory); err != nil {
		t.Fatalf("runHostMatchLoopWithHandles returned error: %v", err)
	}
	if !strings.Contains(logs.String(), "DNS 命中目标连接但 SNI 不同") {
		t.Fatalf("expected conflict log, got: %s", logs.String())
	}
}
```

- [ ] **Step 2: 运行测试确认失败或通过**

Run: `go test ./internal/capture -run "Conflict|DNS" -v`

Expected: PASS；如果冲突日志缺字段，补齐 `target_host`、`observed_host`、`matched_ip`、`trace_id`。

- [ ] **Step 3: 更新 README**

在命令行参数章节加入：

```markdown
- `-host-match sni|dns|both`：域名命中方式，默认 `sni`。
```

加入说明：

```markdown
DNS 模式只观察明文 `UDP/53` DNS 响应，不支持 DoH、DoT、DoQ，也不会修改 DNS 包。`both` 模式采用 `SNI OR DNS` 语义：只要 SNI 或 DNS 解析 IP 任一命中，就会接管该 TCP 连接；如果 DNS 命中但 SNI 不同，程序会输出冲突日志并继续按 DNS 命中处理。
```

加入示例：

```powershell
.\build\tls-mitm.exe -target-host www.bing.com -target-port 443 -host-match both
.\build\tls-mitm.exe -target-host www.bing.com -target-port 443 -host-match dns
```

- [ ] **Step 4: 全量验证**

Run: `go test ./...`

Expected: PASS。

Run: `go test -tags=divert_cgo ./...`

Expected: PASS。

Run: `go run ./cmd/tls-mitm -h`

Expected: 帮助信息包含 `-host-match <模式>`、`sni、dns 或 both`、DNS 示例。

- [ ] **Step 5: 提交收口任务**

```bash
git add internal/capture/loop_test.go README.md
git commit -m "docs: 补充 DNS 域名命中使用说明" -m "- 说明 -host-match sni|dns|both 的行为差异" -m "- 标注 DNS 模式仅支持明文 UDP/53 响应" -m "- 增加 DNS 与 SNI 冲突场景说明"
```

## 自检

### Spec coverage

- `-host-match sni|dns|both`：Task 1
- 默认 `sni` 保持现有行为：Task 1、Task 5
- 明文 `UDP/53` DNS 响应观察：Task 2、Task 5
- `A` 记录、压缩 name、CNAME 链：Task 2
- DNS 命中缓存 TTL、fallback、过期清理：Task 3
- `SNI OR DNS` 语义：Task 4、Task 5
- 同一连接最多一个 blocker：Task 5 通过 factory call 断言覆盖
- DNS 命中但 SNI 不同时继续篡改并打冲突日志：Task 4、Task 6
- 默认不启用 DNS observe：Task 5 的 `sni` 模式忽略 DNS 覆盖
- README 和帮助信息更新：Task 1、Task 6

### 占位内容扫描

- 未发现占位式任务、未完成标记或空泛实现描述
- 每个任务都包含具体文件、测试代码、运行命令、期望结果和提交命令
- 每个生产代码改动前都有对应失败测试步骤

### Type consistency

- 配置字段统一使用 `config.Config.HostMatch`
- DNS 解析入口统一使用 `dnsmeta.ParseIPv4UDPResponse`
- DNS 缓存入口统一使用 `dnscache.New`、`Cache.Store`、`Cache.Lookup`
- 抓包层 DNS filter 统一使用 `capture.BuildDNSResponseFilter`
- Windows 导出函数保留 `RunHostMatchLoop`，新增 `RunDomainMatchLoop` 承载 DNS observe handle
