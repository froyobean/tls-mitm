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

// Store 在命中目标域名时缓存 IPv4 A 记录。
func (c *Cache) Store(host string, ip netip.Addr, ttl time.Duration) (Entry, bool) {
	if c == nil {
		return Entry{}, false
	}
	normalizedHost := normalizeHost(host)
	if normalizedHost != c.targetHost || !ip.Is4() {
		return Entry{}, false
	}
	if ttl <= 0 {
		ttl = c.fallbackTTL
	}
	if ttl > c.maxTTL {
		ttl = c.maxTTL
	}

	entry := Entry{
		Host:      normalizedHost,
		IP:        ip,
		ExpiresAt: c.now().Add(ttl),
		TTL:       ttl,
	}
	c.byIP[ip] = entry
	return entry, true
}

// Lookup 返回给定 IP 对应的未过期缓存项。
func (c *Cache) Lookup(ip netip.Addr) (Entry, bool) {
	if c == nil {
		return Entry{}, false
	}
	now := c.now()
	for cachedIP, entry := range c.byIP {
		if !entry.ExpiresAt.After(now) {
			delete(c.byIP, cachedIP)
		}
	}
	entry, ok := c.byIP[ip]
	if !ok {
		return Entry{}, false
	}
	return entry, true
}

func normalizeHost(host string) string {
	normalized := strings.ToLower(strings.TrimSpace(host))
	return strings.TrimSuffix(normalized, ".")
}
