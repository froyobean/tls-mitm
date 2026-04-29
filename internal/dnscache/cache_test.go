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

func TestCacheLookupCleansOtherExpiredEntries(t *testing.T) {
	now := time.Unix(100, 0)
	cache := New("www.example.com", func() time.Time { return now })
	cache.Store("www.example.com", netip.MustParseAddr("93.184.216.34"), time.Second)
	cache.Store("www.example.com", netip.MustParseAddr("93.184.216.35"), 5*time.Second)

	now = now.Add(2 * time.Second)
	entry, ok := cache.Lookup(netip.MustParseAddr("93.184.216.35"))
	if !ok {
		t.Fatal("expected unexpired entry to hit")
	}
	if entry.IP.String() != "93.184.216.35" {
		t.Fatalf("unexpected entry: %+v", entry)
	}
	if _, stale := cache.byIP[netip.MustParseAddr("93.184.216.34")]; stale {
		t.Fatal("expected expired sibling entry to be cleaned during lookup")
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

func TestCacheNormalizesTrailingDot(t *testing.T) {
	now := time.Unix(100, 0)
	cache := New("www.example.com.", func() time.Time { return now })
	cache.Store("www.example.com", netip.MustParseAddr("93.184.216.34"), 300*time.Second)

	entry, ok := cache.Lookup(netip.MustParseAddr("93.184.216.34"))
	if !ok {
		t.Fatal("expected cache hit with trailing dot normalization")
	}
	if entry.Host != "www.example.com" {
		t.Fatalf("unexpected normalized host: %+v", entry)
	}
}

func TestCacheRejectsIPv6(t *testing.T) {
	now := time.Unix(100, 0)
	cache := New("www.example.com", func() time.Time { return now })

	if _, ok := cache.Store("www.example.com", netip.MustParseAddr("2001:db8::1"), 300*time.Second); ok {
		t.Fatal("expected IPv6 record to be ignored")
	}
	if _, ok := cache.Lookup(netip.MustParseAddr("2001:db8::1")); ok {
		t.Fatal("expected IPv6 lookup to miss")
	}
}
