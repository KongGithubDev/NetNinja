package main

// Tests for the geo routing data path: list parsing, pool election/rotation and
// the session (ads included) decision. They stay offline on purpose — the only
// network-touching helpers (geoLookup / country verification) are exercised on
// the server through /geo-check.

import (
	"context"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNormalizeGeoDomain(t *testing.T) {
	cases := map[string]string{
		"||ads.example^":   "ads.example",
		"*.example.com":    "example.com",
		"Example.COM.":     "example.com",
		"example.com:8080": "example.com",
		"example.com/path": "example.com",
		"  ome.tv  ":       "ome.tv",
		"localhost":        "",
		"tv":               "",
		"":                 "",
	}
	for in, want := range cases {
		if got := normalizeGeoDomain(in); got != want {
			t.Errorf("normalizeGeoDomain(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseGeoDomainListShapes(t *testing.T) {
	in := "# comment\nome.tv\n||ads.example^\n*.chat.example\nfoo.com, bar.net\n#tail\n"
	got := parseGeoDomainList(strings.NewReader(in))
	want := []string{"ome.tv", "ads.example", "chat.example", "foo.com", "bar.net"}
	if len(got) != len(want) {
		t.Fatalf("parseGeoDomainList = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("parseGeoDomainList = %v, want %v", got, want)
		}
	}
}

func TestInGeoDomainsMatchesSubdomainsOnly(t *testing.T) {
	geoDomains.Store(buildGeoDomainSet([]string{"ome.tv", "chat.example"}))
	defer geoDomains.Store(&geoDomainSet{set: map[string]struct{}{}})

	for _, h := range []string{"ome.tv", "www.ome.tv", "a.b.ome.tv", "x.chat.example", "OME.TV", "ome.tv:443"} {
		if !inGeoDomains(h) {
			t.Errorf("inGeoDomains(%q) = false, want true", h)
		}
	}
	for _, h := range []string{"notome.tv", "ome.tv.evil.com", "tv", "example.com", ""} {
		if inGeoDomains(h) {
			t.Errorf("inGeoDomains(%q) = true, want false", h)
		}
	}
}

func resetGeoPoolForTest(t testing.TB, addrs ...string) []*geoNode {
	t.Helper()
	geoPoolMu.Lock()
	geoPool = nil
	geoPoolCur = nil
	geoPoolMu.Unlock()
	syncGeoPool(addrs, "test")
	geoPoolOn = true
	nodes := geoPoolSnapshot()
	if len(nodes) != len(addrs) {
		t.Fatalf("pool has %d node(s), want %d", len(nodes), len(addrs))
	}
	for _, n := range nodes {
		n.mu.Lock()
		n.country = geoExpectCountry()
		n.mu.Unlock()
	}
	return nodes
}

func TestGeoPoolSticksThenFailsOver(t *testing.T) {
	geoPoolMaxRTT = 1500 * time.Millisecond
	geoPoolSlowHits = 3
	geoPoolFailHits = 2
	nodes := resetGeoPoolForTest(t, "a:1080", "b:1080")
	a, b := nodes[0], nodes[1]

	geoMarkResult(a, nil, 50*time.Millisecond)
	geoMarkResult(b, nil, 300*time.Millisecond)

	if got := pickGeoNode(nil); got != a {
		t.Fatalf("first pick = %v, want the fastest node a", got)
	}
	if got := pickGeoNode(nil); got != a {
		t.Fatalf("second pick = %v, want the sticky node a", got)
	}

	// One failure is not enough: the node keeps its turn.
	geoMarkResult(a, context.DeadlineExceeded, 0)
	if got := pickGeoNode(nil); got != a {
		t.Fatalf("pick after a single failure = %v, want a still sticky", got)
	}
	geoMarkResult(a, context.DeadlineExceeded, 0)
	if got := pickGeoNode(nil); got != b {
		t.Fatalf("pick after two failures = %v, want failover to b", got)
	}
	if geoPoolCurrentAddr() != b.addr {
		t.Fatalf("current = %q, want %q", geoPoolCurrentAddr(), b.addr)
	}
}

func TestGeoPoolRotatesOffSlowNode(t *testing.T) {
	geoPoolMaxRTT = 100 * time.Millisecond
	geoPoolSlowHits = 2
	geoPoolFailHits = 2
	nodes := resetGeoPoolForTest(t, "slow:1080", "fast:1080")
	slow, fast := nodes[0], nodes[1]

	geoMarkResult(fast, nil, 10*time.Millisecond)
	geoMarkResult(slow, nil, 900*time.Millisecond)
	geoMarkResult(slow, nil, 900*time.Millisecond)

	if slow.healthy(geoExpectCountry()) {
		t.Fatal("node stayed usable after repeated slow dials")
	}
	if got := pickGeoNode(nil); got != fast {
		t.Fatalf("pick = %v, want fast", got)
	}
}

func TestGeoPoolNeverUsesWrongCountry(t *testing.T) {
	geoPoolMaxRTT = 1500 * time.Millisecond
	geoPoolSlowHits = 3
	geoPoolFailHits = 2
	nodes := resetGeoPoolForTest(t, "jp:1080", "th:1080")
	jp, th := nodes[0], nodes[1]

	jp.mu.Lock()
	jp.country = "JP"
	jp.mu.Unlock()

	geoMarkResult(jp, nil, 10*time.Millisecond) // fastest, but exits the wrong country
	geoMarkResult(th, nil, 400*time.Millisecond)

	if got := pickGeoNode(nil); got != th {
		t.Fatalf("pick = %v, want the Thai node even though JP is faster", got)
	}
}

func TestGeoEgressAdsFollowSession(t *testing.T) {
	adBlockMu.Lock()
	prevDoms, prevAllow := adBlockDomains, adBlockAllow
	adBlockDomains = map[string]struct{}{"doubleclick.net": {}, "ads.example": {}}
	adBlockAllow = nil
	adBlockMu.Unlock()
	defer func() {
		adBlockMu.Lock()
		adBlockDomains, adBlockAllow = prevDoms, prevAllow
		adBlockMu.Unlock()
	}()

	geoDomains.Store(buildGeoDomainSet([]string{"ome.tv"}))
	defer geoDomains.Store(&geoDomainSet{set: map[string]struct{}{}})

	prevMode, prevTTL, prevAds := geoSessionMode, geoSessionTTL, geoAdsGlobal
	geoSessionMode, geoSessionTTL, geoAdsGlobal = "all", time.Minute, false
	defer func() { geoSessionMode, geoSessionTTL, geoAdsGlobal = prevMode, prevTTL, prevAds }()

	const key = "ip:203.0.113.9"
	ctx := ctxWithGeoKey(context.Background(), key)

	if via, why := geoEgressFor(ctx, "ads.doubleclick.net", ""); via {
		t.Fatalf("ad host egressed Thai before any geo session (%s)", why)
	}
	noteGeoSession(key)

	if via, why := geoEgressFor(ctx, "ads.doubleclick.net", ""); !via || why != "ad" {
		t.Fatalf("ad host in a session = (%v,%q), want (true,ad)", via, why)
	}
	if via, why := geoEgressFor(ctx, "assets.third-party.example", ""); !via || why != "session" {
		t.Fatalf("session host = (%v,%q), want (true,session)", via, why)
	}
	if via, why := geoEgressFor(ctx, "ome.tv", ""); !via || why != "geo" {
		t.Fatalf("geo domain = (%v,%q), want (true,geo)", via, why)
	}
	if via, _ := geoEgressFor(ctx, "r1---sn-abc.googlevideo.com", ""); via {
		t.Fatal("video CDN should stay direct even inside a session (speed)")
	}
	// Another client, same host: no session, no Thai egress.
	otherCtx := ctxWithGeoKey(context.Background(), "ip:198.51.100.7")
	if via, _ := geoEgressFor(otherCtx, "assets.third-party.example", ""); via {
		t.Fatal("a different client must not inherit the geo session")
	}
}

func TestGeoAdsGlobalRoutesEveryClient(t *testing.T) {
	adBlockMu.Lock()
	prevDoms, prevAllow := adBlockDomains, adBlockAllow
	adBlockDomains = map[string]struct{}{"doubleclick.net": {}}
	adBlockAllow = nil
	adBlockMu.Unlock()
	defer func() {
		adBlockMu.Lock()
		adBlockDomains, adBlockAllow = prevDoms, prevAllow
		adBlockMu.Unlock()
	}()

	geoDomains.Store(buildGeoDomainSet([]string{"ome.tv"}))
	defer geoDomains.Store(&geoDomainSet{set: map[string]struct{}{}})

	prevAds, prevMode := geoAdsGlobal, geoSessionMode
	geoAdsGlobal, geoSessionMode = true, "all"
	defer func() { geoAdsGlobal, geoSessionMode = prevAds, prevMode }()

	ctx := ctxWithGeoKey(context.Background(), "ip:203.0.113.9")
	if via, why := geoEgressFor(ctx, "static.doubleclick.net", ""); !via || why != "ad" {
		t.Fatalf("GEO_ADS_EGRESS=1 must localise ads for every client, got (%v,%q)", via, why)
	}
}

// BenchmarkGeoEgressForDialPath measures what every connection pays for geo
// routing: with a 100k-entry domain list and a 50k-entry ad list loaded, the
// common path must stay in the nanosecond range so the pool costs nothing next
// to the dial itself.
func BenchmarkGeoEgressForDialPath(b *testing.B) {
	list := make([]string, 0, 100000)
	list = append(list, "ome.tv", "chatroulette.com")
	for i := 0; i < 100000; i++ {
		list = append(list, fmt.Sprintf("site%d.example%d.com", i, i%997))
	}
	geoDomains.Store(buildGeoDomainSet(list))
	defer geoDomains.Store(&geoDomainSet{set: map[string]struct{}{}})

	adBlockMu.Lock()
	prevDoms := adBlockDomains
	doms := make(map[string]struct{}, 50000)
	for i := 0; i < 50000; i++ {
		doms[fmt.Sprintf("ad%d.tracker%d.net", i, i%97)] = struct{}{}
	}
	adBlockDomains = doms
	adBlockMu.Unlock()
	defer func() {
		adBlockMu.Lock()
		adBlockDomains = prevDoms
		adBlockMu.Unlock()
	}()

	geoPoolMaxRTT = 1500 * time.Millisecond
	geoPoolSlowHits = 3
	geoPoolFailHits = 2
	resetGeoPoolForTest(b, "a:1080", "b:1080", "c:1080")

	prevMode, prevTTL := geoSessionMode, geoSessionTTL
	geoSessionMode, geoSessionTTL = "all", time.Minute
	defer func() { geoSessionMode, geoSessionTTL = prevMode, prevTTL }()

	plain := ctxWithGeoKey(context.Background(), "ip:203.0.113.9")
	session := ctxWithGeoKey(context.Background(), "ip:198.51.100.7")
	noteGeoSession("ip:198.51.100.7")

	b.Run("no-session-common-path", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if via, _ := geoEgressFor(plain, "www.somewhere.example", "93.184.216.34:443"); via {
				b.Fatal("unexpected Thai egress")
			}
		}
	})
	b.Run("geo-domain-hit", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if via, why := geoEgressFor(plain, "www.ome.tv", "93.184.216.34:443"); !via || why != "geo" {
				b.Fatalf("got (%v,%q)", via, why)
			}
		}
	})
	b.Run("inside-session", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, why := geoEgressFor(session, "www.somewhere.example", "93.184.216.34:443"); why != "session" {
				b.Fatalf("got %q", why)
			}
		}
	})
}

func TestServePACIsUsableByIPadOS(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://proxy.example/proxy.pac", nil)
	servePAC(rec, req)

	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "ns-proxy-autoconfig") {
		t.Fatalf("Content-Type = %q, want application/x-ns-proxy-autoconfig", ct)
	}
	if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Fatalf("Cache-Control = %q, want no-store", cc)
	}
	body := rec.Body.String()
	for _, want := range []string{"FindProxyForURL", "PROXY ", "dnsDomainIs(host, \"speedtest.net\")", "dnsDomainIs(host, \"googlevideo.com\")"} {
		if !strings.Contains(body, want) {
			t.Fatalf("PAC body is missing %q:\n%s", want, body)
		}
	}
}
