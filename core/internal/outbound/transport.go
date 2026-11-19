package outbound

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"arc/core/internal/dnswire"
	"arc/core/internal/protect"
	"arc/core/internal/store"
)

const (
	LineDialTimeout = 4 * time.Second
	ProbeTimeout    = LineDialTimeout + 2*time.Second
)

type TargetAddr struct {
	Domain string
	IP     netip.Addr
	Port   uint16
}

func (t TargetAddr) String() string {
	if t.Domain != "" {
		return net.JoinHostPort(t.Domain, strconv.Itoa(int(t.Port)))
	}
	return netip.AddrPortFrom(t.IP, t.Port).String()
}

var activeCursor atomic.Uint32

func SwitchActive(regionIdx, nodeIdx int) {
	regions := store.Get().Regions
	if regionIdx < 0 || regionIdx >= len(regions) {
		return
	}
	if nodeIdx < 0 || nodeIdx >= len(regions[regionIdx].Nodes) {
		return
	}
	activeCursor.Store((uint32(regionIdx) << 16) | (uint32(nodeIdx) & 0xFFFF))
}

// GetActiveNode returns the selected node, or nils before a catalog loads.
func GetActiveNode() (*store.Region, *store.Node) {
	v := activeCursor.Load()
	ai, ni := int(v>>16), int(v&0xFFFF)
	regions := store.Get().Regions
	if len(regions) == 0 {
		return nil, nil
	}
	if ai >= len(regions) {
		ai = 0
	}
	a := &regions[ai]
	if ni >= len(a.Nodes) {
		ni = 0
	}
	return a, &a.Nodes[ni]
}

var (
	flowGen atomic.Uint64
	epCache [2][store.MaxEndpoints]atomic.Pointer[netip.Addr]
	epLocks [2][store.MaxEndpoints]sync.Mutex
)

// epSlot is the runtime endpoint cache for one (protocol, endpoint) pair, so
// an address learned through one profile's private DoH never serves the other.
func epSlot(proto store.Protocol, epID uint8) *atomic.Pointer[netip.Addr] {
	return &epCache[proto-1][epID]
}

var (
	liveMu sync.Mutex
	live   = map[*liveConn]struct{}{}
)

// liveConn is a tracked outbound connection. last is the unix-nano time of
// its last successful read (dial time until the first byte arrives).
type liveConn struct {
	net.Conn
	last atomic.Int64
}

func (c *liveConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.last.Store(time.Now().UnixNano())
	}
	return n, err
}

func (c *liveConn) Close() error {
	liveMu.Lock()
	delete(live, c)
	liveMu.Unlock()
	return c.Conn.Close()
}

func (c *liveConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func trackConn(c net.Conn) net.Conn {
	lc := &liveConn{Conn: c}
	lc.last.Store(time.Now().UnixNano())
	liveMu.Lock()
	live[lc] = struct{}{}
	liveMu.Unlock()
	return lc
}

func TrackConn(c net.Conn) net.Conn { return trackConn(c) }

func closeTracked() {
	liveMu.Lock()
	old := live
	live = map[*liveConn]struct{}{}
	liveMu.Unlock()

	for c := range old {
		_ = c.SetDeadline(time.Now())
		go c.Conn.Close()
	}
}

// closeStale closes tracked connections that have received nothing for at
// least idle; connections still receiving data are kept.
func closeStale(idle time.Duration) int {
	cut := time.Now().Add(-idle).UnixNano()
	var stale []*liveConn
	liveMu.Lock()
	for c := range live {
		if c.last.Load() <= cut {
			stale = append(stale, c)
			delete(live, c)
		}
	}
	liveMu.Unlock()
	for _, c := range stale {
		_ = c.SetDeadline(time.Now())
		go c.Conn.Close()
	}
	return len(stale)
}

func CloseLiveConns() {
	flowGen.Add(1)
	closeProtoClients()
	closeTracked()
}

func ResolveEndpoint(ctx context.Context, region *store.Region, epID uint8, proto store.Protocol) (netip.Addr, error) {
	cat := store.Get()
	if int(epID) >= len(cat.Endpoints) {
		return netip.Addr{}, errors.New("bad endpoint")
	}
	// Endpoints resolve only through this protocol's private DoH.
	doh := cat.Profile(proto).DoHUrls
	gen := flowGen.Load()
	slot := epSlot(proto, epID)
	if cached := slot.Load(); cached != nil {
		return *cached, nil
	}
	epLocks[proto-1][epID].Lock()
	defer epLocks[proto-1][epID].Unlock()
	if cached := slot.Load(); cached != nil {
		return *cached, nil
	}
	respWire, err := RaceDoHServers(ctx, doh, dnswire.Query(cat.Endpoints[epID], dnswire.TypeA))
	if err != nil {
		return netip.Addr{}, err
	}
	ip, err := dnswire.FirstIP(respWire)
	if err == nil {
		publishEP(slot, ip, gen)
		saveDiskEP(region, epID, proto, ip, gen)
	}
	return ip, err
}

func publishEP(slot *atomic.Pointer[netip.Addr], ip netip.Addr, gen uint64) {
	if flowGen.Load() != gen {
		return
	}
	p := &ip
	slot.Store(p)
	if flowGen.Load() != gen {
		slot.CompareAndSwap(p, nil)
	}
}

func ClearEndpointCache() {
	CloseLiveConns()
	for p := range epCache {
		for i := range epCache[p] {
			epCache[p][i].Store(nil)
		}
	}
	dohIPCache.Clear()

	directDoH.CloseIdleConnections()
}

func InvalidateActive() {
	_, node := GetActiveNode()
	if node != nil {
		epSlot(node.Proto, node.EpID).Store(nil)
	}
	flowGen.Add(1)
	if node != nil {
		clearAnyTLSNode(node)
	}
	closeTracked()
	directDoH.CloseIdleConnections()
}

// dohRT is the tier-2 DoH transport (domestic encrypted DNS and the private
// DoH). It dials direct on protected sockets; hostnames come from tier 1.
type dohRT struct {
	mu sync.Mutex
	tr *http.Transport
}

func (d *dohRT) RoundTrip(req *http.Request) (*http.Response, error) {
	d.mu.Lock()
	tr := d.tr
	d.mu.Unlock()
	return tr.RoundTrip(req)
}

func (d *dohRT) CloseIdleConnections() {
	d.mu.Lock()
	old := d.tr
	d.tr = newDirectDoHTransport()
	d.mu.Unlock()
	go old.CloseIdleConnections()
}

func newDirectDoHTransport() *http.Transport {
	return &http.Transport{
		ForceAttemptHTTP2:     true,
		MaxIdleConnsPerHost:   6,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   4 * time.Second,
		ResponseHeaderTimeout: 4 * time.Second,
		ExpectContinueTimeout: time.Second,
		DialContext:           directDoHDial,
	}
}

func directDoHDial(ctx context.Context, network, addr string) (net.Conn, error) {
	gen := flowGen.Load()
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	if net.ParseIP(host) != nil {
		return protect.Dialer().DialContext(ctx, network, addr)
	}
	ip, err := resolveBootstrapHost(ctx, host, gen)
	if err != nil {
		return nil, err
	}
	return protect.Dialer().DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
}

var directDoH = &dohRT{tr: newDirectDoHTransport()}

var directDoHClient = &http.Client{Transport: directDoH}

// RaceDoHServers races tier-2 DoH urls direct (domestic or private DoH).
func RaceDoHServers(ctx context.Context, urls []string, rawQuery []byte) ([]byte, error) {
	return raceDoH(ctx, directDoHClient, urls, rawQuery)
}

func raceDoH(ctx context.Context, client *http.Client, urls []string, rawQuery []byte) ([]byte, error) {
	if len(rawQuery) < 12 {
		return nil, errors.New("short dns query")
	}
	b64 := base64.RawURLEncoding.EncodeToString(rawQuery)
	return dnswire.Race(ctx, 3*time.Second, len(urls), func(ctx context.Context, i int) ([]byte, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, urls[i]+"?dns="+b64, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/dns-message")
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		if err != nil || resp.StatusCode != http.StatusOK || len(body) < 12 {
			return nil, errors.New("bad doh response")
		}
		body[0], body[1] = rawQuery[0], rawQuery[1]
		return body, nil
	})
}
