package outbound

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"arc/core/internal/store"
)

var (
	epDiskMu      sync.Mutex
	epDiskPath    string
	epDisk        map[string]string
	epDiskSeq     uint64
	epDiskWriteMu sync.Mutex
	epDiskWritten uint64
)

const epDiskDialTimeout = 250 * time.Millisecond

func SetDataDir(dir string) {
	epDiskMu.Lock()
	defer epDiskMu.Unlock()
	epDiskPath = filepath.Join(dir, "ep_cache.json")
	epDisk = map[string]string{}
	if b, err := os.ReadFile(epDiskPath); err == nil {
		_ = json.Unmarshal(b, &epDisk)
	}
	for k := range epDisk {
		if strings.Count(k, "|") != 2 {
			delete(epDisk, k)
		}
	}
}

func epKey(a *store.Region, epID uint8, proto store.Protocol) string {
	return a.Name + "|" + strconv.Itoa(int(proto)) + "|" + store.Get().Endpoints[epID]
}

func diskEP(a *store.Region, epID uint8, proto store.Protocol) (netip.Addr, bool) {
	epDiskMu.Lock()
	s, ok := epDisk[epKey(a, epID, proto)]
	epDiskMu.Unlock()
	if ok {
		ip, err := netip.ParseAddr(s)
		return ip, err == nil
	}
	return netip.Addr{}, false
}

func saveDiskEP(a *store.Region, epID uint8, proto store.Protocol, ip netip.Addr, gen uint64) {
	key := epKey(a, epID, proto)
	epDiskMu.Lock()
	if epDiskPath == "" || flowGen.Load() != gen || epDisk[key] == ip.String() {
		epDiskMu.Unlock()
		return
	}
	epDisk[key] = ip.String()
	epDiskSeq++
	seq := epDiskSeq
	snap := make(map[string]string, len(epDisk))
	for k, v := range epDisk {
		snap[k] = v
	}
	path := epDiskPath
	epDiskMu.Unlock()

	b, err := json.Marshal(snap)
	if err != nil {
		return
	}
	epDiskWriteMu.Lock()
	defer epDiskWriteMu.Unlock()
	if seq < epDiskWritten {
		return
	}
	tmp := path + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil && os.Rename(tmp, path) == nil {
		epDiskWritten = seq
	}
}

type dialRes struct {
	c   net.Conn
	err error
}

var errSkipAlt = errors.New("alternate endpoint skipped")

func drainConns(ch <-chan dialRes, n int) {
	for i := 0; i < n; i++ {
		if r := <-ch; r.c != nil {
			_ = r.c.Close()
		}
	}
}

func happyEyeballsTCP(ctx context.Context, delay time.Duration,
	primary netip.Addr,
	alt func(context.Context) (netip.Addr, error),
	dial func(context.Context, string, string) (net.Conn, error),
	port uint16) (net.Conn, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ch := make(chan dialRes, 2)
	try := func(ip netip.Addr) {
		c, err := dial(ctx, "tcp", netip.AddrPortFrom(ip, port).String())
		ch <- dialRes{c, err}
	}
	go try(primary)
	pending := 1
	t := time.NewTimer(delay)
	defer t.Stop()
	altStarted := false
	var last error
	startAlt := func() {
		if altStarted || ctx.Err() != nil {
			return
		}
		altStarted = true
		pending++
		go func() {
			ip, err := alt(ctx)
			if err != nil || !ip.IsValid() || ip == primary {
				if err == nil {
					err = errSkipAlt
				}
				ch <- dialRes{nil, err}
				return
			}
			try(ip)
		}()
	}
	for pending > 0 {
		select {
		case r := <-ch:
			pending--
			if r.err == nil {
				go drainConns(ch, pending)
				return r.c, nil
			}
			if !errors.Is(r.err, errSkipAlt) {
				last = r.err
			}
			startAlt()
		case <-t.C:
			startAlt()
		}
	}
	if last == nil {
		last = errors.New("dial failed")
	}
	return nil, last
}

func raceStaleDial(ctx context.Context, a *store.Region, epID uint8, port uint16, stale netip.Addr, proto store.Protocol,
	dial func(ctx context.Context, network, addr string) (net.Conn, error)) (net.Conn, error) {
	return happyEyeballsTCP(ctx, epDiskDialTimeout, stale,
		func(ctx context.Context) (netip.Addr, error) {
			return ResolveEndpoint(ctx, a, epID, proto)
		}, dial, port)
}
