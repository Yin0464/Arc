package outbound

import (
	"context"
	"crypto/sha256"
	"net"
	"strings"
	"sync"

	"github.com/metacubex/tls"
	utls "github.com/metacubex/utls"

	"arc/core/internal/store"
)

var fingerprintByName = map[string]utls.ClientHelloID{
	"chrome":                     utls.HelloChrome_Auto,
	"firefox":                    utls.HelloFirefox_Auto,
	"safari":                     utls.HelloSafari_Auto,
	"ios":                        utls.HelloIOS_Auto,
	"android":                    utls.HelloAndroid_11_OkHttp,
	"edge":                       utls.HelloEdge_Auto,
	"360":                        utls.Hello360_Auto,
	"qq":                         utls.HelloQQ_Auto,
	"chrome120":                  utls.HelloChrome_120,
	"firefox120":                 utls.HelloFirefox_120,
	"safari16":                   utls.HelloSafari_16_0,
	"chrome_psk":                 utls.HelloChrome_100_PSK,
	"chrome_psk_shuffle":         utls.HelloChrome_106_Shuffle,
	"chrome_padding_psk_shuffle": utls.HelloChrome_114_Padding_PSK_Shuf,
	"chrome_pq":                  utls.HelloChrome_115_PQ,
	"chrome_pq_psk":              utls.HelloChrome_115_PQ_PSK,
}

var (
	tlsSessionCache  = tls.NewLRUClientSessionCache(128)
	utlsSessionCache = utls.NewLRUClientSessionCache(128)

	randomFPOnce sync.Once
	randomFP     utls.ClientHelloID
	randomizedFP utls.ClientHelloID
)

func init() {
	w := utls.DefaultWeights
	w.TLSVersMax_Set_VersionTLS13 = 1
	w.FirstKeyShare_Set_CurveP256 = 0
	randomizedFP = utls.HelloRandomized
	randomizedFP.Seed, _ = utls.NewPRNGSeed()
	randomizedFP.Weights = &w
}

func clientHelloID(name string) (utls.ClientHelloID, bool) {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" || name == "none" {
		return utls.ClientHelloID{}, false
	}
	if name == "randomized" {
		return randomizedFP, true
	}
	if name == "random" {
		randomFPOnce.Do(func() {
			// chrome:6 safari:3 ios:2 firefox:1
			n := int(sha256.Sum256([]byte("arc-random-fp"))[0]) % 12
			switch {
			case n < 6:
				randomFP = utls.HelloChrome_Auto
			case n < 9:
				randomFP = utls.HelloSafari_Auto
			case n < 11:
				randomFP = utls.HelloIOS_Auto
			default:
				randomFP = utls.HelloFirefox_Auto
			}
		})
		return randomFP, true
	}
	id, ok := fingerprintByName[name]
	return id, ok
}

func nodeTLS(ctx context.Context, conn net.Conn, sni string, o *store.NodeOpts, defALPN []string) (net.Conn, error) {
	if o == nil {
		o = &store.NodeOpts{}
	}
	alpn := o.ALPN
	if alpn == nil {
		alpn = defALPN
	}
	if fp, ok := clientHelloID(o.Fingerprint); ok {
		uc := utls.UClient(conn, &utls.Config{
			ServerName:         sni,
			InsecureSkipVerify: o.SkipCertVerify,
			NextProtos:         alpn,
			ClientSessionCache: utlsSessionCache,
		}, fp)
		if err := uc.HandshakeContext(ctx); err != nil {
			return nil, err
		}
		return uc, nil
	}
	tc := tls.Client(conn, &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: o.SkipCertVerify,
		NextProtos:         alpn,
		ClientSessionCache: tlsSessionCache,
	})
	if err := tc.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	return tc, nil
}
