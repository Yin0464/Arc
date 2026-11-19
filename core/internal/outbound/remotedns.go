package outbound

import (
	"context"
	"net"
	"net/http"
	"strconv"
	"time"
)

// RemoteDoHUrls is the pre-check resolver for names no rule matches. It is
// reached only through the active node: the TLS connection is a tunnelled
// TCP stream to the hostname, so the node resolves and dials it remotely.
var RemoteDoHUrls = [1]string{"https://dns.google/dns-query"}

// ClassifyECS is the mainland /24 client-subnet hint sent with pre-check
// queries, so CDN names that also serve China answer with their CN addresses.
var ClassifyECS = [3]byte{114, 114, 114}

func WithECS(q []byte) []byte {
	if len(q) < 12 || q[10] != 0 || q[11] != 0 {
		return q
	}
	out := append(make([]byte, 0, len(q)+22), q...)
	out[11] = 1
	return append(out,
		0, 0, 41, 0x10, 0x00, 0, 0, 0, 0,
		0, 11,
		0, 8, 0, 7,
		0, 1, 24, 0,
		ClassifyECS[0], ClassifyECS[1], ClassifyECS[2])
}

var remoteHTTPClient = &http.Client{Transport: &http.Transport{
	ForceAttemptHTTP2:     true,
	MaxIdleConnsPerHost:   2,
	IdleConnTimeout:       180 * time.Second,
	HTTP2:                 &http.HTTP2Config{SendPingTimeout: 30 * time.Second, PingTimeout: 5 * time.Second},
	TLSHandshakeTimeout:   5 * time.Second,
	ResponseHeaderTimeout: 5 * time.Second,
	DialContext:           remoteDialContext,
}}

func remoteDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return nil, err
	}
	return DialTCP(ctx, TargetAddr{Domain: host, Port: uint16(p)})
}

// RaceRemoteDoH sends one pre-check query through the active node.
func RaceRemoteDoH(ctx context.Context, rawQuery []byte) ([]byte, error) {
	return raceDoH(ctx, remoteHTTPClient, RemoteDoHUrls[:], WithECS(rawQuery))
}

func CloseRemoteDoH() { remoteHTTPClient.CloseIdleConnections() }
