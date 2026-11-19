package sniff

import "testing"

func FuzzSniff(f *testing.F) {
	f.Add([]byte("GET / HTTP/1.1\r\nHost: a.b\r\n\r\n"))
	f.Fuzz(func(t *testing.T, b []byte) { _ = TLSRecordReady(b); _ = TLSSNI(b); _ = HTTPHost(b) })
}
