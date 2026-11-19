package engine

import (
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"arc/core/internal/dnswire"
)

func TestTCPDNSServesSeveralQueries(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	done := make(chan struct{})
	go func() { handleTCPDNSConn(server); close(done) }()
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	for i, name := range []string{"www.google.com", "mail.google.com"} {
		q := dnswire.Query(name, dnswire.TypeA)
		if _, err := client.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(q))), q...)); err != nil {
			t.Fatalf("query %d: %v", i, err)
		}
		var hdr [2]byte
		if _, err := io.ReadFull(client, hdr[:]); err != nil {
			t.Fatalf("answer %d: %v", i, err)
		}
		resp := make([]byte, binary.BigEndian.Uint16(hdr[:]))
		if _, err := io.ReadFull(client, resp); err != nil {
			t.Fatalf("answer %d body: %v", i, err)
		}
		if dnswire.AnswerCount(resp) == 0 {
			t.Fatalf("answer %d empty", i)
		}
	}
	_ = client.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not exit after the client closed")
	}
}
