package engine

import (
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

func TestPipeHalfCloseKeepsSlowResponse(t *testing.T) {
	leftClient, leftServer := tcpPair(t)
	rightClient, rightServer := tcpPair(t)
	errc := make(chan error, 1)
	go func() {
		buf, err := io.ReadAll(rightServer)
		if err != nil {
			errc <- err
			return
		}
		if string(buf) != "GET" {
			errc <- fmt.Errorf("request %q", buf)
			return
		}
		time.Sleep(1200 * time.Millisecond)
		_, err = rightServer.Write([]byte("OK!"))
		errc <- err
		rightServer.Close()
	}()
	go pipeStreams(leftServer, rightClient)

	if _, err := leftClient.Write([]byte("GET")); err != nil {
		t.Fatal(err)
	}
	if err := leftClient.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 3)
	_ = leftClient.SetReadDeadline(time.Now().Add(4 * time.Second))
	if _, err := io.ReadFull(leftClient, got); err != nil || string(got) != "OK!" {
		t.Fatalf("response %q %v", got, err)
	}
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
}

func tcpPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	done := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			t.Error(err)
			return
		}
		done <- c
	}()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server := <-done
	t.Cleanup(func() {
		client.Close()
		server.Close()
	})
	return client, server
}

func TestPeekedConnForwardsCloseWrite(t *testing.T) {
	inner := &recordCloseWrite{}
	closeWrite(&peekedConn{Conn: inner})
	if !inner.hit {
		t.Fatal("sniffed conn dropped CloseWrite")
	}
}

type recordCloseWrite struct {
	net.Conn
	hit bool
}

func (c *recordCloseWrite) CloseWrite() error {
	c.hit = true
	return nil
}
