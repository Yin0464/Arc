package protect

import (
	"net"
	"testing"
)

func TestControlFailsClosedWhenRequired(t *testing.T) {
	defer func() { Set(nil); SetRequired(false) }()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	defer ln.Close()
	addr := ln.Addr().String()

	Set(nil)
	SetRequired(false)
	if c, err := Dialer().Dial("tcp", addr); err != nil {
		t.Fatalf("no hook, not required: %v", err)
	} else {
		c.Close()
	}
	if !ProtectFD(3) {
		t.Fatal("ProtectFD should pass when not required")
	}

	SetRequired(true)
	if c, err := Dialer().Dial("tcp", addr); err == nil {
		c.Close()
		t.Fatal("required without hook must fail closed")
	}
	if ProtectFD(3) {
		t.Fatal("ProtectFD must fail closed when required")
	}

	calls := 0
	Set(func(int) bool { calls++; return true })
	if c, err := Dialer().Dial("tcp", addr); err != nil {
		t.Fatalf("hook ok: %v", err)
	} else {
		c.Close()
	}
	if calls == 0 {
		t.Fatal("hook not called")
	}
	Set(func(int) bool { return false })
	if c, err := Dialer().Dial("tcp", addr); err == nil {
		c.Close()
		t.Fatal("hook refusal must fail")
	}
}
