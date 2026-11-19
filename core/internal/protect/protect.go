package protect

import (
	"errors"
	"net"
	"sync/atomic"
	"syscall"
	"time"
)

type Func func(fd int) bool

var hook atomic.Pointer[Func]

func Set(f Func) {
	if f == nil {
		hook.Store(nil)
		return
	}
	hook.Store(&f)
}

var errProtect = errors.New("VpnService.protect failed")

var required atomic.Bool

func SetRequired(on bool) { required.Store(on) }

func Control(network, address string, c syscall.RawConn) error {
	f := hook.Load()
	if f == nil {
		if required.Load() {
			return errProtect
		}
		return nil
	}
	ok := true
	if err := c.Control(func(fd uintptr) { ok = (*f)(int(fd)) }); err != nil {
		return err
	}
	if !ok {
		return errProtect
	}
	return nil
}

var (
	dialer = net.Dialer{
		Timeout: 10 * time.Second,
		KeepAliveConfig: net.KeepAliveConfig{
			Enable:   true,
			Idle:     15 * time.Second,
			Interval: 10 * time.Second,
			Count:    4,
		},
		Control: Control,
	}
	listenConfig = net.ListenConfig{Control: Control}
)

func Dialer() *net.Dialer { return &dialer }

func ListenConfig() *net.ListenConfig { return &listenConfig }

func ProtectFD(fd int) bool {
	f := hook.Load()
	if f == nil {
		return !required.Load()
	}
	return (*f)(fd)
}
