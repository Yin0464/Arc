package anytls

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"
)

type DialOutFunc func(ctx context.Context) (net.Conn, error)

type StringMap map[string]string

func (s StringMap) ToBytes() []byte {
	var lines []string
	for k, v := range s {
		lines = append(lines, k+"="+v)
	}
	return []byte(strings.Join(lines, "\n"))
}

func StringMapFromBytes(b []byte) StringMap {
	m := make(StringMap)
	for _, line := range strings.Split(string(b), "\n") {
		v := strings.SplitN(line, "=", 2)
		if len(v) == 2 {
			m[v[0]] = v[1]
		}
	}
	return m
}

func newDeadlineWatcher(ddl time.Duration, timeOut func()) (done func()) {
	t := time.NewTimer(ddl)
	closeCh := make(chan struct{})
	go func() {
		defer t.Stop()
		select {
		case <-closeCh:
		case <-t.C:
			timeOut()
		}
	}()
	var once sync.Once
	return func() {
		once.Do(func() { close(closeCh) })
	}
}

func startRoutine(ctx context.Context, d time.Duration, f func()) {
	go func() {
		t := time.NewTimer(d)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				f()
				t.Reset(d)
			}
		}
	}()
}
