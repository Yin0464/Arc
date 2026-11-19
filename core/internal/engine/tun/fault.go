package tun

import (
	"errors"
	"syscall"
	"time"
)

const (
	tunFaultWindowLimit = 10 * time.Second
	tunFaultMinCount    = 5
	TransientBackoff    = 2 * time.Millisecond
)

type FaultDisposition int

const (
	FaultTransient FaultDisposition = iota
	FaultPeerGone
)

type FaultWindow struct {
	limit     time.Duration
	minFaults uint64
	started   time.Time
	last      time.Time
	faults    uint64
}

func NewFaultWindow() FaultWindow {
	return FaultWindow{limit: tunFaultWindowLimit, minFaults: tunFaultMinCount}
}

func (w *FaultWindow) RecordSuccess() {
	if w.faults == 0 && w.started.IsZero() {
		return
	}
	w.started = time.Time{}
	w.last = time.Time{}
	w.faults = 0
}

func (w *FaultWindow) RecordFault(now time.Time) bool {
	if !w.last.IsZero() && now.Sub(w.last) > w.limit {
		w.started = time.Time{}
		w.faults = 0
	}
	if w.started.IsZero() {
		w.started = now
	}
	w.last = now
	w.faults++
	return w.faults >= w.minFaults && !w.started.IsZero() && now.Sub(w.started) >= w.limit
}

// tunErrno unwraps err (including *os.PathError and *os.SyscallError) to its errno.
func tunErrno(err error) (errno syscall.Errno, ok bool) {
	ok = errors.As(err, &errno)
	return errno, ok
}

func FaultKind(err error) FaultDisposition {
	errno, ok := tunErrno(err)
	if !ok {
		return FaultTransient
	}
	switch errno {
	case syscall.EPIPE, syscall.ECONNRESET, syscall.ENOTCONN, syscall.EBADF,
		syscall.ECONNREFUSED, syscall.ENOTSOCK, syscall.ENODEV, syscall.ENXIO:
		return FaultPeerGone
	default:
		return FaultTransient
	}
}
