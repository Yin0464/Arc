package anytls

import (
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

type Stream struct {
	id            uint32
	sess          *Session
	pipeR         *PipeReader
	pipeW         *PipeWriter
	writeDeadline PipeDeadline
	dieOnce       sync.Once
	dieHook       func()
	dieErr        atomic.Pointer[error]
}

func (s *Stream) storedDieErr() error {
	if p := s.dieErr.Load(); p != nil {
		return *p
	}
	return nil
}

func newStream(id uint32, sess *Session) *Stream {
	s := &Stream{id: id, sess: sess, writeDeadline: MakePipeDeadline()}
	s.pipeR, s.pipeW = Pipe()
	return s
}

func (s *Stream) Read(b []byte) (n int, err error) {
	n, err = s.pipeR.Read(b)
	if n == 0 {
		if de := s.storedDieErr(); de != nil {
			err = de
		}
	}
	return
}

func (s *Stream) Write(b []byte) (n int, err error) {
	select {
	case <-s.writeDeadline.Wait():
		return 0, os.ErrDeadlineExceeded
	default:
	}
	if de := s.storedDieErr(); de != nil {
		return 0, de
	}
	return s.sess.writeDataFrame(s.id, b)
}

func (s *Stream) Close() error { return s.closeWithError(io.ErrClosedPipe) }

func (s *Stream) closeLocally() {
	var once bool
	s.dieOnce.Do(func() {
		err := net.ErrClosed
		s.dieErr.Store(&err)
		s.pipeR.Close()
		once = true
	})
	if once && s.dieHook != nil {
		s.dieHook()
		s.dieHook = nil
	}
}

func (s *Stream) closeWithError(err error) error {
	var once bool
	s.dieOnce.Do(func() {
		s.dieErr.Store(&err)
		s.pipeR.Close()
		once = true
	})
	if once {
		e := s.sess.streamClosed(s.id)
		if s.dieHook != nil {
			s.dieHook()
			s.dieHook = nil
		}
		return e
	}
	return s.storedDieErr()
}

func (s *Stream) SetReadDeadline(t time.Time) error  { return s.pipeR.SetReadDeadline(t) }
func (s *Stream) SetWriteDeadline(t time.Time) error { s.writeDeadline.Set(t); return nil }
func (s *Stream) SetDeadline(t time.Time) error {
	s.SetWriteDeadline(t)
	return s.SetReadDeadline(t)
}

func (s *Stream) LocalAddr() net.Addr {
	if s.sess.conn != nil {
		return s.sess.conn.LocalAddr()
	}
	return nil
}

func (s *Stream) RemoteAddr() net.Addr {
	if s.sess.conn != nil {
		return s.sess.conn.RemoteAddr()
	}
	return nil
}
