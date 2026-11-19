package anytls

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type Client struct {
	die       context.Context
	dieCancel context.CancelFunc
	dialOut   DialOutFunc

	sessionCounter atomic.Uint64

	idleMu       sync.Mutex
	idleSessions []*Session

	sessionsMu sync.Mutex
	sessions   map[uint64]*Session

	padding            *atomic.Pointer[PaddingFactory]
	clientMetadata     string
	idleSessionTimeout time.Duration
	minIdleSession     int
	disableReuse       bool
}

func NewClient(ctx context.Context, dialOut DialOutFunc, padding *atomic.Pointer[PaddingFactory], clientMetadata string, idleSessionCheckInterval, idleSessionTimeout time.Duration, minIdleSession int, disableReuse bool) *Client {
	c := &Client{
		sessions:           make(map[uint64]*Session),
		dialOut:            dialOut,
		padding:            padding,
		clientMetadata:     clientMetadata,
		idleSessionTimeout: idleSessionTimeout,
		minIdleSession:     minIdleSession,
		disableReuse:       disableReuse,
	}
	// The configured values are authoritative; the pool and codegen only pass
	// positive ones, so anything else is a programming error.
	if idleSessionCheckInterval <= 0 {
		panic(fmt.Sprintf("anytls: idle session check interval %v must be positive", idleSessionCheckInterval))
	}
	if idleSessionTimeout <= 0 {
		panic(fmt.Sprintf("anytls: idle session timeout %v must be positive", idleSessionTimeout))
	}
	if minIdleSession < 0 {
		panic(fmt.Sprintf("anytls: min idle session %d must not be negative", minIdleSession))
	}
	c.die, c.dieCancel = context.WithCancel(ctx)
	if !c.disableReuse {
		startRoutine(c.die, idleSessionCheckInterval, c.idleCleanup)
	}
	return c
}

func (c *Client) CreateStream(ctx context.Context) (net.Conn, error) {
	select {
	case <-c.die.Done():
		return nil, io.ErrClosedPipe
	default:
	}
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		var session *Session
		if !c.disableReuse {
			session = c.getIdleSession()
		}
		if session == nil {
			var err error
			session, err = c.createSession(ctx)
			if session == nil {
				lastErr = err
				continue
			}
		}
		stream, err := session.OpenStream()
		if err != nil {
			_ = session.Close()
			lastErr = err
			continue
		}
		stream.dieHook = func() {
			if session.IsClosed() {
				return
			}
			if c.disableReuse {
				_ = session.Close()
				return
			}
			select {
			case <-c.die.Done():
				_ = session.Close()
			default:
				c.idleMu.Lock()
				if !session.IsClosed() {
					session.idleSince = time.Now()
					c.idleSessions = append([]*Session{session}, c.idleSessions...)
				}
				c.idleMu.Unlock()
			}
		}
		return stream, nil
	}
	if lastErr == nil {
		lastErr = io.ErrClosedPipe
	}
	return nil, fmt.Errorf("failed to create stream: %w", lastErr)
}

func (c *Client) getIdleSession() *Session {
	c.idleMu.Lock()
	defer c.idleMu.Unlock()
	for len(c.idleSessions) > 0 {
		s := c.idleSessions[0]
		c.idleSessions = c.idleSessions[1:]
		if !s.IsClosed() {
			return s
		}
	}
	return nil
}

func (c *Client) createSession(ctx context.Context) (*Session, error) {
	underlying, err := c.dialOut(ctx)
	if err != nil {
		return nil, err
	}
	session := NewClientSession(underlying, c.padding, c.clientMetadata)
	session.seq = c.sessionCounter.Add(1)
	session.dieHook = func() {
		if !c.disableReuse {
			c.idleMu.Lock()
			out := c.idleSessions[:0]
			for _, s := range c.idleSessions {
				if s != session {
					out = append(out, s)
				}
			}
			c.idleSessions = out
			c.idleMu.Unlock()
		}
		c.sessionsMu.Lock()
		delete(c.sessions, session.seq)
		c.sessionsMu.Unlock()
	}
	c.sessionsMu.Lock()
	c.sessions[session.seq] = session
	c.sessionsMu.Unlock()
	session.Run()
	return session, nil
}

func (c *Client) Close() error {
	c.dieCancel()
	c.sessionsMu.Lock()
	toClose := make([]*Session, 0, len(c.sessions))
	for _, s := range c.sessions {
		toClose = append(toClose, s)
	}
	c.sessions = make(map[uint64]*Session)
	c.sessionsMu.Unlock()
	for _, s := range toClose {
		s.Close()
	}
	return nil
}

// CloseIdle closes every pooled session that has no open stream. Sessions
// carrying a stream are left alone.
func (c *Client) CloseIdle() int {
	c.idleMu.Lock()
	idle := c.idleSessions
	c.idleSessions = nil
	c.idleMu.Unlock()
	for _, s := range idle {
		_ = s.Close()
	}
	return len(idle)
}

func (c *Client) idleCleanup() {
	expTime := time.Now().Add(-c.idleSessionTimeout)
	activeCount := 0
	c.idleMu.Lock()
	var toClose []*Session
	kept := c.idleSessions[:0]
	for _, session := range c.idleSessions {
		if !session.idleSince.Before(expTime) {
			kept = append(kept, session)
			activeCount++
			continue
		}
		if activeCount < c.minIdleSession {
			session.idleSince = time.Now()
			kept = append(kept, session)
			activeCount++
			continue
		}
		toClose = append(toClose, session)
	}
	c.idleSessions = kept
	c.idleMu.Unlock()
	for _, s := range toClose {
		s.Close()
	}
}

func (c *Client) Warm(ctx context.Context, n int) {
	if c.disableReuse || n <= 0 {
		return
	}
	c.idleMu.Lock()
	have := 0
	for _, s := range c.idleSessions {
		if !s.IsClosed() {
			have++
		}
	}
	c.idleMu.Unlock()
	for have < n {
		select {
		case <-ctx.Done():
			return
		case <-c.die.Done():
			return
		default:
		}
		session, err := c.createSession(ctx)
		if err != nil || session == nil {
			return
		}
		c.idleMu.Lock()
		closed := session.IsClosed()
		if !closed {
			session.idleSince = time.Now()
			c.idleSessions = append([]*Session{session}, c.idleSessions...)
		}
		c.idleMu.Unlock()
		if closed {
			return
		}
		have++
	}
}

func (c *Client) MinIdleSession() int { return c.minIdleSession }
