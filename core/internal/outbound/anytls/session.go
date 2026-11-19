package anytls

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

type Session struct {
	conn     net.Conn
	connLock sync.Mutex

	streams    map[uint32]*Stream
	streamID   atomic.Uint32
	streamLock sync.RWMutex

	dieOnce sync.Once
	die     chan struct{}
	dieHook func()

	synDone     func()
	synDoneLock sync.Mutex

	seq       uint64
	idleSince time.Time
	padding   *atomic.Pointer[PaddingFactory]

	peerVersion atomic.Uint32

	isClient       bool
	sendPadding    bool
	buffering      bool
	buffer         []byte
	pktCounter     atomic.Uint32
	clientMetadata string

	heartMu      sync.Mutex
	heartPending bool
	heartMisses  int
	heartEvery   time.Duration

	// recvBusy is set while recvLoop hands a payload to a stream that may be
	// back-pressured; lastRecv is the unix-nano time of the last frame read.
	// Either one proves the peer is alive, so heartbeats are not counted missed.
	recvBusy atomic.Bool
	lastRecv atomic.Int64
}

func NewClientSession(conn net.Conn, padding *atomic.Pointer[PaddingFactory], clientMetadata string) *Session {
	s := &Session{
		conn:           conn,
		isClient:       true,
		sendPadding:    true,
		padding:        padding,
		clientMetadata: clientMetadata,
		die:            make(chan struct{}),
		streams:        make(map[uint32]*Stream),
		heartEvery:     heartbeatInterval,
	}
	return s
}

func (s *Session) Run() {
	settings := StringMap{
		"v":           "2",
		"client":      s.clientMetadata,
		"padding-md5": s.padding.Load().Md5,
	}
	f := newFrame(cmdSettings, 0)
	f.data = settings.ToBytes()
	s.connLock.Lock()
	s.buffering = true
	s.connLock.Unlock()
	s.writeControlFrame(f)
	go s.recvLoop()
	if s.isClient {
		go s.heartbeatLoop()
	}
}

func (s *Session) IsClosed() bool {
	select {
	case <-s.die:
		return true
	default:
		return false
	}
}

func (s *Session) Close() error {
	var once bool
	s.dieOnce.Do(func() {
		_ = s.conn.SetDeadline(time.Now())
		close(s.die)
		once = true
	})
	if !once {
		return io.ErrClosedPipe
	}
	s.cancelSynDone()
	if s.dieHook != nil {
		s.dieHook()
		s.dieHook = nil
	}
	s.streamLock.Lock()
	for _, stream := range s.streams {
		stream.closeLocally()
	}
	s.streams = make(map[uint32]*Stream)
	s.streamLock.Unlock()
	return s.conn.Close()
}

func (s *Session) OpenStream() (*Stream, error) {
	if s.IsClosed() {
		return nil, io.ErrClosedPipe
	}
	sid := s.streamID.Add(1)
	stream := newStream(sid, s)
	if sid >= 2 && s.peerVersion.Load() >= 2 {
		s.synDoneLock.Lock()
		if s.synDone != nil {
			s.synDone()
		}
		s.synDone = newDeadlineWatcher(3*time.Second, func() { s.Close() })
		s.synDoneLock.Unlock()
	}
	// Register before the SYN goes out, so a fast peer reply (data, FIN or a
	// SYNACK error) on a reused session is never dropped as an unknown stream.
	s.streamLock.Lock()
	if s.IsClosed() {
		s.streamLock.Unlock()
		s.cancelSynDone()
		return nil, io.ErrClosedPipe
	}
	s.streams[sid] = stream
	s.streamLock.Unlock()
	if _, err := s.writeControlFrame(newFrame(cmdSYN, sid)); err != nil {
		s.streamLock.Lock()
		delete(s.streams, sid)
		s.streamLock.Unlock()
		s.cancelSynDone()
		return nil, err
	}
	s.connLock.Lock()
	s.buffering = false
	s.connLock.Unlock()
	return stream, nil
}

// cancelSynDoneFor cancels the SYN watchdog only for a frame of the newest
// stream; a late frame of an older stream says nothing about the newest SYN.
func (s *Session) cancelSynDoneFor(sid uint32) {
	if sid == s.streamID.Load() {
		s.cancelSynDone()
	}
}

func (s *Session) cancelSynDone() {
	s.synDoneLock.Lock()
	if s.synDone != nil {
		s.synDone()
		s.synDone = nil
	}
	s.synDoneLock.Unlock()
}

func (s *Session) recvLoop() error {
	defer s.Close()
	var hdr rawHeader
	var rbuf []byte
	for {
		if s.IsClosed() {
			return io.ErrClosedPipe
		}
		if _, err := io.ReadFull(s.conn, hdr[:]); err != nil {
			return err
		}
		s.lastRecv.Store(time.Now().UnixNano())
		sid := hdr.StreamID()
		switch hdr.Cmd() {
		case cmdPSH:
			// A frame for the newest stream proves the peer accepted its SYN.
			s.cancelSynDoneFor(sid)
			if hdr.Length() > 0 {
				// pipeW.Write returns only after the reader copied the payload,
				// so one buffer, grown to the largest frame, serves every frame.
				if cap(rbuf) < int(hdr.Length()) {
					rbuf = make([]byte, hdr.Length())
				}
				buffer := rbuf[:hdr.Length()]
				if _, err := io.ReadFull(s.conn, buffer); err != nil {
					return err
				}
				s.streamLock.RLock()
				stream, ok := s.streams[sid]
				s.streamLock.RUnlock()
				if ok {
					s.recvBusy.Store(true)
					_, _ = stream.pipeW.Write(buffer)
					s.recvBusy.Store(false)
					s.lastRecv.Store(time.Now().UnixNano())
				}
			}
		case cmdSYNACK:
			s.cancelSynDoneFor(sid)
			if hdr.Length() > 0 {
				buffer := make([]byte, int(hdr.Length()))
				if _, err := io.ReadFull(s.conn, buffer); err != nil {
					return err
				}
				s.streamLock.RLock()
				stream, ok := s.streams[sid]
				s.streamLock.RUnlock()
				if ok {
					stream.closeWithError(fmt.Errorf("remote: %s", string(buffer)))
				}
			}
		case cmdFIN:
			s.cancelSynDoneFor(sid)
			s.streamLock.Lock()
			stream, ok := s.streams[sid]
			delete(s.streams, sid)
			s.streamLock.Unlock()
			if ok {
				stream.closeLocally()
			}
		case cmdWaste, cmdSettings:
			if err := discardFramePayload(s.conn, hdr.Length()); err != nil {
				return err
			}
		case cmdAlert:
			if err := discardFramePayload(s.conn, hdr.Length()); err != nil {
				return err
			}
			return nil
		case cmdUpdatePaddingScheme:
			if hdr.Length() > 0 {
				rawScheme := make([]byte, int(hdr.Length()))
				if _, err := io.ReadFull(s.conn, rawScheme); err != nil {
					return err
				}
				UpdatePaddingScheme(rawScheme, s.padding)
			}
		case cmdHeartRequest:
			if err := discardFramePayload(s.conn, hdr.Length()); err != nil {
				return err
			}
			if _, err := s.writeControlFrame(newFrame(cmdHeartResponse, sid)); err != nil {
				return err
			}
		case cmdHeartResponse:
			if err := discardFramePayload(s.conn, hdr.Length()); err != nil {
				return err
			}
			s.heartMu.Lock()
			s.heartPending = false
			s.heartMisses = 0
			s.heartMu.Unlock()
		case cmdServerSettings:
			if hdr.Length() > 0 {
				buffer := make([]byte, int(hdr.Length()))
				if _, err := io.ReadFull(s.conn, buffer); err != nil {
					return err
				}
				m := StringMapFromBytes(buffer)
				if v, err := strconv.Atoi(m["v"]); err == nil {
					s.peerVersion.Store(uint32(v))
				}
			}
		default:
			if err := discardFramePayload(s.conn, hdr.Length()); err != nil {
				return err
			}
		}
	}
}

func discardFramePayload(r io.Reader, n uint16) error {
	if n == 0 {
		return nil
	}
	_, err := io.CopyN(io.Discard, r, int64(n))
	return err
}

func (s *Session) streamClosed(sid uint32) error {
	if s.IsClosed() {
		return io.ErrClosedPipe
	}
	_, err := s.writeControlFrame(newFrame(cmdFIN, sid))
	s.streamLock.Lock()
	delete(s.streams, sid)
	s.streamLock.Unlock()
	return err
}

const maxFrameDataLen = 0xFFFF

var framePool = sync.Pool{New: func() any {
	b := make([]byte, 0, 2048)
	return &b
}}

func borrowFrame(n int) ([]byte, func()) {
	if n > headerOverHeadSize+maxFrameDataLen {
		return make([]byte, n), func() {}
	}
	bp := framePool.Get().(*[]byte)
	b := *bp
	if cap(b) < n {
		b = make([]byte, n)
	} else {
		b = b[:n]
	}
	*bp = b
	return b, func() {
		*bp = (*bp)[:0]
		framePool.Put(bp)
	}
}

func (s *Session) writeDataFrame(sid uint32, data []byte) (int, error) {
	dataLen := len(data)
	if dataLen == 0 {
		return 0, nil
	}
	if dataLen <= maxFrameDataLen {
		buf, recycle := borrowFrame(headerOverHeadSize + dataLen)
		defer recycle()
		buf[0] = cmdPSH
		binary.BigEndian.PutUint32(buf[1:5], sid)
		binary.BigEndian.PutUint16(buf[5:7], uint16(dataLen))
		copy(buf[7:], data)
		if _, err := s.writeConn(buf); err != nil {
			s.Close()
			return 0, err
		}
		return dataLen, nil
	}
	frameCount := (dataLen + maxFrameDataLen - 1) / maxFrameDataLen
	buf := make([]byte, 0, dataLen+frameCount*headerOverHeadSize)
	for written := 0; written < dataLen; {
		chunk := min(dataLen-written, maxFrameDataLen)
		buf = binary.BigEndian.AppendUint16(binary.BigEndian.AppendUint32(append(buf, cmdPSH), sid), uint16(chunk))
		buf = append(buf, data[written:written+chunk]...)
		written += chunk
	}
	if _, err := s.writeConn(buf); err != nil {
		s.Close()
		return 0, err
	}
	return dataLen, nil
}

func (s *Session) writeControlFrame(frame frame) (int, error) {
	dataLen := len(frame.data)
	buf := make([]byte, headerOverHeadSize+dataLen)
	buf[0] = frame.cmd
	binary.BigEndian.PutUint32(buf[1:5], frame.sid)
	binary.BigEndian.PutUint16(buf[5:7], uint16(dataLen))
	copy(buf[7:], frame.data)
	_, err := s.writeConnDeadline(buf, 5*time.Second)
	if err != nil {
		s.Close()
		return 0, err
	}
	return dataLen, nil
}

// dataWriteTimeout bounds one data-frame write. A failed or timed-out write
// leaves the frame stream out of sync, so the caller closes the whole session
// rather than letting it return to the idle pool.
const dataWriteTimeout = 15 * time.Second

func (s *Session) writeConn(b []byte) (n int, err error) {
	return s.writeConnDeadline(b, dataWriteTimeout)
}

func (s *Session) writeConnDeadline(b []byte, ddl time.Duration) (n int, err error) {
	s.connLock.Lock()
	defer s.connLock.Unlock()
	if ddl > 0 {
		_ = s.conn.SetWriteDeadline(time.Now().Add(ddl))
		defer s.conn.SetWriteDeadline(time.Time{})
	}

	if s.buffering {
		s.buffer = append(s.buffer, b...)
		return len(b), nil
	} else if len(s.buffer) > 0 {
		b = append(s.buffer, b...)
		s.buffer = nil
	}

	if s.sendPadding {
		pkt := s.pktCounter.Add(1)
		paddingF := s.padding.Load()
		if pkt < paddingF.Stop {
			pktSizes := paddingF.GenerateRecordPayloadSizes(pkt)
			for _, l := range pktSizes {
				remainPayloadLen := len(b)
				if l == CheckMark {
					if remainPayloadLen == 0 {
						break
					}
					continue
				}
				if remainPayloadLen > l {
					_, err = s.conn.Write(b[:l])
					if err != nil {
						return 0, err
					}
					n += l
					b = b[l:]
				} else if remainPayloadLen > 0 {
					if paddingLen := l - remainPayloadLen - headerOverHeadSize; paddingLen > 0 {
						b = appendWaste(b, paddingLen)
					}
					_, err = s.conn.Write(b)
					if err != nil {
						return 0, err
					}
					n += remainPayloadLen
					b = nil
				} else {
					_, err = s.conn.Write(appendWaste(nil, l))
					if err != nil {
						return 0, err
					}
					b = nil
				}
			}
			if len(b) == 0 {
				return
			}
			n2, err := s.conn.Write(b)
			return n + n2, err
		}
		s.sendPadding = false
	}
	return s.conn.Write(b)
}

// appendWaste appends a cmdWaste frame (stream 0) carrying n random bytes.
func appendWaste(b []byte, n int) []byte {
	b = binary.BigEndian.AppendUint16(append(b, cmdWaste, 0, 0, 0, 0), uint16(n))
	b = append(b, make([]byte, n)...)
	_, _ = rand.Read(b[len(b)-n:])
	return b
}

const heartbeatInterval = 15 * time.Second

// peerActive reports whether recvLoop is delivering to a stream or has read a
// frame within the last heartbeat period.
func (s *Session) peerActive() bool {
	return s.recvBusy.Load() || time.Since(time.Unix(0, s.lastRecv.Load())) < s.heartEvery
}

func (s *Session) heartbeatLoop() {
	ticker := time.NewTicker(s.heartEvery)
	defer ticker.Stop()
	for {
		select {
		case <-s.die:
			return
		case <-ticker.C:
			s.connLock.Lock()
			buffering := s.buffering
			s.connLock.Unlock()
			if buffering {
				continue
			}
			s.heartMu.Lock()
			if s.heartPending && s.peerActive() {
				s.heartMisses = 0
			} else if s.heartPending {
				s.heartMisses++
				if s.heartMisses >= 2 {
					s.heartMu.Unlock()
					_ = s.Close()
					return
				}
			} else {
				s.heartPending = true
			}
			s.heartMu.Unlock()
			if _, err := s.writeControlFrame(newFrame(cmdHeartRequest, 0)); err != nil {
				return
			}
		}
	}
}
