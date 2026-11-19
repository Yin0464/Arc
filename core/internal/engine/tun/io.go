package tun

import (
	"errors"
	"io"
	"os"
	"sync"
	"syscall"
)

const (
	Batch       = 64
	WQueue      = 2048
	tunPktBufSz = 2048
)

// Packet is one outbound TUN frame; Pooled, when set, returns to BufPool.
type Packet struct {
	Pkt    []byte
	Pooled *[]byte
}

func (p Packet) Release() {
	if p.Pooled != nil {
		BufPool.Put(p.Pooled)
	}
}

// Writer batches frames onto one TUN fd from a single goroutine. Each batch
// runs under mu and out writes one frame (out may drop and retake mu).
type Writer struct {
	mu   *sync.Mutex
	out  func(pkt []byte)
	tun  *os.File
	q    chan Packet
	stop chan struct{}
	done chan struct{}
}

func NewWriter(tun *os.File, qcap int, mu *sync.Mutex, out func(pkt []byte)) *Writer {
	w := &Writer{
		mu:   mu,
		out:  out,
		tun:  tun,
		q:    make(chan Packet, qcap),
		stop: make(chan struct{}),
		done: make(chan struct{}),
	}
	go w.run()
	return w
}

func (w *Writer) Shutdown() {
	select {
	case <-w.stop:
	default:
		close(w.stop)
	}
}

func (w *Writer) Enqueue(p Packet) bool {
	select {
	case <-w.stop:
		p.Release()
		return false
	default:
	}
	select {
	case w.q <- p:
		return true
	default:
	}
	select {
	case w.q <- p:
		return true
	case <-w.stop:
		p.Release()
		return false
	}
}

func (w *Writer) run() {
	defer close(w.done)
	batch := make([]Packet, 0, Batch)
	for {
		select {
		case <-w.stop:
			w.discard()
			return
		case p := <-w.q:
			batch = append(batch[:0], p)
		fill:
			for len(batch) < Batch {
				select {
				case p := <-w.q:
					batch = append(batch, p)
				default:
					break fill
				}
			}
			stopped := false
			w.mu.Lock()
			for i := range batch {
				if !stopped {
					select {
					case <-w.stop:
						stopped = true
					default:
						w.out(batch[i].Pkt)
					}
				}
				batch[i].Release()
				batch[i] = Packet{}
			}
			w.mu.Unlock()
		}
	}
}

// File is the TUN fd this writer drains into.
func (w *Writer) File() *os.File { return w.tun }

func (w *Writer) discard() {
	for {
		select {
		case p := <-w.q:
			p.Release()
		default:
			return
		}
	}
}

type Reader struct {
	f     *os.File
	bufs  [][]byte
	lens  []int
	batch bool
}

func NewReader(f *os.File, batch int) *Reader {
	r := &Reader{f: f, bufs: make([][]byte, batch), lens: make([]int, batch)}
	for i := range r.bufs {
		r.bufs[i] = make([]byte, tunPktBufSz)
	}
	r.batch = batch > 1 && fdNonblocking(f)
	return r
}

func fdNonblocking(f *os.File) bool {
	rc, err := f.SyscallConn()
	if err != nil {
		return false
	}
	nb := false
	_ = rc.Control(func(fd uintptr) {
		fl, err := fcntlGetFl(int(fd))
		nb = err == nil && fl&syscall.O_NONBLOCK != 0
	})
	return nb
}

func fcntlGetFl(fd int) (int, error) {
	r, _, e := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), uintptr(syscall.F_GETFL), 0)
	if e != 0 {
		return 0, e
	}
	return int(r), nil
}

func (r *Reader) Pkt(i int) []byte { return r.bufs[i][:r.lens[i]] }

func (r *Reader) Read() (int, error) {
	if !r.batch {
		n, err := r.f.Read(r.bufs[0])
		if err != nil {
			return 0, err
		}
		r.lens[0] = n
		return 1, nil
	}
	rc, err := r.f.SyscallConn()
	if err != nil {
		return 0, err
	}
	cnt := 0
	var rerr error
	err = rc.Read(func(fd uintptr) bool {
		for cnt < len(r.bufs) {
			n, e := syscall.Read(int(fd), r.bufs[cnt])
			if e == syscall.EINTR {
				continue
			}
			if e == syscall.EAGAIN {
				return cnt > 0
			}
			if e != nil {
				rerr = e
				return true
			}
			if n == 0 {
				rerr = io.EOF
				return true
			}
			r.lens[cnt] = n
			cnt++
		}
		return true
	})
	if rerr == nil && err != nil {
		rerr = err
	}
	if cnt == 0 && rerr == nil {
		rerr = errors.New("tun: empty read")
	}
	return cnt, rerr
}
