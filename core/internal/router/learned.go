package router

import (
	"bufio"
	"bytes"
	"hash/crc32"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

const (
	maxLearned = 8192
	LearnTTL   = 7 * 24 * time.Hour
	saveDelay  = 20 * time.Second
)

type learnedEntry struct {
	domain  string
	expires uint32
	act     Action
	ref     atomic.Bool
}

var (
	domainMu  sync.RWMutex
	learned   = map[string]int32{}
	slots     []learnedEntry
	hand      int
	learnPath string
	saveMu    sync.Mutex
	saveTimer *time.Timer
	loadDone  = make(chan struct{})
	loadOnce  sync.Once
)

const learnedFormat = 6

var learnedStamp = sync.OnceValue(func() string {
	h := crc32.NewIEEE()
	h.Write([]byte(domTab))
	h.Write([]byte(ip4Tab))
	h.Write([]byte(ip6Tab))
	return "#v" + strconv.Itoa(learnedFormat) + "-" + strconv.FormatUint(uint64(h.Sum32()), 16)
})

func lookupLearned(domain string) (Action, bool) {
	domainMu.RLock()
	i, ok := learned[domain]
	var act Action
	if ok {
		if e := &slots[i]; int64(e.expires) > nowUnix() {
			if !e.ref.Load() {
				e.ref.Store(true)
			}
			act = e.act
		} else {
			ok = false
		}
	}
	domainMu.RUnlock()
	return act, ok
}

func LearnDomain(domain string, act Action) { LearnDomainFor(domain, act, LearnTTL) }

func LearnDomainFor(domain string, act Action, ttl time.Duration) {
	domain = CleanLowerDomain(domain)
	if domain == "" {
		return
	}
	domainMu.Lock()
	putLocked(domain, act, nowUnix()+int64(ttl/time.Second), true)
	domainMu.Unlock()
	scheduleSave()
}

func putLocked(domain string, act Action, expires int64, overwrite bool) {
	if i, ok := learned[domain]; ok {
		if overwrite {
			e := &slots[i]
			e.act, e.expires = act, uint32(expires)
			e.ref.Store(true)
		}
		return
	}
	var i int
	if len(slots) < maxLearned {
		i = len(slots)
		slots = append(slots, learnedEntry{})
	} else {
		now := nowUnix()
		for {
			v := &slots[hand]
			if int64(v.expires) <= now || !v.ref.Swap(false) {
				break
			}
			hand = (hand + 1) % maxLearned
		}
		delete(learned, slots[hand].domain)
		i = hand
		hand = (hand + 1) % maxLearned
	}
	e := &slots[i]
	e.domain, e.act, e.expires = domain, act, uint32(expires)
	e.ref.Store(false)
	learned[domain] = int32(i)
}

func ClearLearned() {
	domainMu.Lock()
	learned = map[string]int32{}
	slots = nil
	hand = 0
	domainMu.Unlock()
}

func SetDataDir(dir string) {
	loadOnce.Do(func() {
		learnPath = filepath.Join(dir, "learned.txt")
		go func() {
			defer close(loadDone)
			if b, err := os.ReadFile(learnPath); err == nil {
				if hdr, rest, _ := bytes.Cut(b, []byte{'\n'}); string(hdr) == learnedStamp() {
					LoadLearned(rest)
				} else {
					_ = os.Remove(learnPath)
				}
			}
		}()
	})
}

func LoadLearned(b []byte) int {
	now, n := nowUnix(), 0
	domainMu.Lock()
	defer domainMu.Unlock()
	if len(slots) == 0 {
		n := min(bytes.Count(b, []byte{'\n'})+1, maxLearned)
		learned = make(map[string]int32, n)
		slots = make([]learnedEntry, 0, n)
	}
	for len(b) > 0 {
		line := b
		if i := bytes.IndexByte(b, '\n'); i >= 0 {
			line, b = b[:i], b[i+1:]
		} else {
			b = nil
		}
		sp1 := bytes.IndexByte(line, ' ')
		if sp1 < 0 || sp1+3 > len(line) || line[sp1+2] != ' ' {
			continue
		}
		exp, okNum := int64(0), sp1 > 0 && sp1 <= 10
		for _, c := range line[:sp1] {
			if c < '0' || c > '9' {
				okNum = false
				break
			}
			exp = exp*10 + int64(c-'0')
		}
		act := Action(line[sp1+1] - '0')
		if !okNum || exp <= now || (act != ActionProxy && act != ActionDirect) {
			continue
		}
		putLocked(CleanLowerDomain(string(line[sp1+3:])), act, exp, false)
		n++
	}
	return n
}

func DumpLearned() []byte {
	now := nowUnix()
	var buf bytes.Buffer
	domainMu.RLock()
	buf.Grow(len(slots) * 36)
	for i := range slots {
		e := &slots[i]
		if d := e.domain; int64(e.expires) > now && (e.act == ActionProxy || e.act == ActionDirect) {
			buf.WriteString(strconv.FormatInt(int64(e.expires), 10))
			buf.WriteByte(' ')
			buf.WriteByte(byte('0' + e.act))
			buf.WriteByte(' ')
			buf.WriteString(d)
			buf.WriteByte('\n')
		}
	}
	domainMu.RUnlock()
	return buf.Bytes()
}

func scheduleSave() {
	if learnPath == "" {
		return
	}
	saveMu.Lock()
	if saveTimer == nil {
		saveTimer = time.AfterFunc(saveDelay, func() { _ = FlushLearned() })
	}
	saveMu.Unlock()
}

func FlushLearned() error {
	saveMu.Lock()
	if saveTimer != nil {
		saveTimer.Stop()
		saveTimer = nil
	}
	saveMu.Unlock()
	if learnPath == "" {
		return nil
	}
	<-loadDone
	tmp := learnPath + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(f)
	_, err = w.WriteString(learnedStamp() + "\n")
	if err == nil {
		_, err = w.Write(DumpLearned())
	}
	if err == nil {
		err = w.Flush()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, learnPath)
}
