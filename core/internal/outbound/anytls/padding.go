package anytls

import (
	"crypto/md5"
	"crypto/rand"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"sync/atomic"
)

const CheckMark = -1

var DefaultPaddingScheme = []byte(`stop=8
0=30-30
1=100-400
2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000
3=9-9,500-1000
4=500-1000
5=500-1000
6=500-1000
7=500-1000`)

type PaddingFactory struct {
	scheme    StringMap
	RawScheme []byte
	Stop      uint32
	Md5       string
}

func UpdatePaddingScheme(rawScheme []byte, to *atomic.Pointer[PaddingFactory]) bool {
	if p := NewPaddingFactory(rawScheme); p != nil {
		to.Store(p)
		return true
	}
	return false
}

func NewPaddingFactory(rawScheme []byte) *PaddingFactory {
	p := &PaddingFactory{
		RawScheme: rawScheme,
		Md5:       fmt.Sprintf("%x", md5.Sum(rawScheme)),
	}
	scheme := StringMapFromBytes(rawScheme)
	if len(scheme) == 0 {
		return nil
	}
	stop, err := strconv.Atoi(scheme["stop"])
	if err != nil {
		return nil
	}
	p.Stop = uint32(stop)
	p.scheme = scheme
	return p
}

func (p *PaddingFactory) GenerateRecordPayloadSizes(pkt uint32) (pktSizes []int) {
	s, ok := p.scheme[strconv.Itoa(int(pkt))]
	if !ok {
		return
	}
	for _, sRange := range strings.Split(s, ",") {
		sRangeMinMax := strings.Split(sRange, "-")
		if len(sRangeMinMax) == 2 {
			_min, err1 := strconv.ParseInt(sRangeMinMax[0], 10, 64)
			_max, err2 := strconv.ParseInt(sRangeMinMax[1], 10, 64)
			if err1 != nil || err2 != nil {
				continue
			}
			_min, _max = min(_min, _max), max(_min, _max)
			if _min <= 0 || _max <= 0 {
				continue
			}
			if _min == _max {
				pktSizes = append(pktSizes, int(_min))
			} else {
				i, _ := rand.Int(rand.Reader, big.NewInt(_max-_min))
				pktSizes = append(pktSizes, int(i.Int64()+_min))
			}
		} else if sRange == "c" {
			pktSizes = append(pktSizes, CheckMark)
		}
	}
	return
}
