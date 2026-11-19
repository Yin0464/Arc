package sniff

import (
	"bytes"
	"encoding/binary"
	"net"
	"strings"
)

func TLSRecordReady(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	if b[0] != 0x16 || len(b) < 5 {
		return b[0] != 0x16
	}
	return len(b) >= 5+int(binary.BigEndian.Uint16(b[3:5]))
}

func TLSSNI(b []byte) string {
	if len(b) < 43 || b[0] != 0x16 || b[5] != 0x01 {
		return ""
	}
	off := 43
	if len(b) <= off {
		return ""
	}
	off += 1 + int(b[off])
	if len(b) < off+2 {
		return ""
	}
	off += 2 + int(binary.BigEndian.Uint16(b[off:off+2]))
	if len(b) < off+1 {
		return ""
	}
	off += 1 + int(b[off])
	if len(b) < off+2 {
		return ""
	}
	extEnd := min(len(b), off+2+int(binary.BigEndian.Uint16(b[off:off+2])))
	off += 2

	for off+4 <= extEnd {
		extType := binary.BigEndian.Uint16(b[off : off+2])
		extLen := int(binary.BigEndian.Uint16(b[off+2 : off+4]))
		off += 4
		if off+extLen > extEnd {
			break
		}
		if extType == 0x0000 && extLen >= 5 && b[off+2] == 0x00 {
			nameLen := int(binary.BigEndian.Uint16(b[off+3 : off+5]))
			if off+5+nameLen <= extEnd {
				return string(b[off+5 : off+5+nameLen])
			}
		}
		off += extLen
	}
	return ""
}

func HTTPHost(b []byte) string {
	for _, line := range bytes.Split(b, []byte("\r\n")) {
		if len(line) > 5 && bytes.EqualFold(line[:5], []byte("Host:")) {
			h := strings.TrimSpace(string(line[5:]))
			if host, _, err := net.SplitHostPort(h); err == nil {
				return host
			}
			return h
		}
	}
	return ""
}
