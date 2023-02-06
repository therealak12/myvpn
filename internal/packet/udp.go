package packet

import (
	"encoding/binary"
	"fmt"
	"sync"
)

type UDP struct {
	SrcPort  uint16
	DstPort  uint16
	Length   uint16
	Checksum uint16
	Payload  []byte
}

var (
	udpPool = &sync.Pool{New: func() interface{} {
		return &UDP{}
	}}
)

func NewUDP() *UDP {
	var empty UDP
	pkt := udpPool.Get().(*UDP)
	*pkt = empty
	return pkt
}

func ParseUdp(data []byte, udp *UDP) error {
	udp.SrcPort = binary.BigEndian.Uint16(data[0:2])
	udp.DstPort = binary.BigEndian.Uint16(data[2:4])
	udp.Length = binary.BigEndian.Uint16(data[4:6])
	udp.Checksum = binary.BigEndian.Uint16(data[6:8])
	switch {
	case udp.Length >= 8:
		hlen := int(udp.Length)
		if hlen > len(data) {
			hlen = len(data)
		}
		udp.Payload = data[8:hlen]
	case udp.Length == 0:
		// jumbogram
		udp.Payload = data[8:]
	default:
		return fmt.Errorf("udp packet %d bytes is too small", udp.Length)
	}
	return nil
}

func ReleaseUDP(pkt *UDP) {
	// clear internal slice references
	pkt.Payload = nil
	udpPool.Put(pkt)
}

func (u *UDP) Serialize(hdr []byte, csumFields ...[]byte) error {
	if len(hdr) != 8 {
		return fmt.Errorf("incorrect header size: %d != 8", len(hdr))
	}

	binary.BigEndian.PutUint16(hdr, u.SrcPort)
	binary.BigEndian.PutUint16(hdr[2:], u.DstPort)
	u.Length = uint16(len(u.Payload)) + 8
	binary.BigEndian.PutUint16(hdr[4:], u.Length)
	hdr[6] = 0
	hdr[7] = 0
	u.Checksum = Checksum(csumFields...)
	binary.BigEndian.PutUint16(hdr[6:], u.Checksum)
	return nil
}
