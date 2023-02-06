package packet

import (
	"encoding/binary"
	"fmt"
	"sync"
)

type TCPOption struct {
	OptionType   uint8
	OptionLength uint8
	OptionData   []byte
}

type TCP struct {
	SrcPort                                    uint16
	DstPort                                    uint16
	SeqNum                                     uint32
	AckNum                                     uint32
	DataOffset                                 uint8
	FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS bool
	Window                                     uint16
	Checksum                                   uint16
	Urgent                                     uint16
	Options                                    []TCPOption
	Padding                                    []byte
	Payload                                    []byte

	opts         [4]TCPOption
	headerLength int
}

var (
	tcpPool = &sync.Pool{New: func() interface{} {
		return &TCP{}
	}}
)

func NewTCP() *TCP {
	var empty TCP
	pkt := tcpPool.Get().(*TCP)
	*pkt = empty
	return pkt
}

func ParseTCP(data []byte, tcp *TCP) error {
	tcp.SrcPort = binary.BigEndian.Uint16(data[0:2])
	tcp.DstPort = binary.BigEndian.Uint16(data[2:4])
	tcp.SeqNum = binary.BigEndian.Uint32(data[4:8])
	tcp.AckNum = binary.BigEndian.Uint32(data[8:12])
	tcp.DataOffset = data[12] >> 4
	tcp.FIN = data[13]&0x01 != 0
	tcp.SYN = data[13]&0x02 != 0
	tcp.RST = data[13]&0x04 != 0
	tcp.PSH = data[13]&0x08 != 0
	tcp.ACK = data[13]&0x10 != 0
	tcp.URG = data[13]&0x20 != 0
	tcp.ECE = data[13]&0x40 != 0
	tcp.CWR = data[13]&0x80 != 0
	tcp.NS = data[12]&0x01 != 0
	tcp.Window = binary.BigEndian.Uint16(data[14:16])
	tcp.Checksum = binary.BigEndian.Uint16(data[16:18])
	tcp.Urgent = binary.BigEndian.Uint16(data[18:20])
	if tcp.Options == nil {
		tcp.Options = tcp.opts[:0]
	} else {
		tcp.Options = tcp.Options[:0]
	}
	if tcp.DataOffset < 5 {
		return fmt.Errorf("invalid tcp data offset %d < 5", tcp.DataOffset)
	}
	dataStart := int(tcp.DataOffset) * 4
	if dataStart > len(data) {
		return fmt.Errorf("data offset greater than packet length")
	}
	tcp.Payload = data[dataStart:]
	restOfData := data[20:dataStart]
OPTIONS:
	for len(restOfData) > 0 {
		tcp.Options = append(tcp.Options, TCPOption{OptionType: restOfData[0]})
		opt := &tcp.Options[len(tcp.Options)-1]
		switch opt.OptionType {
		case 0: // end of options
			opt.OptionLength = 1
			tcp.Padding = restOfData[1:]
			break OPTIONS
		case 1:
			opt.OptionLength = 1
		default:
			opt.OptionLength = restOfData[1]
			if opt.OptionLength < 2 {
				return fmt.Errorf("invalid tcp option length %d < 2", opt.OptionLength)
			}
			if int(opt.OptionLength) > len(restOfData) {
				return fmt.Errorf("invalid tcp option length %d exceeds remaining bytes %d", opt.OptionLength, len(restOfData))
			}
			opt.OptionData = data[2:opt.OptionLength]
		}
		restOfData = restOfData[opt.OptionLength:]
	}

	tcp.headerLength = int(tcp.DataOffset) * 4
	return nil
}

func (t *TCP) HeaderLength() int {
	// if headerLength is zero we'll calculate it manually
	// headerLength = 20 bytes + options length + padding length
	if t.headerLength == 0 {
		optionLength := 0
		for _, o := range t.Options {
			switch o.OptionType {
			case 0, 1:
				optionLength += 1
			default:
				optionLength += 2 + len(o.OptionData)
			}
		}
		t.Padding = lotsOfZeros[:optionLength%4]
		t.headerLength = len(t.Padding) + optionLength + 20
		t.DataOffset = uint8(t.headerLength / 4)
	}

	return t.headerLength
}

func (t *TCP) flagsAndOffset() uint16 {
	f := uint16(t.DataOffset) << 12
	if t.FIN {
		f |= 0x0001
	}
	if t.SYN {
		f |= 0x0002
	}
	if t.RST {
		f |= 0x0004
	}
	if t.PSH {
		f |= 0x0008
	}
	if t.ACK {
		f |= 0x0010
	}
	if t.URG {
		f |= 0x0020
	}
	if t.ECE {
		f |= 0x0040
	}
	if t.CWR {
		f |= 0x0080
	}
	if t.NS {
		f |= 0x0100
	}
	return f
}

func (t *TCP) Serialize(hdr []byte, csumFields ...[]byte) error {
	if t.HeaderLength() != len(hdr) {
		return fmt.Errorf("incorrect buffer size: %d buffer given, %d needed", len(hdr), t.HeaderLength())
	}
	binary.BigEndian.PutUint16(hdr, t.SrcPort)
	binary.BigEndian.PutUint16(hdr[2:], t.DstPort)
	binary.BigEndian.PutUint32(hdr[4:], t.SeqNum)
	binary.BigEndian.PutUint32(hdr[8:], t.AckNum)
	binary.BigEndian.PutUint16(hdr[12:], t.flagsAndOffset())
	binary.BigEndian.PutUint16(hdr[14:], t.Window)
	binary.BigEndian.PutUint16(hdr[18:], t.Urgent)
	start := 20
	for _, o := range t.Options {
		hdr[start] = o.OptionType
		switch o.OptionType {
		case 0, 1:
			start++
		default:
			o.OptionLength = uint8(len(o.OptionData) + 2)
			hdr[start+1] = o.OptionLength
			copy(hdr[start+2:start+len(o.OptionData)+2], o.OptionData)
			start += int(o.OptionLength)
		}
	}
	copy(hdr[start:], t.Padding)
	hdr[16] = 0
	hdr[17] = 0
	t.Checksum = Checksum(csumFields...)
	binary.BigEndian.PutUint16(hdr[16:], t.Checksum)
	return nil
}

func ReleaseTCP(pkt *TCP) {
	// clear internal slice references
	for _, opt := range pkt.Options {
		opt.OptionData = nil
	}
	pkt.Options = nil
	pkt.Padding = nil
	pkt.Payload = nil

	tcpPool.Put(pkt)
}
