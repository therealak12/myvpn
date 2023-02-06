package packet

import (
	"encoding/binary"
	"fmt"
	"github.com/therealak12/myvpn/internal/consts"
	"log"
	"net"
	"sync"
	"sync/atomic"
)

type IPPacket struct {
	Pkt    *IPv4
	MTUBuf []byte
	Wire   []byte
}

type IPProtocol uint8

type IPv4Option struct {
	OptionType   uint8
	OptionLength uint8
	OptionData   []byte
}

type IPv4 struct {
	Version    uint8
	IHL        uint8
	TOS        uint8
	Length     uint16
	Id         uint16
	Flags      uint8
	FragOffset uint16
	TTL        uint8
	Protocol   IPProtocol
	Checksum   uint16
	SrcIP      net.IP
	DstIP      net.IP
	Options    []IPv4Option
	Padding    []byte
	Payload    []byte

	headerLength int
}

const (
	IPProtocolICMPv4 IPProtocol = 1
	IPProtocolTCP    IPProtocol = 6
	IPProtocolUDP    IPProtocol = 17
)

var (
	currentFrags = make(map[uint16]*IPPacket)
	ipv4Pool     = &sync.Pool{New: func() interface{} {
		return &IPv4{}
	}}
	globalIPID uint32
)

// NewIPv4 returns an empty IPv4 struct
func NewIPv4() *IPv4 {
	var empty IPv4
	pkt := ipv4Pool.Get().(*IPv4)
	*pkt = empty
	return pkt
}

// ParseIPv4 deserializes a byte array into an IPv4 struct
// TODO: use gopacket.NewPacket
// https://github.com/google/gopacket/blob/3aa782ce48d4a525acaebab344cedabfb561f870/layers/ip4.go#L188
func ParseIPv4(data []byte, ipv4 *IPv4) error {
	if len(data) < 20 {
		return fmt.Errorf("ipv4 header length %d is less than 20", len(data))
	}

	ipv4.Version = data[0] >> 4
	ipv4.IHL = uint8(data[0]) & 0x0F
	ipv4.TOS = data[1]
	ipv4.Length = binary.BigEndian.Uint16(data[2:4])
	ipv4.Id = binary.BigEndian.Uint16(data[4:6])

	flagsFragment := binary.BigEndian.Uint16(data[6:8])

	// omit 13 bits to obtain 3 bit flags
	ipv4.Flags = uint8(flagsFragment >> 13)
	ipv4.FragOffset = flagsFragment & 0x1FFF

	ipv4.TTL = data[8]
	ipv4.Protocol = IPProtocol(data[9])
	ipv4.Checksum = binary.BigEndian.Uint16(data[10:12])
	ipv4.SrcIP = data[12:16]
	ipv4.DstIP = data[16:20]

	if ipv4.Length < 20 {
		return fmt.Errorf("too small IP length (%d < 20)", ipv4.Length)
	}
	if ipv4.IHL < 5 {
		return fmt.Errorf("too small IP header length (%d < 5)", ipv4.IHL)
	}
	if int(4*ipv4.IHL) > int(ipv4.Length) {
		return fmt.Errorf("4 * ip header length > ip length (%d > %d)", 4*ipv4.IHL, ipv4.Length)
	}

	ipv4.Payload = data[4*ipv4.IHL:]
	restOfData := data[20 : 4*ipv4.IHL]
	// extract options
	for len(restOfData) > 0 {
		if ipv4.Options == nil {
			ipv4.Options = make([]IPv4Option, 0, 4)
		}
		opt := IPv4Option{OptionType: restOfData[0]}
		switch opt.OptionType {
		case 0:
			opt.OptionLength = 1
			ipv4.Options = append(ipv4.Options, opt)
			ipv4.Padding = restOfData[1:]
			return nil
		case 1:
			opt.OptionLength = 1
			restOfData = restOfData[1:]
			ipv4.Options = append(ipv4.Options, opt)
		default:
			if len(restOfData) < 2 {
				return fmt.Errorf("option length %d less than 2", len(restOfData))
			}
			opt.OptionLength = restOfData[1]
			if len(restOfData) < int(opt.OptionLength) {
				return fmt.Errorf("option length exceeds remaining IP header size, option type %v length %v", opt.OptionType, opt.OptionLength)
			}
			if opt.OptionLength <= 2 {
				return fmt.Errorf("option type %v length %d must be greater than 2", opt.OptionType, opt.OptionLength)
			}
			opt.OptionData = restOfData[2:opt.OptionLength]
			restOfData = restOfData[opt.OptionLength:]
			ipv4.Options = append(ipv4.Options, opt)
		}
	}

	return nil
}

func ProcessFragment(currentPacket *IPv4, currentData []byte) (bool, *IPv4, []byte) {
	existingPacket, ok := currentFrags[currentPacket.Id]
	if ok {
		// this is the first fragment
		if currentPacket.Flags&0x1 == 0 {
			// this is also the last fragment
			return false, nil, nil
		}
		// slices are passed by reference, so we duplicate currentData to
		// ensure external modifications do not affect ours
		currentDataDup := make([]byte, len(currentData))
		copy(currentDataDup, currentData)
		cloneIPv4 := &IPv4{}
		if err := ParseIPv4(currentDataDup, cloneIPv4); err != nil {
			log.Printf("failed to current fragment, err: %v\n", err)
			return false, nil, nil
		}
		currentFrags[cloneIPv4.Id] = &IPPacket{
			Pkt: cloneIPv4,
			Wire:   currentDataDup,
		}
		return false, cloneIPv4, currentDataDup
	} else {
		// not the first fragment
		existingPacket.Wire = append(existingPacket.Wire, currentPacket.Payload...)
		if err := ParseIPv4(existingPacket.Wire, existingPacket.Pkt); err != nil {
			log.Printf("failed to received data, err: %v\n", err)
			return false, nil, nil
		}

		return currentPacket.Flags&0x1 == 0, existingPacket.Pkt, existingPacket.Wire
	}
}

func (ip *IPv4) PseudoHeader(buf []byte, proto IPProtocol, dataLen int) error {
	if len(buf) != consts.Ipv4PseudoLength {
		return fmt.Errorf("incorrect buffer size: %d buffer given, %d needed", len(buf), consts.Ipv4PseudoLength)
	}
	copy(buf[0:4], ip.SrcIP)
	copy(buf[4:8], ip.DstIP)
	buf[8] = 0
	buf[9] = byte(proto)
	binary.BigEndian.PutUint16(buf[10:], uint16(dataLen))
	return nil
}

func (ip *IPv4) HeaderLength() int {
	if ip.headerLength == 0 {
		optionLength := uint8(0)
		for _, opt := range ip.Options {
			switch opt.OptionType {
			case 0:
				// this is the end of option lists
				optionLength++
			case 1:
				// this is the padding
				optionLength++
			default:
				optionLength += opt.OptionLength

			}
		}
		// make sure the options are aligned to 32 bit boundary
		if (optionLength % 4) != 0 {
			optionLength += 4 - (optionLength % 4)
		}
		ip.IHL = 5 + (optionLength / 4)
		ip.headerLength = int(optionLength) + 20
	}
	return ip.headerLength
}

func (ip *IPv4) flagsFrags() (ff uint16) {
	ff |= uint16(ip.Flags) << 13
	ff |= ip.FragOffset
	return
}

func (ip *IPv4) Serialize(hdr []byte, dataLen int) error {
	if len(hdr) != ip.HeaderLength() {
		return fmt.Errorf("incorrect buffer size: %d buffer given, %d needed", len(hdr), ip.HeaderLength())
	}
	hdr[0] = (ip.Version << 4) | ip.IHL
	hdr[1] = ip.TOS
	ip.Length = uint16(ip.headerLength + dataLen)
	binary.BigEndian.PutUint16(hdr[2:], ip.Length)
	binary.BigEndian.PutUint16(hdr[4:], ip.Id)
	binary.BigEndian.PutUint16(hdr[6:], ip.flagsFrags())
	hdr[8] = ip.TTL
	hdr[9] = byte(ip.Protocol)
	copy(hdr[12:16], ip.SrcIP)
	copy(hdr[16:20], ip.DstIP)

	curLocation := 20
	// Now, we will encode the options
	for _, opt := range ip.Options {
		switch opt.OptionType {
		case 0:
			// this is the end of option lists
			hdr[curLocation] = 0
			curLocation++
		case 1:
			// this is the padding
			hdr[curLocation] = 1
			curLocation++
		default:
			hdr[curLocation] = opt.OptionType
			hdr[curLocation+1] = opt.OptionLength

			// sanity checking to protect us from buffer overrun
			if len(opt.OptionData) > int(opt.OptionLength-2) {
				return fmt.Errorf("option length is smaller than length of option data")
			}
			copy(hdr[curLocation+2:curLocation+int(opt.OptionLength)], opt.OptionData)
			curLocation += int(opt.OptionLength)
		}
	}
	hdr[10] = 0
	hdr[11] = 0
	ip.Checksum = Checksum(hdr)
	binary.BigEndian.PutUint16(hdr[10:], ip.Checksum)
	return nil
}

func IPID() uint16 {
	return uint16(atomic.AddUint32(&globalIPID, 1) & 0x0000ffff)
}

func ReleaseIPv4(pkt *IPv4) {
	// clear internal slice references
	pkt.SrcIP = nil
	pkt.DstIP = nil
	pkt.Options = nil
	pkt.Padding = nil
	pkt.Payload = nil

	ipv4Pool.Put(pkt)
}
