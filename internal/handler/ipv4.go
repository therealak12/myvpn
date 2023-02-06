package handler

import (
	"github.com/therealak12/myvpn/internal/consts"
	"github.com/therealak12/myvpn/internal/packet"
	"log"
	"net"
)

func genFragments(first *packet.IPv4, offset uint16, data []byte) []*packet.IPPacket {
	var ret []*packet.IPPacket
	for {
		frag := packet.NewIPv4()

		frag.Version = 4
		frag.Id = first.Id
		frag.SrcIP = make(net.IP, len(first.SrcIP))
		copy(frag.SrcIP, first.SrcIP)
		frag.DstIP = make(net.IP, len(first.DstIP))
		copy(frag.DstIP, first.DstIP)
		frag.TTL = first.TTL
		frag.Protocol = first.Protocol
		frag.FragOffset = offset
		if len(data) <= consts.MTU-20 {
			frag.Payload = data
		} else {
			frag.Flags = 1
			offset += (consts.MTU - 20) / 8
			frag.Payload = data[:consts.MTU-20]
			data = data[consts.MTU-20:]
		}

		pkt := &packet.IPPacket{Pkt: frag}
		pkt.MTUBuf = newBuffer()

		payloadLen := len(frag.Payload)
		payloadStart := consts.MTU - payloadLen
		if payloadLen != 0 {
			copy(pkt.MTUBuf[payloadStart:], frag.Payload)
		}
		ipHL := frag.HeaderLength()
		ipStart := payloadStart - ipHL
		if err := frag.Serialize(pkt.MTUBuf[ipStart:payloadStart], payloadLen); err != nil {
			log.Printf("failed to serialize fragment, err: %v\n", err)
			return nil
		}
		pkt.Wire = pkt.MTUBuf[ipStart:]
		ret = append(ret, pkt)

		if frag.Flags == 0 {
			return ret
		}
	}
}

func ReleaseIPPacket(pkt *packet.IPPacket) {
	packet.ReleaseIPv4(pkt.Pkt)
	if pkt.MTUBuf != nil {
		releaseBuffer(pkt.MTUBuf)
	}
	pkt.MTUBuf = nil
	pkt.Wire = nil
}
