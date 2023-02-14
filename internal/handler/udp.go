package handler

import (
	"fmt"
	"github.com/therealak12/myvpn/internal/consts"
	"github.com/therealak12/myvpn/internal/packet"
	"github.com/yinghuocho/gosocks"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

type UDPPacket struct {
	ip     *packet.IPv4
	udp    *packet.UDP
	mtuBuf []byte
	Wire   []byte
}

var (
	udpPacketPool = &sync.Pool{
		New: func() interface{} {
			return &UDPPacket{}
		}}
)

func newUDPPacket() *UDPPacket {
	return udpPacketPool.Get().(*UDPPacket)
}

func udpConnID(ip *packet.IPv4, udp *packet.UDP) string {
	return strings.Join([]string{
		ip.SrcIP.String(),
		fmt.Sprintf("%d", udp.SrcPort),
		ip.DstIP.String(),
		fmt.Sprintf("%d", udp.DstPort),
	}, "|")
}

// copyUDPPacket create a UDPPacket and fills it with the given
//
//	Pkt, udp and raw data
func copyUDPPacket(raw []byte, ip *packet.IPv4, udp *packet.UDP) *UDPPacket {
	ipHdr := packet.NewIPv4()
	udpHdr := packet.NewUDP()
	pkt := newUDPPacket()

	var buf []byte
	if len(raw) <= consts.MTU {
		buf = newBuffer()
		pkt.mtuBuf = buf
	} else {
		buf = make([]byte, len(raw))
	}
	n := copy(buf, raw)
	pkt.Wire = buf[:n]
	if err := packet.ParseIPv4(pkt.Wire, ipHdr); err != nil {
		log.Printf("failed to parse Pkt packet, err: %v\n", err)
	}
	if err := packet.ParseUdp(ipHdr.Payload, udpHdr); err != nil {
		log.Printf("failed to parse udp packet, err: %v\n", err)
	}

	pkt.ip = ipHdr
	pkt.udp = udpHdr
	return pkt
}

// responsePacket wraps payload in a udp packet and returns first and
//
//	other Pkt fragments (if required)
func responsePacket(localIP, remoteIP net.IP, localPort, remotePort uint16, payload []byte) (*UDPPacket, []*packet.IPPacket) {
	ipID := packet.IPID()

	ip := packet.NewIPv4()
	udp := packet.NewUDP()

	ip.Version = 4
	ip.Id = ipID
	ip.SrcIP = make(net.IP, len(remoteIP))
	copy(ip.SrcIP, remoteIP)
	ip.DstIP = make(net.IP, len(localIP))
	copy(ip.DstIP, localIP)
	ip.TTL = 64
	ip.Protocol = packet.IPProtocolUDP

	udp.SrcPort = remotePort
	udp.DstPort = localPort
	udp.Payload = payload

	pkt := newUDPPacket()
	pkt.ip = ip
	pkt.udp = udp

	pkt.mtuBuf = newBuffer()
	payloadLen := len(udp.Payload)
	payloadStart := consts.MTU - payloadLen
	// payload needs fragmentation if it's too long
	if payloadLen > consts.MTU-28 {
		ip.Flags = 1
		// 20 bytes IP header + 8 bytes UDP header
		payloadStart = 28
	}
	udpHL := 8
	udpStart := payloadStart - udpHL
	pseudoStart := udpStart - consts.Ipv4PseudoLength
	if err := ip.PseudoHeader(pkt.mtuBuf[pseudoStart:udpStart], packet.IPProtocolUDP, udpHL+payloadLen); err != nil {
		log.Printf("failed to create IP PseudoHeader, err: %v\n", err)
		return nil, nil
	}
	if err := udp.Serialize(pkt.mtuBuf[udpStart:payloadStart], pkt.mtuBuf[pseudoStart:payloadStart], udp.Payload); err != nil {
		log.Printf("failed to serialize udp packet, err: %v\n", err)
		return nil, nil
	}
	if payloadLen != 0 {
		copy(pkt.mtuBuf[payloadStart:], payload)
	}
	ipHL := ip.HeaderLength()
	ipStart := udpStart - ipHL
	// (consts.MTU-payloadStart) should be equal to payloadLen :-?
	if err := ip.Serialize(pkt.mtuBuf[ipStart:udpStart], udpHL+(consts.MTU-payloadStart)); err != nil {
		log.Printf("failed to serialize Pkt packet, err: %v\n", err)
		return nil, nil
	}
	pkt.Wire = pkt.mtuBuf[ipStart:]

	if ip.Flags == 0 {
		return pkt, nil
	}
	frags := genFragments(ip, (consts.MTU-20)/8, payload[consts.MTU-28:])
	return pkt, frags
}

type UDPConnTrack struct {
	handler *Handler
	connId  string

	toTunCh     chan<- interface{}
	quitBySelf  chan bool
	QuitByOther chan bool

	fromTunCh   chan *UDPPacket
	socksClosed chan bool

	localSocksAddr string
	socksConn      *gosocks.SocksConn

	localIP    net.IP
	remoteIP   net.IP
	localPort  uint16
	remotePort uint16
}

func (ut *UDPConnTrack) send(data []byte) {
	pkt, fragments := responsePacket(ut.localIP, ut.remoteIP, ut.localPort, ut.remotePort, data)
	ut.toTunCh <- pkt
	if fragments != nil {
		for _, fragment := range fragments {
			ut.toTunCh <- fragment
		}
	}
}

func (ut *UDPConnTrack) run() {
	// connect to socks
	var err error
	for i := 0; i < 2; i += 1 {
		ut.socksConn, err = dialLocalSocks(ut.localSocksAddr)
		if err != nil {
			log.Printf("failed to connect socks5 proxy, err: %v\n", err)
		} else {
			if err := ut.socksConn.SetDeadline(time.Now().Add(time.Minute)); err != nil {
				log.Printf("failed to set socks5 connection deadline, err: %v\n", err)
			}
			break
		}
	}
	if ut.socksConn == nil {
		close(ut.socksClosed)
		close(ut.quitBySelf)
		ut.handler.clearUDPConnTrack(ut.connId)
		return
	}

	socksAddr := ut.socksConn.LocalAddr().(*net.TCPAddr)
	// udpBind is a utility connection.
	// We write packets to it and the gosocks lib reads packets from it.
	// The read packets are then sent to the relayAddr received from the SOCKS server.
	udpBind, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   socksAddr.IP,
		Port: 0,
		Zone: socksAddr.Zone,
	})
	if err != nil {
		log.Printf("failed to listen udp, err: %v\n", err)
		ut.socksConn.Close()
		close(ut.socksClosed)
		close(ut.quitBySelf)
		ut.handler.clearTCPConnTrack(ut.connId)
		return
	}

	// socks request/reply
	_, err = gosocks.WriteSocksRequest(ut.socksConn, &gosocks.SocksRequest{
		Cmd:      gosocks.SocksCmdUDPAssociate,
		HostType: gosocks.SocksIPv4Host,
		DstHost:  "0.0.0.0",
		DstPort:  0,
	})
	if err != nil {
		log.Printf("failed to send udp associate request, err: %v\n", err)
		ut.socksConn.Close()
		close(ut.socksClosed)
		close(ut.quitBySelf)
		ut.handler.clearTCPConnTrack(ut.connId)
		return
	}

	reply, err := gosocks.ReadSocksReply(ut.socksConn)
	if err != nil {
		log.Printf("failed to read socks reply, err: %v\n", err)
		ut.socksConn.Close()
		close(ut.socksClosed)
		close(ut.quitBySelf)
		ut.handler.clearTCPConnTrack(ut.connId)
		return
	}
	if reply.Rep != gosocks.SocksSucceeded {
		log.Printf("socks connect request failed, retcode: %v\n", reply.Rep)
		ut.socksConn.Close()
		close(ut.socksClosed)
		close(ut.quitBySelf)
		ut.handler.clearTCPConnTrack(ut.connId)
		return
	}
	relayAddr := gosocks.SocksAddrToNetAddr("udp", reply.BndHost, reply.BndPort).(*net.UDPAddr)

	if err := ut.socksConn.SetDeadline(time.Time{}); err != nil {
		log.Printf("failed to set socksConn deadline, err: %v\n", err)
	}
	// monitor TCP connection to socks server
	go gosocks.ConnMonitor(ut.socksConn, ut.socksClosed)

	quitUDP := make(chan bool)
	relayUDPCh := make(chan *gosocks.UDPPacket)
	go gosocks.UDPReader(udpBind, relayUDPCh, quitUDP)

	start := time.Now()
	for {
		var t *time.Timer
		if ut.handler.isDNS(ut.remoteIP.String(), ut.remotePort) {
			t = time.NewTimer(10 * time.Second)
		} else {
			t = time.NewTimer(2 * time.Minute)
		}
		select {
		case pkt, ok := <-relayUDPCh:
			if !ok {
				ut.socksConn.Close()
				udpBind.Close()
				close(ut.quitBySelf)
				ut.handler.clearUDPConnTrack(ut.connId)
				close(quitUDP)
				return
			}
			if pkt.Addr.String() != relayAddr.String() {
				log.Printf("response relayed from %s, expected %s", pkt.Addr.String(), relayAddr.String())
				continue
			}
			udpReq, err := gosocks.ParseUDPRequest(pkt.Data)
			if err != nil {
				log.Printf("failed to parse udp request from relay, err: %v\n", err)
				continue
			}
			if udpReq.Frag != gosocks.SocksNoFragment {
				continue
			}
			ut.send(udpReq.Data)
			if ut.handler.isDNS(ut.remoteIP.String(), ut.remotePort) {
				// DNS-without-fragment only has one request-response
				end := time.Now()
				ms := end.Sub(start).Nanoseconds() / 1000_000
				log.Printf("DNS session response received: %d ms", ms)
				if ut.handler.Cache != nil {
					ut.handler.Cache.store(udpReq.Data)
				}
				ut.socksConn.Close()
				udpBind.Close()
				close(ut.quitBySelf)
				ut.handler.clearUDPConnTrack(ut.connId)
				close(quitUDP)
				return
			}
		// pkt from tun
		case pkt := <-ut.fromTunCh:
			req := &gosocks.UDPRequest{
				Frag:     0,
				HostType: gosocks.SocksIPv4Host,
				DstHost:  pkt.ip.DstIP.String(),
				DstPort:  pkt.udp.DstPort,
				Data:     pkt.udp.Payload,
			}
			datagram := gosocks.PackUDPRequest(req)
			_, err := udpBind.WriteToUDP(datagram, relayAddr)
			ReleaseUDPPacket(pkt)
			if err != nil {
				log.Printf("error to send UDP packet to relay: %s", err)
				ut.socksConn.Close()
				udpBind.Close()
				close(ut.quitBySelf)
				ut.handler.clearUDPConnTrack(ut.connId)
				close(quitUDP)
				return
			}

		case <-ut.socksClosed:
			ut.socksConn.Close()
			udpBind.Close()
			close(ut.quitBySelf)
			ut.handler.clearUDPConnTrack(ut.connId)
			close(quitUDP)
			return

		case <-t.C:
			ut.socksConn.Close()
			udpBind.Close()
			close(ut.quitBySelf)
			ut.handler.clearUDPConnTrack(ut.connId)
			close(quitUDP)
			return

		case <-ut.QuitByOther:
			log.Printf("UDPConnTrack quitByOther")
			ut.socksConn.Close()
			udpBind.Close()
			close(quitUDP)
			return
		}
		t.Stop()
	}
}

func (ut *UDPConnTrack) newPacket(pkt *UDPPacket) {
	select {
	case <-ut.QuitByOther:
	case <-ut.quitBySelf:
	case ut.fromTunCh <- pkt:
	}
}

func ReleaseUDPPacket(pkt *UDPPacket) {
	packet.ReleaseIPv4(pkt.ip)
	packet.ReleaseUDP(pkt.udp)
	if pkt.mtuBuf != nil {
		releaseBuffer(pkt.mtuBuf)
	}
	pkt.mtuBuf = nil
	pkt.Wire = nil
	udpPacketPool.Put(pkt)
}

func (h *Handler) clearUDPConnTrack(connId string) {
	h.UDPConnTracksMu.Lock()
	defer h.UDPConnTracksMu.Unlock()

	delete(h.UDPConnTracks, connId)
	log.Printf("tracking %d UDP connections", len(h.UDPConnTracks))
}

func (h *Handler) getUDPConnTrack(connId string, ip *packet.IPv4, udp *packet.UDP) *UDPConnTrack {
	h.UDPConnTracksMu.Lock()
	defer h.UDPConnTracksMu.Unlock()

	track := h.UDPConnTracks[connId]
	if track != nil {
		return track
	} else {
		track = &UDPConnTrack{
			handler:     h,
			connId:      connId,
			toTunCh:     h.WriteCh,
			fromTunCh:   make(chan *UDPPacket, 100),
			socksClosed: make(chan bool),
			quitBySelf:  make(chan bool),
			QuitByOther: make(chan bool),

			localPort:  udp.SrcPort,
			remotePort: udp.DstPort,

			localSocksAddr: h.LocalSocksAddr,
		}
		track.localIP = make(net.IP, len(ip.SrcIP))
		copy(track.localIP, ip.SrcIP)
		track.remoteIP = make(net.IP, len(ip.DstIP))
		copy(track.remoteIP, ip.DstIP)

		h.UDPConnTracks[connId] = track
		go track.run()
		return track
	}
}

func (h *Handler) HandleUDP(data []byte, ip *packet.IPv4, udp *packet.UDP) {
	var buf [1024]byte
	var done bool

	// fist look at dns cache
	if h.Cache != nil && h.isDNS(ip.DstIP.String(), udp.DstPort) {
		answer := h.Cache.query(udp.Payload)
		if answer != nil {
			data, err := answer.PackBuffer(buf[:])
			if err == nil {
				resp, fragments := responsePacket(ip.SrcIP, ip.DstIP, udp.SrcPort, udp.DstPort, data)
				go func(first *UDPPacket, frags []*packet.IPPacket) {
					h.WriteCh <- first
					if frags != nil {
						for _, frag := range frags {
							h.WriteCh <- frag
						}
					}
				}(resp, fragments)
				done = true
			}
		}
	}

	// then create a UDPConnTrack entry to forward
	if !done {
		connID := udpConnID(ip, udp)
		pkt := copyUDPPacket(data, ip, udp)
		track := h.getUDPConnTrack(connID, ip, udp)
		track.newPacket(pkt)
	}
}
