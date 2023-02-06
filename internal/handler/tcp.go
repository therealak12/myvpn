package handler

import (
	"fmt"
	"github.com/therealak12/myvpn/internal/consts"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/yinghuocho/gosocks"

	"github.com/therealak12/myvpn/internal/packet"
)

type TCPPacket struct {
	ipv4   *packet.IPv4
	tcp    *packet.TCP
	mtuBuf []byte
	Wire   []byte
}

var (
	tcpPacketPool = &sync.Pool{New: func() interface{} {
		return &TCPPacket{}
	}}
)

func newTCPPacket() *TCPPacket {
	return tcpPacketPool.Get().(*TCPPacket)
}

func ReleaseTCPPacket(pkt *TCPPacket) {
	packet.ReleaseIPv4(pkt.ipv4)
	packet.ReleaseTCP(pkt.tcp)
	if pkt.mtuBuf != nil {
		releaseBuffer(pkt.mtuBuf)
	}
	pkt.mtuBuf = nil
	pkt.mtuBuf = nil
	tcpPacketPool.Put(pkt)
}

func createTCPPacket(data []byte) (*TCPPacket, error) {
	ipHdr := packet.NewIPv4()
	tcpHdr := packet.NewTCP()
	tcpPkt := newTCPPacket()

	var buf []byte
	if len(data) <= consts.MTU {
		buf = newBuffer()
		tcpPkt.mtuBuf = buf
	} else {
		buf = make([]byte, len(data))
	}

	n := copy(buf, data)
	tcpPkt.Wire = buf[:n]
	if err := packet.ParseIPv4(tcpPkt.Wire, ipHdr); err != nil {
		return nil, err
	}
	if err := packet.ParseTCP(ipHdr.Payload, tcpHdr); err != nil {
		return nil, err
	}
	tcpPkt.ipv4 = ipHdr
	tcpPkt.tcp = tcpHdr

	return tcpPkt, nil
}

// tcpConnId returns a string created by concatenating
// src and dst ipv4 and ports
func tcpConnId(ip *packet.IPv4, tcp *packet.TCP) string {
	return strings.Join([]string{
		ip.SrcIP.String(),
		fmt.Sprintf("%d", tcp.SrcPort),
		ip.DstIP.String(),
		fmt.Sprintf("%d", tcp.DstPort),
	}, "|")
}

// packTCP receives an IPV4 and a TCP packet and wraps them in
// a TCPPacket
func packTCP(ipv4 *packet.IPv4, tcp *packet.TCP) *TCPPacket {
	pkt := newTCPPacket()
	pkt.ipv4 = ipv4
	pkt.tcp = tcp

	buf := newBuffer()
	pkt.mtuBuf = buf

	tcpPayloadLen := len(tcp.Payload)
	tcpPayloadStart := consts.MTU - tcpPayloadLen
	if tcpPayloadLen != 0 {
		copy(pkt.mtuBuf[tcpPayloadStart:], tcp.Payload)
	}
	tcpHL := tcp.HeaderLength()
	tcpStart := tcpPayloadStart - tcpHL
	pseudoIPHeaderStart := tcpStart - consts.Ipv4PseudoLength
	if err := ipv4.PseudoHeader(pkt.mtuBuf[pseudoIPHeaderStart:tcpStart], packet.IPProtocolTCP, tcpHL+tcpPayloadLen); err != nil {
		log.Printf("failed to create pseudo Pkt header, err: %v\n", err)
		return nil
	}
	if err := tcp.Serialize(pkt.mtuBuf[tcpStart:tcpPayloadStart], pkt.mtuBuf[pseudoIPHeaderStart:]); err != nil {
		log.Printf("failed to create serialize tcp packet, err: %v\n", err)
		return nil
	}
	ipHL := ipv4.HeaderLength()
	ipStart := tcpStart - ipHL
	if err := ipv4.Serialize(pkt.mtuBuf[ipStart:tcpStart], tcpHL+tcpPayloadLen); err != nil {
		log.Printf("failed to create serialize Pkt packet, err: %v\n", err)
		return nil
	}
	pkt.Wire = pkt.mtuBuf[ipStart:]
	return pkt
}

// rst creates a tcp packet with RST flag set
func rst(srcIP, dstIP net.IP, srcPort, dstPort uint16, seq, ack, payloadLen uint32) *TCPPacket {
	ipHdr := packet.NewIPv4()
	tcpHdr := packet.NewTCP()

	ipHdr.Version = 4
	ipHdr.Id = packet.IPID()
	ipHdr.DstIP = srcIP
	ipHdr.SrcIP = dstIP
	ipHdr.TTL = 64
	ipHdr.Protocol = packet.IPProtocolTCP

	tcpHdr.DstPort = srcPort
	tcpHdr.SrcPort = dstPort
	tcpHdr.Window = uint16(MaxRecvWindow)
	tcpHdr.RST = true
	tcpHdr.ACK = true
	tcpHdr.SeqNum = 0

	// RFC 793
	// If the incoming segment has an ACK field, the reset takes its
	// sequence number from the ACK field of the segment, otherwise the
	// reset has sequence number zero and the ACK field is set to the sum
	// of the sequence number and segment length of the incoming segment.
	// The connection remains in the CLOSED state.
	tcpHdr.AckNum = seq + payloadLen
	if tcpHdr.AckNum == seq {
		tcpHdr.AckNum += 1
	}
	if ack != 0 {
		tcpHdr.SeqNum = ack
	}
	return packTCP(ipHdr, tcpHdr)
}

func rstByPacket(pkt *TCPPacket) *TCPPacket {
	return rst(pkt.ipv4.SrcIP, pkt.ipv4.DstIP, pkt.tcp.SrcPort, pkt.tcp.DstPort, pkt.tcp.SeqNum, pkt.tcp.AckNum, uint32(len(pkt.tcp.Payload)))
}

func (tt *TCPConnTrack) changeState(next tcpState) {
	tt.state = next
}

func (tt *TCPConnTrack) validAck(pkt *TCPPacket) bool {
	return pkt.tcp.AckNum == tt.nextSeq
}

func (tt *TCPConnTrack) validSeq(pkt *TCPPacket) bool {
	return pkt.tcp.SeqNum == tt.recvNextSeq
}

func (tt *TCPConnTrack) relayPayload(pkt *TCPPacket) bool {
	payloadLen := uint32(len(pkt.tcp.Payload))
	select {
	case tt.toSocksCh <- pkt:
		tt.recvNextSeq += payloadLen

		// reduce window when received
		wnd := atomic.LoadInt32(&tt.recvWindow)
		wnd -= int32(payloadLen)
		if wnd < 0 {
			wnd = 0
		}
		atomic.StoreInt32(&tt.recvWindow, wnd)

		return true
	case <-tt.socksCloseCh:
		return false
	}
}

func (tt *TCPConnTrack) send(pkt *TCPPacket) {
	if pkt.tcp.ACK {
		tt.lastAck = pkt.tcp.AckNum
	}

	tt.toTunCh <- pkt
}

func (tt *TCPConnTrack) synAck() {
	ipHdr := packet.NewIPv4()
	tcpHdr := packet.NewTCP()

	ipHdr.Version = 4
	ipHdr.Id = packet.IPID()
	ipHdr.SrcIP = tt.remoteIP
	ipHdr.DstIP = tt.localIP
	ipHdr.TTL = 64
	ipHdr.Protocol = packet.IPProtocolTCP

	tcpHdr.SrcPort = tt.remotePort
	tcpHdr.DstPort = tt.localPort
	tcpHdr.Window = uint16(atomic.LoadInt32(&tt.recvWindow))
	tcpHdr.SYN = true
	tcpHdr.ACK = true
	tcpHdr.SeqNum = tt.nextSeq
	tcpHdr.AckNum = tt.recvNextSeq

	tcpHdr.Options = []packet.TCPOption{{
		layers.TCPOptionKindMSS,
		4,
		[]byte{0x5, 0xb4}, // 1460 mss for 1500 mtu
	}}

	synAck := packTCP(ipHdr, tcpHdr)
	tt.send(synAck)
	tt.nextSeq += 1
}

// finAck creates a tcp packet with FIN & ACK flag set
func (tt *TCPConnTrack) finAck() {
	ipHdr := packet.NewIPv4()
	tcpHdr := packet.NewTCP()

	ipHdr.Version = 4
	ipHdr.Id = packet.IPID()
	ipHdr.SrcIP = tt.remoteIP
	ipHdr.DstIP = tt.localIP
	ipHdr.TTL = 64
	ipHdr.Protocol = packet.IPProtocolTCP

	tcpHdr.SrcPort = tt.remotePort
	tcpHdr.DstPort = tt.localPort
	tcpHdr.Window = uint16(atomic.LoadInt32(&tt.recvWindow))
	tcpHdr.FIN = true
	tcpHdr.ACK = true
	tcpHdr.SeqNum = tt.nextSeq
	tcpHdr.AckNum = tt.recvNextSeq

	ack := packTCP(ipHdr, tcpHdr)
	tt.send(ack)

	// FIN counts 1 seq
	tt.nextSeq += 1
}

// ack creates a tcp packet with ACK flag set
func (tt *TCPConnTrack) ack() {
	ipHdr := packet.NewIPv4()
	tcpHdr := packet.NewTCP()

	ipHdr.Version = 4
	ipHdr.Id = packet.IPID()
	ipHdr.SrcIP = tt.remoteIP
	ipHdr.DstIP = tt.localIP
	ipHdr.TTL = 64
	ipHdr.Protocol = packet.IPProtocolTCP

	tcpHdr.SrcPort = tt.remotePort
	tcpHdr.DstPort = tt.localPort
	tcpHdr.Window = uint16(atomic.LoadInt32(&tt.recvWindow))
	tcpHdr.ACK = true
	tcpHdr.SeqNum = tt.nextSeq
	tcpHdr.AckNum = tt.recvNextSeq

	ack := packTCP(ipHdr, tcpHdr)
	tt.send(ack)
}

// payload wraps data in a TCP packet ands sends it
func (tt *TCPConnTrack) payload(data []byte) {
	iphdr := packet.NewIPv4()
	tcphdr := packet.NewTCP()

	iphdr.Version = 4
	iphdr.Id = packet.IPID()
	iphdr.SrcIP = tt.remoteIP
	iphdr.DstIP = tt.localIP
	iphdr.TTL = 64
	iphdr.Protocol = packet.IPProtocolTCP

	tcphdr.SrcPort = tt.remotePort
	tcphdr.DstPort = tt.localPort
	tcphdr.Window = uint16(atomic.LoadInt32(&tt.recvWindow))
	tcphdr.ACK = true
	tcphdr.PSH = true
	tcphdr.SeqNum = tt.nextSeq
	tcphdr.AckNum = tt.recvNextSeq
	tcphdr.Payload = data

	pkt := packTCP(iphdr, tcphdr)
	tt.send(pkt)
	// adjust seq
	tt.nextSeq = tt.nextSeq + uint32(len(data))
}

type tcpState byte

const (
	TCPStateClosed      tcpState = 0x0
	TCPStateSynRcvd     tcpState = 0x1
	TCPStateEstablished tcpState = 0x2
	TCPStateFinWait1    tcpState = 0x3
	TCPStateFinWait2    tcpState = 0x4
	TCPStateClosing     tcpState = 0x5
	TCPStateLastAck     tcpState = 0x6
	TCPStateTimeWait    tcpState = 0x7

	MaxSendWindow int = 65535
	MaxRecvWindow int = 65535
)

type TCPConnTrack struct {
	handler *Handler
	connId  string

	input        chan *TCPPacket
	toTunCh      chan<- interface{}
	fromSocksCh  chan []byte
	toSocksCh    chan *TCPPacket
	socksCloseCh chan bool
	QuitByOther  chan bool
	quitBySelf   chan bool

	localSocksAddr string
	socksConn      *gosocks.SocksConn

	// tcp context
	state tcpState
	// sequence I should use to send next segment
	// also as ACK I expect in next received segment
	nextSeq uint32
	// expected sequence in next received segment
	recvNextSeq uint32
	lastAck     uint32

	// flow control
	recvWindow  int32
	sendWindow  int32
	sendWndCond *sync.Cond

	localIP    net.IP
	remoteIP   net.IP
	localPort  uint16
	remotePort uint16
}

// stateClosed receives a SYN packet and tries to connect to socks proxy.
// Sends SYN/ACK on success and RST otherwise.
func (tt *TCPConnTrack) stateClosed(synPacket *TCPPacket) (continueTrack, release bool) {
	var err error
	for i := 0; i < 2; i += 1 {
		tt.socksConn, err = dialLocalSocks(tt.localSocksAddr)
		if err != nil {
			log.Printf("failed to connect socks5 proxy, err:%v\n", err)
		} else {
			if err = tt.socksConn.SetDeadline(time.Time{}); err != nil {
				log.Printf("failed to set deadline for socks conn, err: %v\n", err)
			}
			break
		}
	}
	if tt.socksConn == nil {
		resp := rstByPacket(synPacket)
		tt.toTunCh <- resp.Wire
		return false, true
	}

	tt.recvNextSeq = synPacket.tcp.SeqNum + 1
	tt.nextSeq = 1

	tt.synAck()
	tt.changeState(TCPStateSynRcvd)
	return true, true
}

func (tt *TCPConnTrack) tcpSocks2Tun(dstIP net.IP, dstPort uint16, conn net.Conn,
	readCh chan<- []byte, writeCh <-chan *TCPPacket, closeCh chan bool) {
	_, err := gosocks.WriteSocksRequest(conn, &gosocks.SocksRequest{
		Cmd:      gosocks.SocksCmdConnect,
		HostType: gosocks.SocksIPv4Host,
		DstHost:  dstIP.String(),
		DstPort:  dstPort,
	})
	if err != nil {
		log.Printf("failed to sends socks request, err: %v\n", err)
		if err2 := conn.Close(); err2 != nil {
			log.Printf("failed to close conn, err: %v\n", err2)
		}
		close(closeCh)
		return
	}
	reply, err := gosocks.ReadSocksReply(conn)
	if err != nil {
		log.Printf("failed to read socks reply, err: %v\n", err)
		if err2 := conn.Close(); err2 != nil {
			log.Printf("failed to close conn, err: %v\n", err2)
		}
		close(closeCh)
		return
	}
	if reply.Rep != gosocks.SocksSucceeded {
		log.Printf("socks connect request failed, retcode: %d\n", reply.Rep)
		if err2 := conn.Close(); err2 != nil {
			log.Printf("failed to close conn, err: %v\n", err2)
		}
		close(closeCh)
		return
	}

	// writer loop (inside goroutine)
	go func() {
	loop:
		for {
			select {
			case <-closeCh:
				break loop
			case pkt := <-writeCh:
				_, err := conn.Write(pkt.tcp.Payload)
				if err != nil {
					log.Printf("failed to write payload to conn, err: %v\n", err)
				}
				wnd := atomic.LoadInt32(&tt.recvWindow)
				wnd += int32(len(pkt.tcp.Payload))
				if wnd > int32(MaxRecvWindow) {
					wnd = int32(MaxRecvWindow)
				}
				atomic.StoreInt32(&tt.recvWindow, wnd)

				ReleaseTCPPacket(pkt)
			}
		}
	}()

	// reader loop
	for {
		var buf [consts.MTU - 40]byte

		var wnd, cur int32
		wnd = atomic.LoadInt32(&tt.sendWindow)
		if wnd <= 0 {
			for wnd <= 0 {
				tt.sendWndCond.L.Lock()
				tt.sendWndCond.Wait()
				wnd = atomic.LoadInt32(&tt.sendWindow)
			}
			tt.sendWndCond.L.Unlock()
		}

		cur = wnd
		if cur > consts.MTU-40 {
			cur = consts.MTU - 40
		}

		n, err := conn.Read(buf[:cur])
		if err != nil {
			log.Printf("failed to read from conn, err: %f\n", err)
			if err := conn.Close(); err != nil {
				log.Printf("failed to close conn, err: %f\n", err)
			}
			break
		} else {
			b := make([]byte, n)
			copy(b, buf[:n])
			readCh <- b

			next := wnd - int32(n)
			if next < 0 {
				next = 0
			}
			// if sendWindow is not equal to wnd, it's already updated by
			// a received packet from TUN
			atomic.CompareAndSwapInt32(&tt.sendWindow, wnd, next)
		}
	}

	close(closeCh)
}

// stateSynRcvd expects an ACK with matching ACK number
func (tt *TCPConnTrack) stateSynRcvd(pkt *TCPPacket) (continueTrack, release bool) {
	if !(tt.validSeq(pkt) && tt.validAck(pkt)) {
		if !pkt.tcp.RST {
			resp := rstByPacket(pkt)
			tt.toTunCh <- resp
		}
		return true, true
	}
	if pkt.tcp.RST {
		return false, true
	}
	if !pkt.tcp.ACK {
		return true, true
	}

	continueTrack = true
	release = true
	tt.changeState(TCPStateEstablished)
	go tt.tcpSocks2Tun(tt.remoteIP, tt.remotePort, tt.socksConn,
		tt.fromSocksCh, tt.toSocksCh, tt.socksCloseCh)
	if len(pkt.tcp.Payload) != 0 {
		if tt.relayPayload(pkt) {
			release = false
		}
	}
	return
}

// stateEstablished calls relayPayload for a valid packet with ACK set.
// Also changes state if FIN is set.
func (tt *TCPConnTrack) stateEstablished(pkt *TCPPacket) (continueTrack, release bool) {
	// ack if seq not expected
	if !tt.validSeq(pkt) {
		tt.ack()
		return true, true
	}

	// connection ends with a valid RST
	if pkt.tcp.RST {
		return false, true
	}

	// ignore non-ACK packets
	if !pkt.tcp.ACK {
		return true, true
	}

	continueTrack = true
	release = true

	if len(pkt.tcp.Payload) != 0 {
		if tt.relayPayload(pkt) {
			release = false
		}
	}

	if pkt.tcp.FIN {
		tt.recvNextSeq += 1
		tt.finAck()
		tt.changeState(TCPStateLastAck)
		if err := tt.socksConn.Close(); err != nil {
			log.Printf("failed to close socksConn, err: %v\n", err)
		}
	}
	return
}

func (tt *TCPConnTrack) stateFinWait1(pkt *TCPPacket) (continueTrack, release bool) {
	// ignore invalid seq
	if !tt.validSeq(pkt) {
		return true, true
	}
	// connection ends by valid RST
	if pkt.tcp.RST {
		return false, true
	}
	// ignore non-ACK response
	if !pkt.tcp.ACK {
		return true, true
	}

	if pkt.tcp.FIN {
		tt.recvNextSeq += 1
		tt.ack()
		if pkt.tcp.ACK && tt.validAck(pkt) {
			tt.changeState(TCPStateTimeWait)
			return false, true
		} else {
			tt.changeState(TCPStateClosing)
			return true, true
		}
	} else {
		tt.changeState(TCPStateFinWait2)
		return true, true
	}
}

func (tt *TCPConnTrack) stateFinWait2(pkt *TCPPacket) (continueTrack, release bool) {
	// ignore packet with invalid seq/ack
	if !(tt.validSeq(pkt) && tt.validAck(pkt)) {
		return true, true
	}
	// connection ends by valid RST
	if pkt.tcp.RST {
		return false, true
	}
	// ignore non-FIN non-ACK packets
	if !(pkt.tcp.FIN && pkt.tcp.ACK) {
		return true, true
	}

	tt.recvNextSeq += 1
	tt.ack()
	tt.changeState(TCPStateTimeWait)
	return false, true
}

func (tt *TCPConnTrack) stateClosing(pkt *TCPPacket) (continueTrack, release bool) {
	// ignore packet with invalid seq/ack
	if !(tt.validSeq(pkt) && tt.validAck(pkt)) {
		return true, true
	}
	// connection ends by valid RST
	if pkt.tcp.RST {
		return false, true
	}
	// ignore non-ACK packets
	if !pkt.tcp.ACK {
		return true, true
	}
	tt.changeState(TCPStateTimeWait)
	return false, true
}

func (tt *TCPConnTrack) stateLastAck(pkt *TCPPacket) (continueTrack, release bool) {
	// ignore packet with invalid sequence/ack, state unchanged
	if !(tt.validSeq(pkt) && tt.validAck(pkt)) {
		return true, true
	}
	// ignore non-ACK packets
	if !pkt.tcp.ACK {
		return true, true
	}
	// connection ends
	tt.changeState(TCPStateClosed)
	return false, true
}

// newPacket puts the pkt in the input channel or does nothing if
// some quit signal is available
func (tt *TCPConnTrack) newPacket(pkt *TCPPacket) {
	select {
	case <-tt.quitBySelf:
	case <-tt.QuitByOther:
	case tt.input <- pkt:
	}
}

func (tt *TCPConnTrack) updateSendWindow(pkt *TCPPacket) {
	atomic.StoreInt32(&tt.sendWindow, int32(pkt.tcp.Window))
	tt.sendWndCond.Signal()
}

func (tt *TCPConnTrack) run() {
	for {
		var ackTimer *time.Timer
		timeout := time.NewTimer(5 * time.Minute)
		var ackTimeout <-chan time.Time
		var socksCloseCh chan bool
		var fromSocksCh chan []byte

		// we should wait for more data or close signal if
		// the connection is in established state
		if tt.state == TCPStateEstablished {
			socksCloseCh = tt.socksCloseCh
			fromSocksCh = tt.fromSocksCh
			ackTimer = time.NewTimer(10 * time.Millisecond)
			ackTimeout = ackTimer.C
		}

		select {
		case pkt := <-tt.input:
			var continueTrack, release bool
			tt.updateSendWindow(pkt)

			switch tt.state {
			case TCPStateClosed:
				continueTrack, release = tt.stateClosed(pkt)
			case TCPStateSynRcvd:
				continueTrack, release = tt.stateSynRcvd(pkt)
			case TCPStateEstablished:
				continueTrack, release = tt.stateEstablished(pkt)
			case TCPStateFinWait1:
				continueTrack, release = tt.stateFinWait1(pkt)
			case TCPStateFinWait2:
				continueTrack, release = tt.stateFinWait2(pkt)
			case TCPStateClosing:
				continueTrack, release = tt.stateClosing(pkt)
			case TCPStateLastAck:
				continueTrack, release = tt.stateLastAck(pkt)
			}

			if release {
				ReleaseTCPPacket(pkt)
			}

			if !continueTrack {
				if tt.socksConn != nil {
					tt.socksConn.Close()
				}
				close(tt.quitBySelf)
				tt.handler.clearTCPConnTrack(tt.connId)
				return
			}
		case <-ackTimeout:
			if tt.lastAck < tt.recvNextSeq {
				// have something to ack
				tt.ack()
			}
		case data := <-fromSocksCh:
			tt.payload(data)
		case <-socksCloseCh:
			tt.finAck()
			tt.changeState(TCPStateFinWait1)
		case <-timeout.C:
			if tt.socksConn != nil {
				if err := tt.socksConn.Close(); err != nil {
					log.Printf("failed to close socskConn, err: %v\n", err)
				}
			}
			close(tt.quitBySelf)
			tt.handler.clearTCPConnTrack(tt.connId)
			return
		case <-tt.QuitByOther:
			log.Printf("received quitByOther\n")
			if tt.socksConn != nil {
				if err := tt.socksConn.Close(); err != nil {
					log.Printf("failed to close socskConn, err: %v\n", err)
				}
			}
			return
		}
		timeout.Stop()
		if ackTimer != nil {
			ackTimer.Stop()
		}
	}
}

func (h *Handler) createTCPConnTrack(connId string, ipv4 *packet.IPv4, tcp *packet.TCP) *TCPConnTrack {
	h.TCPConnTracksMu.Lock()
	defer h.TCPConnTracksMu.Unlock()

	track := &TCPConnTrack{
		handler:      h,
		connId:       connId,
		toTunCh:      h.WriteCh,
		input:        make(chan *TCPPacket, 10000),
		fromSocksCh:  make(chan []byte, 100),
		toSocksCh:    make(chan *TCPPacket, 100),
		socksCloseCh: make(chan bool),
		QuitByOther:  make(chan bool),
		quitBySelf:   make(chan bool),

		recvWindow:  int32(MaxSendWindow),
		sendWindow:  int32(MaxRecvWindow),
		sendWndCond: &sync.Cond{L: &sync.Mutex{}},

		localPort:      tcp.SrcPort,
		remotePort:     tcp.DstPort,
		localSocksAddr: h.LocalSocksAddr,
		state:          TCPStateClosed,
	}

	track.localIP = make(net.IP, len(ipv4.SrcIP))
	copy(track.localIP, ipv4.SrcIP)
	track.remoteIP = make(net.IP, len(ipv4.DstIP))
	copy(track.remoteIP, ipv4.DstIP)

	h.TCPConnTracks[connId] = track

	go track.run()

	return track
}

func (h *Handler) getTCPConnTrack(connId string) *TCPConnTrack {
	h.TCPConnTracksMu.Lock()
	defer h.TCPConnTracksMu.Unlock()

	return h.TCPConnTracks[connId]
}

func (h *Handler) HandleTCP(data []byte, ip *packet.IPv4, tcp *packet.TCP) {
	connId := tcpConnId(ip, tcp)
	track := h.getTCPConnTrack(connId)
	if track != nil {
		tcpPkt, err := createTCPPacket(data)
		if err != nil {
			log.Printf("failed to createTCPPacket, err: %v\n", err)
			return
		}
		track.newPacket(tcpPkt)
	} else {
		if tcp.RST {
			return
		}
		// return an RST to non-SYN packet
		if !tcp.SYN {
			resp := rst(ip.SrcIP, ip.DstIP, tcp.DstPort, tcp.SrcPort, tcp.SeqNum, tcp.AckNum, uint32(len(tcp.Payload)))
			h.WriteCh <- resp
			return
		}

		tcpPkt, err := createTCPPacket(data)
		if err != nil {
			log.Printf("failed to createTCPPacket, err: %v\n", err)
			return
		}
		track = h.createTCPConnTrack(connId, ip, tcp)
		track.newPacket(tcpPkt)
	}
}
