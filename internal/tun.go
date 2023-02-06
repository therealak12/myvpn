package myvpn

import (
	"github.com/therealak12/myvpn/internal/consts"
	"github.com/therealak12/myvpn/internal/handler"
	"github.com/therealak12/myvpn/internal/packet"
	"io"
	"log"
	"strings"
	"sync"
)

type Tun struct {
	*handler.Handler
	dev io.ReadWriteCloser
	mtu int
	wg  sync.WaitGroup
}

func NewTun(dev io.ReadWriteCloser) *Tun {
	return &Tun{
		dev: dev,
		mtu: consts.MTU,
	}
}

func (t *Tun) RunReader() {
	t.wg.Add(1)
	defer t.wg.Done()

	var buffer [consts.MTU]byte
	var ipv4 packet.IPv4
	var tcp packet.TCP
	var udp packet.UDP
	for {
		n, err := t.Dev.Read(buffer[:])
		if err != nil {
			// TODO: stop at critical error
			log.Printf("failed to read packet, err: %v\n", err)
			return
		}
		data := buffer[:n]
		if err = packet.ParseIPv4(data, &ipv4); err != nil {
			log.Printf("error to parse IPv4: %s\n", err)
			continue
		}

		// last flag (0x1) is set on all fragments except the last one
		// FragOffset of the last fragment is greater than zero
		if (ipv4.Flags&0x1) != 0 || ipv4.FragOffset != 0 {
			isLastFrag, pkt, rawData := packet.ProcessFragment(&ipv4, data)
			if isLastFrag {
				ipv4 = *pkt
				data = rawData
			} else {
				continue
			}
		}

		switch ipv4.Protocol {
		case packet.IPProtocolTCP:
			if err := packet.ParseTCP(ipv4.Payload, &tcp); err != nil {
				log.Printf("error to parse TCP: %s\n", err)
				continue
			}
			log.Printf("handle tcp to %s:%d", ipv4.DstIP.String(), tcp.DstPort)
			t.HandleTCP(data, &ipv4, &tcp)
		case packet.IPProtocolUDP:
			if err := packet.ParseUdp(ipv4.Payload, &udp); err != nil {
				log.Printf("error to parse UDP: %s\n", err)
				continue
			}
			log.Printf("handle udp to %s:%d", ipv4.DstIP.String(), udp.DstPort)
			t.HandleUDP(data, &ipv4, &udp)
		default:
			log.Printf("unsupported packet protocol: %d", ipv4.Protocol)
		}
	}
}

func (t *Tun) RunWriter() {
	t.wg.Add(1)
	defer t.wg.Done()
	for {
		select {
		case pkt := <-t.WriteCh:
			switch pkt.(type) {
			case *handler.TCPPacket:
				tcp := pkt.(*handler.TCPPacket)
				t.Dev.Write(tcp.Wire)
				handler.ReleaseTCPPacket(tcp)
			case *handler.UDPPacket:
				udp := pkt.(*handler.UDPPacket)
				t.Dev.Write(udp.Wire)
				handler.ReleaseUDPPacket(udp)
			case *packet.IPPacket:
				ip := pkt.(*packet.IPPacket)
				t.Dev.Write(ip.Wire)
				handler.ReleaseIPPacket(ip)
			default:
				log.Printf("packet type %T not supported", pkt)
			}
		case <-t.WriterStopCh:
			log.Printf("quit tun2socks writer")
			return
		}
	}
}

func (t *Tun) Run() {
	dnsServers := strings.Split("8.8.8.8,8.8.4.4", ",")
	enableDnsCache := false

	h := &handler.Handler{
		Dev:            t.dev,
		LocalSocksAddr: "127.0.0.1:1080",
		DNSServers:     dnsServers,

		WriterStopCh: make(chan bool, 10),
		WriteCh:      make(chan interface{}, 10000),

		UDPConnTracks: make(map[string]*handler.UDPConnTrack),
		TCPConnTracks: make(map[string]*handler.TCPConnTrack),
	}

	if enableDnsCache {
		t.Cache = &handler.DnsCache{
			Storage: make(map[string]*handler.DnsCacheEntry),
		}
	}

	t.Handler = h
	go t.RunWriter()
	t.RunReader()
}

func (t *Tun) Stop() {
	t.WriterStopCh <- true
	if err := t.Dev.Close(); err != nil {
		log.Printf("failed to close tun device, err: %v", err)
	}

	t.TCPConnTracksMu.Lock()
	defer t.TCPConnTracksMu.Unlock()
	for _, tcpTrack := range t.TCPConnTracks {
		close(tcpTrack.QuitByOther)
	}

	t.UDPConnTracksMu.Lock()
	defer t.UDPConnTracksMu.Unlock()
	for _, udpTrack := range t.UDPConnTracks {
		close(udpTrack.QuitByOther)
	}
	t.wg.Wait()
}
