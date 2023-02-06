package handler

import (
	"io"
	"log"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/yinghuocho/gosocks"
)

type DnsCacheEntry struct {
	msg *dns.Msg
	exp time.Time
}

type DnsCache struct {
	servers []string
	mu      sync.Mutex
	Storage map[string]*DnsCacheEntry
}

// packUint16 converts uint16 to a 2-byte array
func packUint16(i uint16) []byte {
	// i >> 8 is the right 8 bytes
	// byte(i) is the left 8 bytes
	return []byte{byte(i >> 8), byte(i)}
}

func dnsCacheKey(q dns.Question) string {
	return string(append([]byte(q.Name), packUint16(q.Qtype)...))
}

// query tries to find a response for payload in dns cache
func (dc *DnsCache) query(payload []byte) *dns.Msg {
	request := new(dns.Msg)
	e := request.Unpack(payload)
	if e != nil {
		return nil
	}
	if len(request.Question) == 0 {
		return nil
	}

	dc.mu.Lock()
	defer dc.mu.Unlock()
	key := dnsCacheKey(request.Question[0])
	entry := dc.Storage[key]
	if entry == nil {
		return nil
	}
	if time.Now().After(entry.exp) {
		delete(dc.Storage, key)
		return nil
	}
	entry.msg.Id = request.Id
	return entry.msg
}

func (dc *DnsCache) store(payload []byte) {
	resp := &dns.Msg{}
	if err := resp.Unpack(payload); err != nil {
		return
	}
	if resp.Rcode != dns.RcodeSuccess {
		return
	}
	if len(resp.Question) == 0 || len(resp.Answer) == 0 {
		return
	}

	dc.mu.Lock()
	defer dc.mu.Unlock()
	key := dnsCacheKey(resp.Question[0])
	log.Printf("cache DNS response for %s\n", key)
	dc.Storage[key] = &DnsCacheEntry{
		msg: resp,
		exp: time.Now().Add(time.Duration(resp.Answer[0].Header().Ttl) * time.Second),
	}
}

type Handler struct {
	Dev            io.ReadWriteCloser
	LocalSocksAddr string

	TCPConnTracks   map[string]*TCPConnTrack
	TCPConnTracksMu sync.Mutex

	UDPConnTracks   map[string]*UDPConnTrack
	UDPConnTracksMu sync.Mutex

	WriterStopCh chan bool
	WriteCh      chan interface{}

	DNSServers []string
	Cache      *DnsCache
}

var (
	localSocksDialer = &gosocks.SocksDialer{
		Auth:    &gosocks.AnonymousClientAuthenticator{},
		Timeout: 1 * time.Second,
	}
)

func dialLocalSocks(localAddr string) (*gosocks.SocksConn, error) {
	return localSocksDialer.Dial(localAddr)
}

func (h *Handler) clearTCPConnTrack(connId string) {
	h.TCPConnTracksMu.Lock()
	defer h.TCPConnTracksMu.Unlock()

	delete(h.TCPConnTracks, connId)
	log.Printf("tracking %d TCP connections\n", len(h.TCPConnTracks))
}

func (h *Handler) isDNS(remoteIP string, remotePort uint16) bool {
	if remotePort != 53 {
		return false
	}
	for _, s := range h.DNSServers {
		if s == remoteIP {
			return true
		}
	}
	return false
}
