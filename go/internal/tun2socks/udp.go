package tun2socks

import (
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/dkwiebe/gotun2socks/internal/gosocks"
	"github.com/dkwiebe/gotun2socks/internal/packet"
	"github.com/miekg/dns"
)

type udpPacket struct {
	ip     *packet.Ip
	udp    *packet.UDP
	mtuBuf []byte
	wire   []byte
}

type udpConnTrack struct {
	t2s *Tun2Socks
	id  string

	toTunCh     chan<- interface{}
	quitBySelf  chan bool
	quitByOther chan bool

	fromTunCh   chan *udpPacket
	socksClosed chan bool

	socksConn *gosocks.SocksConn

	localIP    net.IP
	remoteIP   net.IP
	localPort  uint16
	remotePort uint16

	destroyed bool
}

var (
	udpPacketPool = &sync.Pool{
		New: func() interface{} {
			return &udpPacket{}
		},
	}
)

func newUDPPacket() *udpPacket {
	return udpPacketPool.Get().(*udpPacket)
}

func releaseUDPPacket(pkt *udpPacket) {
	packet.ReleaseIP(pkt.ip)
	packet.ReleaseUDP(pkt.udp)
	if pkt.mtuBuf != nil {
		releaseBuffer(pkt.mtuBuf)
	}
	pkt.mtuBuf = nil
	pkt.wire = nil
	udpPacketPool.Put(pkt)
}

func udpConnID(ip *packet.Ip, udp *packet.UDP) string {
	return strings.Join([]string{
		ip.Src.String(),
		fmt.Sprintf("%d", udp.SrcPort),
		ip.Dst.String(),
		fmt.Sprintf("%d", udp.DstPort),
	}, "|")
}

func copyUDPPacket(raw []byte, ip *packet.Ip, udp *packet.UDP) *udpPacket {
	iphdr := packet.NewIP()
	udphdr := packet.NewUDP()
	pkt := newUDPPacket()

	// make a deep copy
	var buf []byte
	if len(raw) <= MTU {
		buf = newBuffer()
		pkt.mtuBuf = buf
	} else {
		buf = make([]byte, len(raw))
	}
	n := copy(buf, raw)
	pkt.wire = buf[:n]
	packet.ParseIp(pkt.wire, iphdr)
	packet.ParseUDP(iphdr.Payload, udphdr)
	pkt.ip = iphdr
	pkt.udp = udphdr

	return pkt
}

func responsePacket(local net.IP, remote net.IP, lPort uint16, rPort uint16, respPayload []byte) (*udpPacket, []*ipPacket) {
	ipid := packet.IPID()
	udp := packet.NewUDP()

	var ip *packet.Ip
	if remote.To4() != nil {
		ip = packet.NewIP4()
		ip.V4.Id = ipid
	} else {
		ip = packet.NewIP6()
	}

	ip.Src = make(net.IP, len(remote))
	copy(ip.Src, remote)
	ip.Dst = make(net.IP, len(local))
	copy(ip.Dst, local)

	ip.SetHopLimit(64)
	ip.SetNextProto(packet.IPProtocolUDP)

	udp.SrcPort = rPort
	udp.DstPort = lPort
	udp.Payload = respPayload

	pkt := newUDPPacket()
	pkt.ip = ip
	pkt.udp = udp

	pkt.mtuBuf = newBuffer()
	payloadL := len(udp.Payload)
	payloadStart := MTU - payloadL
	// if payload too long, need fragment, only part of payload put to mtubuf[28:]
	if payloadL > MTU-28 {
		if ip.Version == 4 {
			ip.V4.Flags = 1
		}
		payloadStart = 28
	}
	udpHL := 8
	udpStart := payloadStart - udpHL
	pseduoStart := udpStart - packet.IP4_PSEUDO_LENGTH
	if ip.Version == 6 {
		pseduoStart = udpStart - packet.IP6_PSEUDO_LENGTH
	}
	ip.PseudoHeader(pkt.mtuBuf[pseduoStart:udpStart], packet.IPProtocolUDP, udpHL+payloadL)
	// udp length and checksum count on full payload
	udp.Serialize(pkt.mtuBuf[udpStart:payloadStart], pkt.mtuBuf[pseduoStart:payloadStart], udp.Payload)
	if payloadL != 0 {
		copy(pkt.mtuBuf[payloadStart:], udp.Payload)
	}
	ipHL := ip.HeaderLength()
	ipStart := udpStart - ipHL
	// ip length and checksum count on actual transmitting payload
	ip.Serialize(pkt.mtuBuf[ipStart:udpStart], udpHL+(MTU-payloadStart))
	pkt.wire = pkt.mtuBuf[ipStart:]

	if ip.Version == 4 {
		if ip.V4.Flags == 0 {
			return pkt, nil
		}
	} else {
		return pkt, nil
	}

	// generate fragments
	frags := genFragments(ip, (MTU-20)/8, respPayload[MTU-28:])
	return pkt, frags
}

func (ut *udpConnTrack) send(data []byte) {
	pkt, fragments := responsePacket(ut.localIP, ut.remoteIP, ut.localPort, ut.remotePort, data)
	ut.toTunCh <- pkt
	if fragments != nil {
		for _, frag := range fragments {
			ut.toTunCh <- frag
		}
	}
}

func dialUdpTransparent(address string) (conn *gosocks.SocksConn, err error) {
	c, err := net.DialTimeout("udp", address, time.Second)
	if err != nil {
		log.Printf("Error dial udp: %s", err)
		return
	}
	conn = &gosocks.SocksConn{c.(*net.UDPConn), time.Second}
	return
}

func (ut *udpConnTrack) run() {
	// connect to socks
	var e error

	targetIp := ut.remoteIP
	port := ut.remotePort
	if ut.t2s.isDNS(port) {
		if ut.t2s.customDnsHost != nil {
			port = ut.t2s.customDnsPort
			targetIp = ut.t2s.customDnsHost
		}
	}

	var remoteIpPort = ""
	if targetIp.To4() != nil {
		remoteIpPort = fmt.Sprintf("%s:%d", targetIp.String(), port)
	} else {
		remoteIpPort = fmt.Sprintf("[%s]:%d", targetIp.String(), port)
	}

	ut.socksConn, e = dialUdpTransparent(remoteIpPort) //bypass udp
	if e != nil {
		log.Printf("fail to connect remote ip: %s", e)
	} else {
		ut.socksConn.SetDeadline(time.Now().Add(time.Second * 10))
	}

	if ut.socksConn == nil {
		close(ut.socksClosed)
		close(ut.quitBySelf)
		ut.t2s.clearUDPConnTrack(ut.id)
		return
	}

	// create one UDP to recv/send packets
	socksAddr := ut.socksConn.LocalAddr().(*net.UDPAddr)
	udpBind, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   socksAddr.IP,
		Port: 0,
		Zone: socksAddr.Zone,
	})

	if err != nil {
		log.Printf("error in binding local UDP: %s", err)
		ut.socksConn.Close()
		close(ut.socksClosed)
		close(ut.quitBySelf)
		ut.t2s.clearUDPConnTrack(ut.id)
		return
	}

	relayAddr := gosocks.SocksAddrToNetAddr("udp", targetIp.String(), port).(*net.UDPAddr)

	ut.socksConn.SetDeadline(time.Time{})
	// monitor socks TCP connection
	//go gosocks.ConnMonitor(ut.socksConn, ut.socksClosed)
	// read UDP packets from relay
	quitUDP := make(chan bool)
	chRelayUDP := make(chan *gosocks.UDPPacket)
	go gosocks.UDPReader(udpBind, chRelayUDP, quitUDP)

	//start := time.Now()
	for {
		var t = time.NewTimer(time.Second)

		if ut.t2s.stopped {
			return
		}

		select {
		// pkt from relay
		case pkt, ok := <-chRelayUDP:
			if !ok {
				ut.socksConn.Close()
				udpBind.Close()
				close(ut.quitBySelf)
				ut.t2s.clearUDPConnTrack(ut.id)
				close(quitUDP)
				return
			}

			ut.send(pkt.Data)

			if ut.t2s.isDNS(ut.remotePort) {
				// dumpDnsResponse(pkt.Data)
				// DNS-without-fragment only has one request-response
				//	end := time.Now()
				//	ms := end.Sub(start).Nanoseconds() / 1000000
				if ut.remoteIP.To4() != nil {
					if ut.t2s.cache != nil {
						ut.t2s.cache.store(pkt.Data)
					}
				}
				ut.socksConn.Close()
				udpBind.Close()
				close(ut.quitBySelf)
				ut.t2s.clearUDPConnTrack(ut.id)
				close(quitUDP)
				return
			}

		// pkt from tun
		case pkt := <-ut.fromTunCh:
			_, err := udpBind.WriteToUDP(pkt.udp.Payload, relayAddr)
			releaseUDPPacket(pkt)
			if err != nil {
				log.Printf("error to send UDP packet to relay: %s", err)
				ut.socksConn.Close()
				udpBind.Close()
				close(ut.quitBySelf)
				ut.t2s.clearUDPConnTrack(ut.id)
				close(quitUDP)
				return
			}

		case <-ut.socksClosed:
			ut.socksConn.Close()
			udpBind.Close()
			close(ut.quitBySelf)
			ut.t2s.clearUDPConnTrack(ut.id)
			close(quitUDP)
			return

		case <-t.C:
			ut.socksConn.Close()
			udpBind.Close()
			close(ut.quitBySelf)
			ut.t2s.clearUDPConnTrack(ut.id)
			close(quitUDP)
			return

		case <-ut.quitByOther:
			ut.socksConn.Close()
			udpBind.Close()
			close(quitUDP)
			return
			//	default:
			//		time.Sleep(time.Millisecond)
		}
		t.Stop()
	}
}

func dumpDnsResponse(payload []byte) {
	resp := new(dns.Msg)
	e := resp.Unpack(payload)
	if e != nil {
		log.Printf("Error parsing dns1 %s", e)
		return
	}
	log.Printf("DNS dump:")
	log.Printf(resp.String())
}

func (ut *udpConnTrack) newPacket(pkt *udpPacket) {
	select {
	case <-ut.quitByOther:
	case <-ut.quitBySelf:
	case ut.fromTunCh <- pkt:
	}
}

func (t2s *Tun2Socks) clearUDPConnTrack(id string) {
	t2s.udpConnTrackLock.Lock()
	defer t2s.udpConnTrackLock.Unlock()

	track := t2s.udpConnTrackMap[id]
	track.destroyed = true

	delete(t2s.udpConnTrackMap, id)
}

func (t2s *Tun2Socks) getUDPConnTrack(id string, ip *packet.Ip, udp *packet.UDP) *udpConnTrack {
	t2s.udpConnTrackLock.Lock()
	defer t2s.udpConnTrackLock.Unlock()

	track := t2s.udpConnTrackMap[id]
	if track != nil && !track.destroyed {
		return track
	} else {
		if track != nil && track.destroyed {
			t2s.clearUDPConnTrack(id)
		}

		track := &udpConnTrack{
			t2s:         t2s,
			id:          id,
			toTunCh:     t2s.writeCh,
			fromTunCh:   make(chan *udpPacket, 100),
			socksClosed: make(chan bool),
			quitBySelf:  make(chan bool),
			quitByOther: make(chan bool),

			localPort:  udp.SrcPort,
			remotePort: udp.DstPort,
			destroyed:  false,
		}
		track.localIP = make(net.IP, len(ip.Src))
		copy(track.localIP, ip.Src)
		track.remoteIP = make(net.IP, len(ip.Dst))
		copy(track.remoteIP, ip.Dst)

		t2s.udpConnTrackMap[id] = track
		go track.run()
		return track
	}
}

func (t2s *Tun2Socks) udp(raw []byte, ip *packet.Ip, udp *packet.UDP) {
	var buf [1024]byte
	var done bool

	// first look at dns cache
	if t2s.cache != nil && t2s.isDNS(udp.DstPort) {
		answer := t2s.cache.query(udp.Payload)
		if answer != nil {
			data, e := answer.PackBuffer(buf[:])
			if e == nil {
				resp, fragments := responsePacket(ip.Src, ip.Dst, udp.SrcPort, udp.DstPort, data)
				go func(first *udpPacket, frags []*ipPacket) {
					t2s.writeCh <- first
					if frags != nil {
						for _, frag := range frags {
							t2s.writeCh <- frag
						}
					}
				}(resp, fragments)
				done = true
			}
		}
	}

	if !t2s.isDNS(udp.DstPort) {
		done = true
	}

	// then open a udpConnTrack to forward
	if !done {
		connID := udpConnID(ip, udp)
		pkt := copyUDPPacket(raw, ip, udp)
		track := t2s.getUDPConnTrack(connID, ip, udp)
		track.newPacket(pkt)
	}
}

type dnsCacheEntry struct {
	msg *dns.Msg
	exp time.Time
}

type dnsCache struct {
	servers []string
	mutex   sync.Mutex
	storage map[string]*dnsCacheEntry
}

func packUint16(i uint16) []byte { return []byte{byte(i >> 8), byte(i)} }

func cacheKey(q dns.Question) string {
	return string(append([]byte(q.Name), packUint16(q.Qtype)...))
}

func (t2s *Tun2Socks) isDNS(remotePort uint16) bool {
	return remotePort == 53 || remotePort == 853
}

func (c *dnsCache) query(payload []byte) *dns.Msg {
	return nil

	request := new(dns.Msg)
	e := request.Unpack(payload)
	if e != nil {
		return nil
	}
	if len(request.Question) == 0 {
		return nil
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()
	key := cacheKey(request.Question[0])
	entry := c.storage[key]
	if entry == nil {
		return nil
	}
	if time.Now().After(entry.exp) {
		delete(c.storage, key)
		return nil
	}
	entry.msg.Id = request.Id
	return entry.msg
}

func (c *dnsCache) store(payload []byte) {
	return

	resp := new(dns.Msg)
	e := resp.Unpack(payload)
	if e != nil {
		return
	}
	if resp.Rcode != dns.RcodeSuccess {
		return
	}
	if len(resp.Question) == 0 || len(resp.Answer) == 0 {
		return
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()
	key := cacheKey(resp.Question[0])
	c.storage[key] = &dnsCacheEntry{
		msg: resp,
		exp: time.Now().Add(time.Duration(resp.Answer[0].Header().Ttl) * time.Second),
	}
}
