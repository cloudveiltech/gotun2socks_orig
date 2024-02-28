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
	"github.com/getsentry/sentry-go"
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
	defer sentry.Recover()
	// connect to socks
	var e error

	targetIp := ut.remoteIP
	port := ut.remotePort

	isQuic := port == 80 || port == 443
	if isQuic {
		log.Print("QUIC blocked 1")
		if ut.socksConn != nil {
			ut.socksConn.Close()
		}
		close(ut.socksClosed)
		close(ut.quitBySelf)
		ut.t2s.clearUDPConnTrack(ut.id)
		return
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
	defer func() {
		ut.socksConn.Close()
		udpBind.Close()
		close(ut.quitBySelf)
		ut.t2s.clearUDPConnTrack(ut.id)
		quitUDP <- true
		close(quitUDP)
		log.Print("Close UPD Run")
	}()
	go gosocks.UDPReader(udpBind, chRelayUDP, quitUDP)

	//start := time.Now()
	for {
		if ut.t2s.stopped {
			return
		}

		select {
		// pkt from relay
		case pkt, ok := <-chRelayUDP:
			if !ok {
				return
			}
			ut.send(pkt.Data)
		case pkt := <-ut.fromTunCh:
			_, err := udpBind.WriteToUDP(pkt.udp.Payload, relayAddr)
			releaseUDPPacket(pkt)
			if err != nil {
				log.Printf("error to send UDP packet to relay: %s", err)
				return
			}
		case <-ut.socksClosed:
			return
		case <-ut.quitByOther:
			return
		}
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
	if track != nil {
		track.destroyed = true
		delete(t2s.udpConnTrackMap, id)
	}
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
	log.Printf("UDP worker: %d %d", ip.Dst, udp.DstPort)
	connID := udpConnID(ip, udp)
	pkt := copyUDPPacket(raw, ip, udp)
	track := t2s.getUDPConnTrack(connID, ip, udp)
	track.newPacket(pkt)
}

func packUint16(i uint16) []byte { return []byte{byte(i >> 8), byte(i)} }
