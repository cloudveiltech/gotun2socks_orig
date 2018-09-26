package tun2socks

import (
	"io"
	"log"
	"net"
	"runtime"
	"sync"
	"time"

	"github.com/dkwiebe/gotun2socks/internal/gosocks"
	"github.com/dkwiebe/gotun2socks/internal/packet"
)

const (
	MTU = 15000

	PROXY_TYPE_NONE  = 0
	PROXY_TYPE_SOCKS = 1
	PROXY_TYPE_HTTP  = 2
)

var (
	localSocksDialer *gosocks.SocksDialer = &gosocks.SocksDialer{
		Auth: &gosocks.UserNamePasswordClientAuthenticator{
			UserName: "cloudveilsocks",
			Password: "cloudveilsocks",
		},
		Timeout: time.Second,
	}

	directDialer *gosocks.SocksDialer = &gosocks.SocksDialer{
		Auth:    &gosocks.HttpAuthenticator{},
		Timeout: time.Second,
	}

	_, ip1, _ = net.ParseCIDR("10.0.0.0/24")
	_, ip2, _ = net.ParseCIDR("172.16.0.0/20")
	_, ip3, _ = net.ParseCIDR("192.168.0.0/16")
)

type ProxyServer struct {
	ProxyType  int
	IpAddress  string
	AuthHeader string
	Login      string
	Password   string
}

type Tun2Socks struct {
	dev io.ReadWriteCloser

	writerStopCh chan bool
	writeCh      chan interface{}

	tcpConnTrackMap    map[string]*tcpConnTrack
	proxyServerMap     map[int]*ProxyServer
	defaultProxyServer *ProxyServer

	tcpConnTrackLock sync.Mutex

	udpConnTrackLock sync.Mutex
	udpConnTrackMap  map[string]*udpConnTrack

	dnsServers []string
	cache      *dnsCache
	stopped    bool

	wg sync.WaitGroup
}

func isPrivate(ip net.IP) bool {
	return ip1.Contains(ip) || ip2.Contains(ip) || ip3.Contains(ip)
}

func dialLocalSocks(proxyServer *ProxyServer) (*gosocks.SocksConn, error) {
	log.Print("dialLocalSocks")
	localSocksDialer.Auth = &gosocks.UserNamePasswordClientAuthenticator{
		UserName: proxyServer.Login,
		Password: proxyServer.Password,
	}

	return localSocksDialer.Dial(proxyServer.IpAddress)
}

func dialTransaprent(localAddr string) (*gosocks.SocksConn, error) {
	log.Print("dialTransaprent")
	return directDialer.Dial(localAddr)
}

func New(dev io.ReadWriteCloser, dnsServers []string, enableDnsCache bool) *Tun2Socks {
	t2s := &Tun2Socks{
		dev:                dev,
		writerStopCh:       make(chan bool, 10),
		writeCh:            make(chan interface{}, 10000),
		tcpConnTrackMap:    make(map[string]*tcpConnTrack),
		udpConnTrackMap:    make(map[string]*udpConnTrack),
		proxyServerMap:     make(map[int]*ProxyServer),
		defaultProxyServer: nil,
		dnsServers:         dnsServers,
		stopped:            false,
	}
	if enableDnsCache {
		t2s.cache = &dnsCache{
			storage: make(map[string]*dnsCacheEntry),
		}
	}
	return t2s
}

func (t2s *Tun2Socks) SetDefaultProxy(proxy *ProxyServer) {
	t2s.defaultProxyServer = proxy
}

func (t2s *Tun2Socks) SetProxyServers(proxyServerMap map[int]*ProxyServer) {
	t2s.proxyServerMap = proxyServerMap
}

func (t2s *Tun2Socks) Stop() {
	t2s.writerStopCh <- true
	t2s.dev.Close()

	t2s.udpConnTrackLock.Lock()
	defer t2s.udpConnTrackLock.Unlock()
	for _, udpTrack := range t2s.udpConnTrackMap {
		close(udpTrack.quitByOther)
	}
	t2s.stopped = true
	t2s.wg.Wait()
	log.Print("Stop")
}

func (t2s *Tun2Socks) Run() {
	// writer
	go func() {
		t2s.wg.Add(1)
		defer t2s.wg.Done()
		for {
			select {
			case pkt := <-t2s.writeCh:
				switch pkt.(type) {
				case *tcpPacket:
					tcp := pkt.(*tcpPacket)
					t2s.dev.Write(tcp.wire)
					releaseTCPPacket(tcp)
				case *udpPacket:
					udp := pkt.(*udpPacket)
					t2s.dev.Write(udp.wire)
					releaseUDPPacket(udp)
				case *ipPacket:
					ip := pkt.(*ipPacket)
					t2s.dev.Write(ip.wire)
					releaseIPPacket(ip)
				}
			case <-t2s.writerStopCh:
				log.Printf("quit tun2socks writer")
				return
			}
		}
	}()

	// reader
	var buf [MTU]byte
	var ip packet.IPv4
	var tcp packet.TCP
	var udp packet.UDP

	//worker
	go func() {
		i := 0
		for {
			//	wasData := t2s.tcpWorker()
			if t2s.stopped {
				for _, tcpTrack := range t2s.tcpConnTrackMap {
					tcpTrack.destroyed = true
					if tcpTrack.socksConn != nil {
						tcpTrack.socksConn.Close()
					}
					close(tcpTrack.quitByOther)
					t2s.clearTCPConnTrack(tcpTrack.id)
				}
				break
			}
			//	if !wasData {
			time.Sleep(100 * time.Millisecond)
			//	}
			i++
			if i > 10 {
				i = 0
				log.Printf("Conn size tcp %d udp %d, routines %d", len(t2s.tcpConnTrackMap), len(t2s.udpConnTrackMap), runtime.NumGoroutine())
			}
		}
		log.Printf("Worker exit")
	}()

	t2s.wg.Add(1)
	defer t2s.wg.Done()
	for {
		n, e := t2s.dev.Read(buf[:])
		if e != nil {
			// TODO: stop at critical error
			log.Printf("read packet error: %s", e)
			return
		}

		if t2s.stopped {
			log.Printf("quit tun2socks reader")
			return
		}

		data := buf[:n]
		e = packet.ParseIPv4(data, &ip)
		if e != nil {
			log.Printf("error to parse IPv4: %s", e)
			continue
		}

		if ip.Flags&0x1 != 0 || ip.FragOffset != 0 {
			last, pkt, raw := procFragment(&ip, data)
			if last {
				ip = *pkt
				data = raw
			} else {
				continue
			}
		}
		switch ip.Protocol {
		case packet.IPProtocolTCP:
			e = packet.ParseTCP(ip.Payload, &tcp)
			if e != nil {
				log.Printf("error to parse TCP: %s", e)
				continue
			}
			t2s.tcp(data, &ip, &tcp)

		case packet.IPProtocolUDP:
			e = packet.ParseUDP(ip.Payload, &udp)
			if e != nil {
				log.Printf("error to parse UDP: %s", e)
				continue
			}
			t2s.udp(data, &ip, &udp)

		default:
			// Unsupported packets
			log.Printf("Unsupported packet: protocol %d", ip.Protocol)
		}
	}
}
