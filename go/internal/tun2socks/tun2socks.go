package tun2socks

import (
	"fmt"
	"io"
	"log"
	"net"
	"runtime"
	"runtime/debug"
	"sync"
	"time"

	"github.com/dkwiebe/gotun2socks/internal/gosocks"
	"github.com/dkwiebe/gotun2socks/internal/packet"
)

const (
	MTU = 10240

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

	privateIPBlocks []*net.IPNet
)

func initPrivateIps() {
	for _, cidr := range []string{
		"127.0.0.0/8",    // IPv4 loopback
		"10.0.0.0/8",     // RFC1918
		"172.16.0.0/12",  // RFC1918
		"192.168.0.0/16", // RFC1918
		"::1/128",        // IPv6 loopback
		"fe80::/10",      // IPv6 link-local
		"fc00::/7",       // IPv6 unique local addr
	} {
		_, block, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Printf("Error parsing cidr %s", err)
			continue
		}
		privateIPBlocks = append(privateIPBlocks, block)
	}
}

type ProxyServer struct {
	ProxyType  int
	IpAddress  string
	AuthHeader string
	Login      string
	Password   string
}

type UidCallback interface {
	GetUid(sourceIp string, sourcePort uint16, destIp string, destPort uint16) int
}

type Tun2Socks struct {
	dev io.ReadWriteCloser

	writerStopCh chan bool
	writeCh      chan interface{}

	tcpConnTrackMap    map[string]*tcpConnTrack
	proxyServerMap     map[int]*ProxyServer
	defaultProxyServer *ProxyServer
	uidCallback        UidCallback

	tcpConnTrackLock      sync.Mutex
	ipDirectConnTrackLock sync.Mutex

	udpConnTrackLock sync.Mutex
	udpConnTrackMap  map[string]*udpConnTrack
	cache            *dnsCache
	stopped          bool

	wg sync.WaitGroup

	customDnsHost net.IP
	customDnsPort uint16
}

func isPrivate(ip net.IP) bool {
	return false
	/*
		if len(privateIPBlocks) == 0 {
			initPrivateIps()
		}
		for _, block := range privateIPBlocks {
			if block.Contains(ip) {
				return true
			}
		}
		return false*/
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
	return directDialer.Dial(localAddr)
}

func New(dev io.ReadWriteCloser, enableDnsCache bool, dnsServerIp net.IP, dnsServerPort uint16) *Tun2Socks {
	t2s := &Tun2Socks{
		dev:                dev,
		writerStopCh:       make(chan bool, 10),
		writeCh:            make(chan interface{}, 10000),
		tcpConnTrackMap:    make(map[string]*tcpConnTrack),
		udpConnTrackMap:    make(map[string]*udpConnTrack),
		proxyServerMap:     make(map[int]*ProxyServer),
		uidCallback:        nil,
		defaultProxyServer: nil,
		stopped:            false,
		customDnsHost:      dnsServerIp,
		customDnsPort:      dnsServerPort,
	}
	if enableDnsCache {
		t2s.cache = &dnsCache{
			storage: make(map[string]*dnsCacheEntry),
		}
	}
	return t2s
}

func (t2s *Tun2Socks) SetUidCallback(uidCallback UidCallback) {
	t2s.uidCallback = uidCallback
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

	t2s.tcpConnTrackLock.Lock()
	defer t2s.tcpConnTrackLock.Unlock()
	for _, tcpTrack := range t2s.tcpConnTrackMap {
		tcpTrack.destroyed = true
		if tcpTrack.socksConn != nil {
			tcpTrack.socksConn.Close()
		}
		close(tcpTrack.quitByOther)
	}
	t2s.tcpConnTrackMap = make(map[string]*tcpConnTrack)

	t2s.udpConnTrackLock.Lock()
	defer t2s.udpConnTrackLock.Unlock()
	for _, udpTrack := range t2s.udpConnTrackMap {
		close(udpTrack.quitByOther)
	}
	t2s.udpConnTrackMap = make(map[string]*udpConnTrack)

	t2s.stopped = true
	//t2s.wg.Wait()
	log.Print("Stop")
}

func (t2s *Tun2Socks) Run() {
	// writer
	go func() {
		t2s.wg.Add(1)
		defer t2s.wg.Done()

		buf := make([]byte, 2*MTU)
		for {
			select {
			case pkt := <-t2s.writeCh:
				switch pkt.(type) {
				case *tcpPacket:
					tcp := pkt.(*tcpPacket)
					wireStart := tcp.packTcpIntoBuff(buf)
					t2s.dev.Write(buf[wireStart:])
					releaseTCPPacket(tcp)
				case *udpPacket:
					udp := pkt.(*udpPacket)
					t2s.dev.Write(udp.wire)
					releaseUDPPacket(udp)
				case *ipPacket:
					ip := pkt.(*ipPacket)
					t2s.dev.Write(ip.wire)
					releaseIPPacket(ip)
				case []byte:
					t2s.dev.Write(pkt.([]byte))
				}
			case <-t2s.writerStopCh:
				log.Printf("quit tun2socks writer")
				return
			}
		}
	}()

	// reader
	var buf [MTU]byte
	var ip packet.Ip
	var tcp packet.TCP
	var udp packet.UDP

	//worker
	go func() {
		for {
			if t2s.stopped {
				break
			}

			time.Sleep(1000 * time.Millisecond)

			debug.FreeOSMemory()
			log.Printf("Conn size tcp %d udp %d, routines %d", len(t2s.tcpConnTrackMap), len(t2s.udpConnTrackMap), runtime.NumGoroutine())
		}
		log.Printf("Worker exit")
	}()

	t2s.wg.Add(1)
	defer t2s.wg.Done()
	for {
		n, e := t2s.dev.Read(buf[:])

		if t2s.stopped {
			log.Printf("quit tun2socks reader")
			return
		}

		if n == 0 {
			time.Sleep(time.Millisecond)
			continue
		}
		if e != nil {
			// TODO: stop at critical error
			log.Printf("read packet error: %s", e)
			return
		}

		data := buf[:n]
		e = packet.ParseIp(data, &ip)
		if e != nil {
			log.Printf("error to parse Ip: %s", e)
			continue
		}

		if ip.Version == 4 {
			if ip.V4.Flags&0x1 != 0 || ip.V4.FragOffset != 0 {
				last, pkt, raw := procFragment(&ip, data)
				if last {
					ip = *pkt
					data = raw
				} else {
					continue
				}
			}
		}

		switch ip.GetNextProto() {
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
			log.Printf("Unsupported packet protocol %d", ip.GetNextProto())

		}
	}
}

func byteCountBinary(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(b)/float64(div), "KMGTPE"[exp])
}
