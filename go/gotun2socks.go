package gotun2socks

import (
	"context"
	"fmt"
	"log"
	"net"
	"runtime"
	"runtime/debug"
	"strings"

	"github.com/dkwiebe/gotun2socks/internal/tun"
	"github.com/dkwiebe/gotun2socks/internal/tun2socks"
)

type JavaUidCallback interface {
	FindUid(sourceIp string, sourcePort int, destIp string, destPort int) int
}

type Callbacks struct {
	uidCallback JavaUidCallback
}

func (c Callbacks) GetUid(sourceIp string, sourcePort uint16, destIp string, destPort uint16) int {
	if c.uidCallback == nil {
		log.Printf("uid callback is nil")
	}

	return c.uidCallback.FindUid(sourceIp, int(sourcePort), destIp, int(destPort))
}

var tun2SocksInstance *tun2socks.Tun2Socks
var defaultProxy = &tun2socks.ProxyServer{
	ProxyType:  tun2socks.PROXY_TYPE_NONE,
	IpAddress:  ":",
	AuthHeader: "",
	Login:      "",
	Password:   "",
}

var dnsServer string = ""
var dnsPort uint16 = 53
var dnsIp net.IP
var callback *Callbacks = nil
var customDialer net.Dialer
var proxyServerMap map[int]*tun2socks.ProxyServer

func SayHi() string {
	return "hi from tun2http!"
}

func AddProxyServer(uid int, ipPort string, proxyType int, httpAuthHeader string, login string, password string) {
	if proxyServerMap == nil {
		proxyServerMap = make(map[int]*tun2socks.ProxyServer)
	}

	if len(ipPort) < 8 {
		proxyType = tun2socks.PROXY_TYPE_NONE
	}

	proxy := &tun2socks.ProxyServer{
		ProxyType:  proxyType,
		IpAddress:  ipPort,
		AuthHeader: httpAuthHeader,
		Login:      login,
		Password:   password,
	}

	proxyServerMap[uid] = proxy
	log.Printf("Set proxy for uid %d", uid)
}

func SetDefaultProxy(ipPort string, proxyType int, httpAuthHeader string, login string, password string) {
	if len(ipPort) < 8 {
		proxyType = tun2socks.PROXY_TYPE_NONE
	}

	defaultProxy = &tun2socks.ProxyServer{
		ProxyType:  proxyType,
		IpAddress:  ipPort,
		AuthHeader: httpAuthHeader,
		Login:      login,
		Password:   password,
	}
	log.Printf("Set default proxy")
}

func SetUidCallback(javaCallback JavaUidCallback) {
	callback = &Callbacks{
		uidCallback: javaCallback,
	}

	if tun2SocksInstance != nil {
		tun2SocksInstance.SetUidCallback(callback)
	}

	log.Printf("Uid callback set")
}

func SetDnsServer(server string, port int) {
	dnsServer = server
	dnsPort = uint16(port)
	dnsIp = net.ParseIP(server)

	if strings.Count(server, ":") > 1 { //ipv6
		dnsServer = fmt.Sprintf("[%s]:%d", server, port)
	} else {
		dnsServer = fmt.Sprintf("%s:%d", server, port)
	}
}

func Run(descriptor int, maxCpus int, startLocalServer bool, certPath, certKeyPath string) {
	//runtime.GOMAXPROCS(maxCpus)

	var tunAddr string = "10.253.253.253"
	var tunGW string = "10.0.0.1"
	var enableDnsCache bool = true

	f := tun.NewTunDev(uintptr(descriptor), "tun0", tunAddr, tunGW)
	tun2SocksInstance = tun2socks.New(f, enableDnsCache, dnsIp, dnsPort)

	tun2SocksInstance.SetDefaultProxy(defaultProxy)
	tun2SocksInstance.SetProxyServers(proxyServerMap)
	if callback != nil && callback.uidCallback != nil {
		tun2SocksInstance.SetUidCallback(callback)
	} else {
		tun2SocksInstance.SetUidCallback(nil)
	}

	go func() {
		tun2SocksInstance.Run()
	}()

	customDialer = net.Dialer{}

	if len(dnsServer) > 0 {
		r := net.Resolver{
			PreferGo: true,
			Dial:     customDNSDialer,
		}
		net.DefaultResolver = &r

	}

	if startLocalServer {
		startGoProxyServer(certPath, certKeyPath)
	}

	log.Printf("Tun2Htpp started")
	debug.SetTraceback("all")
	debug.SetPanicOnFault(true)
}

func Stop() {
	tun2SocksInstance.Stop()
	stopGoProxyServer()
}

func Prof() {
	//pprof.Lookup("goroutine").WriteTo(os.Stdout, 1)
	runtime.GC()
	debug.FreeOSMemory()
}

func customDNSDialer(ctx context.Context, network, address string) (net.Conn, error) {
	conn, e := customDialer.DialContext(ctx, "udp", dnsServer)
	if e != nil {
		log.Printf("Error dns dial err %s", e)
	}
	return conn, e
}
