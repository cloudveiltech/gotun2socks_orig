package gotun2socks

import (
	"log"
	"os"
	"runtime/debug"
	"runtime/pprof"
	"strings"

	"github.com/dkwiebe/gotun2socks/internal/tun"
	"github.com/dkwiebe/gotun2socks/internal/tun2socks"
)

var tun2SocksInstance *tun2socks.Tun2Socks
var defaultProxy *tun2socks.ProxyServer
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

func Run(descriptor int) {
	var tunAddr string = "10.0.0.2"
	var tunGW string = "10.0.0.1"
	var tunDNS string = "8.8.8.8,8.8.4.4"
	var enableDnsCache bool = true

	dnsServers := strings.Split(tunDNS, ",")
	f := tun.NewTunDev(uintptr(descriptor), "tun0", tunAddr, tunGW)
	tun2SocksInstance = tun2socks.New(f, dnsServers, enableDnsCache)

	tun2SocksInstance.SetDefaultProxy(defaultProxy)
	tun2SocksInstance.SetProxyServers(proxyServerMap)

	go func() {
		tun2SocksInstance.Run()
	}()

	log.Printf("Tun2Htpp started")
	debug.SetTraceback("all")
	debug.SetPanicOnFault(true)
}

func Stop() {
	tun2SocksInstance.Stop()
}

func Prof() {
	pprof.Lookup("goroutine").WriteTo(os.Stdout, 1)
}
