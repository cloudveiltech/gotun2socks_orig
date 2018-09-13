package gotun2socks

import (
	"strings"

	"github.com/dkwiebe/gotun2socks/internal/tun2socks"
	"github.com/dkwiebe/gotun2socks/internal/tun"
)

func main() {}

var tun2SocksInstance *tun2socks.Tun2Socks

func SayHi() string {
	return "hi from tun2http!"
}

func Run(descriptor int) {
	var tunAddr string = "10.0.0.2"
	var tunGW string = "10.0.0.1"
	var tunDNS string = "8.8.8.8,8.8.4.4"
	var localSocksAddr string = "172.104.6.115:10901"
	var publicOnly bool = true
	var enableDnsCache bool = true

	dnsServers := strings.Split(tunDNS, ",")
	f := tun.NewTunDev(uintptr(descriptor), "tun0", tunAddr, tunGW)
	
	tun2SocksInstance := tun2socks.New(f, localSocksAddr, dnsServers, publicOnly, enableDnsCache)
	go func() {
		tun2SocksInstance.Run()
	}()
}

func Stop() {
	tun2SocksInstance.Stop()
}