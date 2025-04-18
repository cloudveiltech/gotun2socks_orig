package gotun2socks

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"runtime"
	"runtime/debug"
	"runtime/pprof"
	"strings"
	"time"

	"github.com/dkwiebe/gotun2socks/internal/tun"
	"github.com/dkwiebe/gotun2socks/internal/tun2socks"
	"github.com/getsentry/sentry-go"

	//"github.com/getsentry/sentry-go"
	"gopkg.in/natefinch/lumberjack.v2"

	_ "net/http/pprof"
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

var logger *lumberjack.Logger = nil
var sentryLaunched = false
var dnsServerV4 string = ""
var dnsServerV6 string = ""
var dnsPort uint16 = 53
var dnsIp4 net.IP
var dnsIp6 net.IP
var callback *Callbacks = nil
var customDialer net.Dialer
var proxyServerMap map[int]*tun2socks.ProxyServer

func SayHi() string {
	return "hi from tun2http!"
}

func ResetProxyServersMap() {
	proxyServerMap = make(map[int]*tun2socks.ProxyServer)
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

func SetDnsServer(server string, port int, isV4 bool) {
	if len(server) == 0 {
		if isV4 {
			dnsIp4 = nil
			dnsServerV4 = ""
			return
		} else {
			dnsIp6 = nil
			dnsServerV6 = ""
			return
		}
	}
	dnsPort = uint16(port)
	if isV4 {
		dnsIp4 = net.ParseIP(server)
	} else {
		dnsIp6 = net.ParseIP(server)
	}

	if isV4 { //ipv6
		dnsServerV4 = fmt.Sprintf("%s:%d", server, port)
	} else {
		dnsServerV6 = fmt.Sprintf("[%s]:%d", server, port)
	}
}

func SetMaxCpus(maxCpus int) {
	log.Printf("Setting max cpus to %d", maxCpus)
	runtime.GOMAXPROCS(maxCpus)
}

func Run(descriptor int, maxCpus int, logPath string, appVersion string) {
	SetMaxCpus(maxCpus)

	if len(logPath) > 0 {
		setupLogger(logPath)
	}
	setupSentry(appVersion)

	var tunAddr string = "10.253.253.253"
	var tunGW string = "10.0.0.1"

	f := tun.NewTunDev(uintptr(descriptor), "tun0", tunAddr, tunGW)
	tun2SocksInstance = tun2socks.New(f, dnsIp4, dnsIp6, dnsPort)

	tun2SocksInstance.SetDefaultProxy(defaultProxy)
	tun2SocksInstance.SetProxyServers(proxyServerMap)
	if callback != nil && callback.uidCallback != nil {
		tun2SocksInstance.SetUidCallback(callback)
	} else {
		tun2SocksInstance.SetUidCallback(nil)
	}

	go func() {
		defer sentry.Recover()
		tun2SocksInstance.Run()
	}()

	customDialer = net.Dialer{}

	// if len(dnsServerV4) > 0 {
	// 	r := net.Resolver{
	// 		PreferGo: true,
	// 		Dial:     customDNSDialer,
	// 	}
	// 	net.DefaultResolver = &r
	// }

	log.Printf("Tun2Htpp started")
	debug.SetTraceback("all")
	debug.SetPanicOnFault(true)
}

func setupLogger(logFile string) {
	logger = &lumberjack.Logger{
		Filename:   logFile,
		MaxSize:    5, // megabytes
		MaxBackups: 3,
		MaxAge:     30, //days
	}
	log.SetOutput(logger)

	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile)
}

func setupSentry(appVersion string) {
	if sentryLaunched {
		return
	}
	sentryLaunched = true

	err := sentry.Init(sentry.ClientOptions{
		Dsn:     SENTRY_DSN,
		Release: "locker-vpn@" + appVersion,
	})
	if err != nil {
		log.Printf("sentry.Init: %s", err)
	}
}

func Stop() {
	tun2SocksInstance.Stop()
	if logger != nil {
		logger.Close()
	}
	sentry.Flush(time.Second)
}

func Prof() {
	pprof.Lookup("goroutine").WriteTo(os.Stdout, 1)
	//	runtime.GC()
	//	debug.FreeOSMemory()
}

func customDNSDialer(ctx context.Context, network, address string) (net.Conn, error) {
	log.Print("CustomDNSDialer called")
	addressServer := dnsServerV4
	if strings.Contains(address, ":") && !strings.Contains(address, ".") {
		addressServer = dnsServerV6

	}
	conn, e := customDialer.DialContext(ctx, "udp", addressServer)
	if e != nil {
		log.Printf("Error dns dial err %s", e)
	}
	return conn, e
}
