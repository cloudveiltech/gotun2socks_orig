package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/cloudveiltech/goproxy"
	"github.com/inconshreveable/go-vhost"
	icap "github.com/patriciy/icap-client"
)

type Config struct {
	icapServerReqUrl  string
	icapServerRespUrl string
	port              uint16
}

var (
	config = Config{"", "", 12344}
	proxy  *goproxy.ProxyHttpServer
	server *http.Server
)

func initGoProxy() {
	//fd, _ := os.Create("err.txt")
	//redirectStderr(fd)

	proxy = goproxy.NewProxyHttpServer()
	proxy.Verbose = false

	proxy.NonproxyHandler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Host == "" {
			fmt.Fprintln(w, "Cannot handle requests without Host header, e.g., HTTP 1.0")
			return
		}

		req.URL.Scheme = "http"
		req.URL.Host = req.Host
		proxy.ServeHTTP(w, req)
	})

	proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)

	if proxy.Verbose {
		log.Printf("Server inited")
	}
}

type dumbResponseWriter struct {
	net.Conn
}

func (dumb dumbResponseWriter) Header() http.Header {
	//	panic("Header() should not be called on this ResponseWriter")
	return make(http.Header)
}

func (dumb dumbResponseWriter) Write(buf []byte) (int, error) {
	if bytes.Equal(buf, []byte("HTTP/1.0 200 OK\r\n\r\n")) {
		return len(buf), nil // throw away the HTTP OK response from the faux CONNECT request
	}
	return dumb.Conn.Write(buf)
}

func (dumb dumbResponseWriter) WriteHeader(code int) {
	//	panic("WriteHeader() should not be called on this ResponseWriter")
}

func (dumb dumbResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return dumb, bufio.NewReadWriter(bufio.NewReader(dumb), bufio.NewWriter(dumb)), nil
}

func runHttpsListener() {
	// listen to the TLS ClientHello but make it a CONNECT request instead
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", config.port))

	if err != nil {
		log.Printf("Error listening for https connections - %v", err)
		return
	}

	for {
		c, err := ln.Accept()
		if err != nil {
			log.Printf("Error accepting new connection - %v", err)
			continue
		}

		go func(c net.Conn) {
			tlsConn, err := vhost.TLS(c)
			localPort := tlsConn.RemoteAddr().(*net.TCPAddr).Port

			port := 443
			ipString := "127.0.0.1"
			remoteAddr := tlsConn.LocalAddr().String()
			if strings.Count(remoteAddr, ":") > 1 {
				//ipv6
				ipString = "::1"
			}

			host := tlsConn.Host()
			if host == "" {
				host = ipString
			}

			if err != nil {
				log.Printf("Assuming plain http connection - %v", err)
				chainReqToHttp(tlsConn)
				return
			}

			if proxy.Verbose {
				log.Printf("Reading dest port for %d is %d", localPort, port)
			}

			if proxy.Verbose {
				log.Printf("Https handler called for %s:%s", host, strconv.Itoa(port))
			}

			host = net.JoinHostPort(host, strconv.Itoa(port))
			resp := dumbResponseWriter{tlsConn}
			connectReq := &http.Request{
				Method: "CONNECT",
				URL: &url.URL{
					Opaque: host,
					Host:   host,
				},
				Host:   host,
				Header: make(http.Header),
			}

			proxy.ServeHTTP(resp, connectReq)
		}(c)
	}
}

func startHttpServer() *http.Server {
	srv := &http.Server{Addr: fmt.Sprintf(":%d", config.port+1)}
	srv.Handler = proxy

	// go func() {
	// 	http.ListenAndServe(":6060", nil)
	// }()
	go func() {
		if err := srv.ListenAndServe(); err != nil {
			// cannot panic, because this probably is an intentional close
			log.Printf("Httpserver: ListenAndServe() error: %s", err)
			server = nil
		}
	}()

	// returning reference so caller can call Shutdown()
	return srv
}

func chainReqToHttp(client net.Conn) {
	localAddress := client.LocalAddr().(*net.TCPAddr).IP

	remote, err := net.Dial("tcp", net.JoinHostPort(localAddress.String(), strconv.Itoa(int(config.port+1))))
	if err != nil {
		log.Printf("chainReqToHttp error connect %s", err)
		return
	}

	defer remote.Close()
	defer client.Close()

	go func() {
		nonBlockingCopy(remote, client)
	}()

	nonBlockingCopy(client, remote)
}

func nonBlockingCopy(from, to net.Conn) {
	buf := make([]byte, 10240)
	for {
		from.SetDeadline(time.Now().Add(time.Minute * 10))
		if server == nil {
			log.Printf("Break chain on server stop")
			break
		}

		n, err := from.Read(buf)
		if err != nil && err != io.EOF {
			log.Printf("error request %s", err)
			break
		}
		if n == 0 {
			break
		}

		if _, err := to.Write(buf[:n]); err != nil {
			log.Printf("error response %s", err)
			break
		}

	}
}

func startGoProxyServer(certPath, certKeyPath, icapServerReqUrl, icapServerRespUrl string, port uint16) {
	config.icapServerReqUrl = icapServerReqUrl
	config.icapServerRespUrl = icapServerRespUrl
	config.port = port

	//icap.SetDebugMode(true)
	initGoProxy()
	loadAndSetCa(certPath, certKeyPath)

	if proxy == nil {
		return
	}

	proxy.Http2Handler = serveHttp2Filtering
	if proxy.Verbose {
		log.Printf("Server is about to start")
	}

	icapOptionsReq, icapOptionsResp := initIcapServerConnection()
	if icapOptionsReq == nil || icapOptionsResp == nil {
		return
	}

	server = startHttpServer()
	proxy.OnRequest().DoFunc(
		func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
			icapReq, err := icap.NewRequest(icap.MethodREQMOD, config.icapServerReqUrl, r, nil)
			icapReq.Header.Set("X-ICAP-E2G", "-,G,0,0,0,")
			if err != nil {
				log.Printf("Error icap %v", err)
				return r, nil
			}

			icapReq.SetPreview(icapOptionsReq.PreviewBytes)
			icapReqClient := &icap.Client{
				Timeout: 5000 * time.Second,
			}

			response, err := icapReqClient.Do(icapReq)

			if err != nil {
				log.Printf("Error icap %v", err)
				return r, nil
			}
			request := response.ContentRequest
			if request == nil {
				request = r
			}

			return request, response.ContentResponse
		})

	proxy.OnResponse().DoFunc(
		func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
			if resp == nil {
				return resp
			}

			if resp.StatusCode >= 400 { //ignore errors
				return resp
			}

			icapReq, err := icap.NewRequest(icap.MethodRESPMOD, config.icapServerRespUrl, resp.Request, resp)
			icapReq.Header.Set("X-ICAP-E2G", "-,G,0,0,0,")
			if err != nil {
				log.Printf("Error icap %v", err)
				return resp
			}

			icapReq.SetPreview(icapOptionsResp.PreviewBytes)
			icapRespClient := &icap.Client{
				Timeout: 5000 * time.Second,
			}
			response, err := icapRespClient.Do(icapReq)

			if err != nil {
				log.Printf("Error icap %v", err)
				return resp
			}

			if response.ContentResponse != nil {
				return response.ContentResponse
			}
			return resp
		})

	go runHttpsListener()

	log.Printf("Server started on port %d", config.port)
}

func initIcapServerConnection() (*icap.Response, *icap.Response) {
	optReq, err := icap.NewRequest(icap.MethodOPTIONS, config.icapServerReqUrl, nil, nil)
	if err != nil {
		log.Fatal(err)
		return nil, nil
	}

	client := &icap.Client{
		Timeout: 5000 * time.Second,
	}
	optReqResp, err := client.Do(optReq)
	if err != nil {
		log.Fatal(err)
		return nil, nil
	}

	optReq, err = icap.NewRequest(icap.MethodOPTIONS, config.icapServerRespUrl, nil, nil)
	if err != nil {
		log.Fatal(err)
		return nil, nil
	}

	optRespResp, err := client.Do(optReq)
	if err != nil {
		log.Fatal(err)
		return nil, nil
	}

	return optReqResp, optRespResp
}

func stopGoProxyServer() {
	if server != nil {
		context, _ := context.WithTimeout(context.Background(), 1*time.Second)
		server.Shutdown(context)
		server = nil
	}
}
