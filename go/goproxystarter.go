package gotun2socks

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/inconshreveable/go-vhost"
)

//import _ "net/http/pprof"

var (
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

func dialRemote(req *http.Request) net.Conn {
	port := ""
	if !strings.Contains(req.Host, ":") {
		if req.URL.Scheme == "https" {
			port = ":443"
		} else {
			port = ":80"
		}
	}

	if req.URL.Scheme == "https" {
		conf := tls.Config{
			//InsecureSkipVerify: true,
		}
		remote, err := tls.Dial("tcp", req.Host+port, &conf)
		if err != nil {
			log.Printf("Websocket error connect %s", err)
			return nil
		}
		return remote
	} else {
		remote, err := net.Dial("tcp", req.Host+port)
		if err != nil {
			log.Printf("Websocket error connect %s", err)
			return nil
		}
		return remote
	}
}

func startHttpsServer() {
	// listen to the TLS ClientHello but make it a CONNECT request instead
	ln, err := net.Listen("tcp", ":23501")
	if err != nil {
		log.Fatalf("Error listening for https connections - %v", err)
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Printf("Error accepting new connection - %v", err)
			continue
		}
		go func(c net.Conn) {
			tlsConn, err := vhost.TLS(c)
			if err != nil {
				log.Printf("Error accepting new connection - %v", err)
			}
			if tlsConn.Host() == "" {
				log.Printf("Cannot support non-SNI enabled clients")
				return
			}
			connectReq := &http.Request{
				Method: "CONNECT",
				URL: &url.URL{
					Opaque: tlsConn.Host(),
					Host:   net.JoinHostPort(tlsConn.Host(), "443"),
				},
				Host:       tlsConn.Host(),
				Header:     make(http.Header),
				RemoteAddr: c.RemoteAddr().String(),
			}
			resp := dumbResponseWriter{tlsConn}
			proxy.ServeHTTP(resp, connectReq)
		}(c)
	}
}

type dumbResponseWriter struct {
	net.Conn
}

func (dumb dumbResponseWriter) Header() http.Header {
	panic("Header() should not be called on this ResponseWriter")
}

func (dumb dumbResponseWriter) Write(buf []byte) (int, error) {
	if bytes.Equal(buf, []byte("HTTP/1.0 200 OK\r\n\r\n")) {
		return len(buf), nil // throw away the HTTP OK response from the faux CONNECT request
	}
	return dumb.Conn.Write(buf)
}

func (dumb dumbResponseWriter) WriteHeader(code int) {
	panic("WriteHeader() should not be called on this ResponseWriter")
}

func (dumb dumbResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return dumb, bufio.NewReadWriter(bufio.NewReader(dumb), bufio.NewWriter(dumb)), nil
}

func startHttpServer() *http.Server {
	srv := &http.Server{Addr: fmt.Sprintf(":%d", 23500)}
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

func startGoProxyServer(certPath, certKeyPath string) {
	initGoProxy()
	LoadAndSetCa(certPath, certKeyPath)

	if proxy == nil {
		return
	}

	if proxy.Verbose {
		log.Printf("Server is about to start")
	}

	server = startHttpServer()
	go startHttpsServer()

	proxy.OnRequest().DoFunc(
		func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
			category, matchType := adblockMatcher.TestUrlBlocked(r.URL.String(), r.Host, r.Referer())
			if category != nil && matchType == Included {
				return r, goproxy.NewResponse(r,
					goproxy.ContentTypeHtml, http.StatusForbidden,
					adblockMatcher.GetBlockPage(r.URL.String(), *category, "Blocked by server policy"))
			}
			return r, nil
		})

	proxy.OnResponse().DoFunc(
		func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
			if resp == nil {
				return resp
			}

			if resp.StatusCode > 400 { //ignore errors
				return resp
			}

			if !adblockMatcher.TestContentTypeIsFiltrable(resp.Header.Get("Content-Type")) {
				return resp
			}
			buf := new(bytes.Buffer)
			buf.ReadFrom(resp.Body)

			bytesData := buf.Bytes()

			//since we'd read all body - we need to recreate reader for client here
			resp.Body.Close()
			resp.Body = ioutil.NopCloser(bytes.NewBuffer(bytesData))

			if !adblockMatcher.IsContentSmallEnoughToFilter(int64(len(bytesData))) {
				return resp
			}

			category := adblockMatcher.TestContainsForbiddenPhrases(bytesData)

			if category != nil {
				message := adblockMatcher.GetBlockPage(resp.Request.URL.String(), *category, "Trigger text found")
				return goproxy.NewResponse(resp.Request, goproxy.ContentTypeHtml, http.StatusForbidden, message)
			}
			return resp
		})

	if proxy.Verbose {
		log.Printf("Server started")
	}
}

func stopGoProxyServer() {
	if server != nil {
		context, _ := context.WithTimeout(context.Background(), 1*time.Second)
		server.Shutdown(context)
		server = nil
	}
}
