package gotun2socks

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/cloudveiltech/goproxy"
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
	proxy.Verbose = true

	proxy.NonproxyHandler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Host == "" {
			fmt.Fprintln(w, "Cannot handle requests without Host header, e.g., HTTP 1.0")
			return
		}

		req.URL.Scheme = "http"
		req.URL.Host = req.Host
		proxy.ServeHTTP(w, req)
	})

	proxy.WebSocketHandler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		h, ok := w.(http.Hijacker)
		if !ok {
			return
		}

		client, _, err := h.Hijack()
		if err != nil {
			log.Printf("Websocket error Hijack %s", err)
			return
		}

		remote := dialRemote(req)

		defer remote.Close()
		defer client.Close()

		log.Printf("Got websocket request %s %s", req.Host, req.URL)

		req.Write(remote)
		go func() {
			for {
				n, err := io.Copy(remote, client)
				if err != nil {
					log.Printf("Websocket error request %s", err)
					return
				}
				if n == 0 {
					log.Printf("Websocket nothing requested close")
					return
				}
				time.Sleep(time.Millisecond) //reduce CPU usage due to infinite nonblocking loop
			}
		}()

		for {
			n, err := io.Copy(client, remote)
			if err != nil {
				log.Printf("Websocket error response %s", err)
				return
			}
			if n == 0 {
				log.Printf("Websocket nothing responded close")
				return
			}
			time.Sleep(time.Millisecond) //reduce CPU usage due to infinite nonblocking loop
		}
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
