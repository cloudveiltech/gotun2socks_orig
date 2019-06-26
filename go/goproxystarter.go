package gotun2socks

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
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

var (
	proxy  *goproxy.ProxyHttpServer
	server *http.Server
)

var caCert = []byte(`-----BEGIN CERTIFICATE-----
MIICwDCCAaigAwIBAgIIcAkf52hi77UwDQYJKoZIhvcNAQELBQAwCzEJMAcGA1UEAwwAMB4XDTE3
MTIxNjE3MDUwM1oXDTIzMTIxNjE3MDUwM1owCzEJMAcGA1UEAwwAMIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAjn9w+G7+wYPyv4gTGrL74TkhaVco2dCHjEJM9EugL2zrpX50yNp55MR/
MGGStlPamh35Pgu0w+EryWgdAUCYjVzPVsrOqDh687ak6qsGrma+VMujCNcklug4loUUN6rbmN/Y
42U0qmg0oTvvwqlBOKaR5elqiinyc0QM1Rq93DOizWXCxOqGBuouPoFKU4eMtlou4RQdGqOKhL75
grNh13b2njjVOddviF3HFqBBBujeNV9yKRNBhTBTLlcn284tJVBaQ/ZCdJe4N3Tyrww0sIHTwcxh
3qEHxe5qyVi4eLXngcArTjKBAv2tdYHukeVse39leP8+h0tlOw6f98O26QIDAQABoygwJjATBgNV
HSUEDDAKBggrBgEFBQcDATAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBHLZgk
WqOYE4Xb8TkhAa7sR/9ngXx+YtHrzSVAH22i4u9Jzli/PHFMBImUn1vaXMObQjJyulJRMLdtSOOS
0vxbivnw7/cTFUIOz0rGTxduJir4nNE+cd/jvJpcGJlvts2ro8Ehocl8Ia8xnxdXzmHicEY3bWJd
YUb2eiIu0jD41tv27VRFnDCPVKTZhs8/Ngu3BoPwFWyAviultIqekbEY9SJdoEcNks3fXTHoYCgD
Szjm7nzomM2FSNYP3nyEf7DgDwMT+R+Yu3AgsiBqFw5hyaxKI+jGE2COQ2m/TcZMeZCdj4h/GAyf
Cj7HthDkIs7LqrAx5lx2vwN4ZHCbd1S1
-----END CERTIFICATE-----`)

var caKey = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEoAIBAAKCAQEAjn9w+G7+wYPyv4gTGrL74TkhaVco2dCHjEJM9EugL2zrpX50
yNp55MR/MGGStlPamh35Pgu0w+EryWgdAUCYjVzPVsrOqDh687ak6qsGrma+VMuj
CNcklug4loUUN6rbmN/Y42U0qmg0oTvvwqlBOKaR5elqiinyc0QM1Rq93DOizWXC
xOqGBuouPoFKU4eMtlou4RQdGqOKhL75grNh13b2njjVOddviF3HFqBBBujeNV9y
KRNBhTBTLlcn284tJVBaQ/ZCdJe4N3Tyrww0sIHTwcxh3qEHxe5qyVi4eLXngcAr
TjKBAv2tdYHukeVse39leP8+h0tlOw6f98O26QIDAQABAoIBAB6lnBdiT9ow1bGJ
w4oXeoKq9duhCkEmTzDERaa46R+qDlhOhTF5g4PHGw+9vH8IM9i3n5ZPkDYcpH0x
riNJ0EV+83zYK3AUjaUC4B80X0B9CmxUS6EoHE90bE87GekLDyWm5w+pAZWwybjv
mhZErqlPcct/0xEaCnHt7dCbasAD7Ef1Jd1aCNAVFCOhrn3EpMlbe/UNXsfnXS8C
Germi+4R89T+AjQS+wTNgqDhbR+W8tC50xZbm4VFWhyzmLTwmKKzi3Mcp8/Ph3Wk
aZJwxnoOvLwvhCCv/T/AGjmO72/LWDKyQi27J5iWp2xDBqOrEykVF7DMQTNSwPZ2
YNoTc+0CgYEA1mqp4g0uxo0FSmOyBLN/uf8tuyuIwhPmSMccrior74etlaqIfo6e
yaALi4ccw8ma857xsT1kMSlc0qn9TorPWoyP5iBQO/F8pUpCtVcjUTF225hhB04V
vI5AjZ9zaCSlJO0Sh/2yiIEkOgfjr7Eu6mAyr7oMP1ygg4bfNSnXxocCgYEAqiIo
lVpAxFLK0qj+RjK581XWB3zH25ftbA1z7UhIjY/07yDz3PFFRPEoH80epq+ZdwHw
XQFuC2JnPyreqeJqsn+J+0+CTR6NWOdHEW3hR7Oeiw+ttregrBUqAT2QE9Dhxh8o
p5Uz0+V3TPrSvKiPTG8GJyLcqC0VfXq7K/Q4gw8CgYAd1aOjx4/NosusqSiZDNzl
5YLYe1tBHgG5+LKd7VJFtwxJOfxaF8Ayb+mLVZaEC6Za5a/dqJwrVwUKbwrHBfuK
LurK644eeSCN40Ja9y/72TUfoxlFKfFOVkDXM+ub/xVXiQE+GOfhpI6E4Jom1TGg
/RewaePQYTQYeQjP3e2fOwKBgHsOyAH3TP9zzwZ+e6T0zfFG9c9mnvyjsHRGasKH
VQsnxAcu85Ss4uiR8e7Go9P3EW619VCgVyNe4sUa0gFZJsnDXF9tTBdR8PUMHChs
LNV7A0McbQ7LVSkDCeXpzIu4u4VdRj+ouNscj6Ubi1AwL64eY/nsymPOcEvZeQa6
2CFbAn9ZkPGtR8GcRpCj3Xe3cvFtnLCoYLHcMsfYtJdNuzgc+NxsHRE8Htv+FNuz
OgKjx8bYAEtKcK1nHl/KPYj12JGPIbTrUDgSseL6s1+B9i9qUDuepWBLVGHyL7hY
8komlPI4M1/6nkIuOCkQtdm6H8EdfIHM34JH0mUkLapm+gEj
-----END RSA PRIVATE KEY-----`)

func setCA() error {
	goproxyCa, err := tls.X509KeyPair(caCert, caKey)
	if err != nil {
		log.Fatalf("Can't load cert key/file")
		return err
	}
	if goproxyCa.Leaf, err = x509.ParseCertificate(goproxyCa.Certificate[0]); err != nil {
		log.Fatalf("Can't parse cert key/file")
		return err
	}
	goproxy.GoproxyCa = goproxyCa
	goproxy.OkConnect = &goproxy.ConnectAction{Action: goproxy.ConnectAccept, TLSConfig: goproxy.TLSConfigFromCA(&goproxyCa)}
	goproxy.MitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: goproxy.TLSConfigFromCA(&goproxyCa)}
	goproxy.HTTPMitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectHTTPMitm, TLSConfig: goproxy.TLSConfigFromCA(&goproxyCa)}
	goproxy.RejectConnect = &goproxy.ConnectAction{Action: goproxy.ConnectReject, TLSConfig: goproxy.TLSConfigFromCA(&goproxyCa)}
	return nil
}

func initGoProxy() {
	//fd, _ := os.Create("err.txt")
	//redirectStderr(fd)

	setCA()

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

func startGoProxyServer() {
	initGoProxy()

	if proxy == nil {
		return
	}

	if proxy.Verbose {
		log.Printf("Server is about to start")
	}

	server = startHttpServer()

	proxy.OnRequest().DoFunc(
		func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
			category := adblockMatcher.TestUrlBlocked(r.URL.String(), r.Host)
			if category != nil {
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
			if !adblockMatcher.IsContentSmallEnoughToFilter(resp.ContentLength) {
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
	context, _ := context.WithTimeout(context.Background(), 1*time.Second)
	server.Shutdown(context)

	server = nil
}
