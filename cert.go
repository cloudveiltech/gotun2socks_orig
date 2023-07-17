package main

import (
	"crypto/x509"
	"io/ioutil"
	"log"
	"strings"
	"time"

	"github.com/cloudveiltech/goproxy"
	tls "github.com/refraction-networking/utls"
)

var (
	caCert []byte = goproxy.CA_CERT
	caKey  []byte = goproxy.CA_KEY
)

func loadAndSetCa(certFile, keyFile string) {
	cert, err := ioutil.ReadFile(certFile)
	if err != nil {
		log.Printf("Can't read cert file")
		log.Fatal(err)
		return
	}
	key, err := ioutil.ReadFile(keyFile)
	if err != nil {
		log.Printf("Can't read cert key file")
		log.Fatal(err)
		return
	}

	caCert = cert
	caKey = key
	setCA(caCert, caKey)
}

func setCA(caCert, caKey []byte) error {
	goproxyCa, err := tls.X509KeyPair(caCert, caKey)
	if err != nil {
		log.Printf("Can't load cert/key file")
		log.Fatal(err)
		return err
	}
	if goproxyCa.Leaf, err = x509.ParseCertificate(goproxyCa.Certificate[0]); err != nil {
		log.Printf("Can't parse cert key/file")
		log.Fatal(err)
		return err
	}
	goproxy.GoproxyCa = goproxyCa
	goproxy.OkConnect = &goproxy.ConnectAction{Action: goproxy.ConnectAccept, TLSConfig: goproxy.TLSConfigFromCA(&goproxyCa)}
	goproxy.MitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: goproxy.TLSConfigFromCA(&goproxyCa)}
	goproxy.HTTPMitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectHTTPMitm, TLSConfig: goproxy.TLSConfigFromCA(&goproxyCa)}
	goproxy.RejectConnect = &goproxy.ConnectAction{Action: goproxy.ConnectReject, TLSConfig: goproxy.TLSConfigFromCA(&goproxyCa)}
	return nil
}

func verifyCerts(dnsName string, peerCerts []*x509.Certificate) (bool, error) {
	dnsNamePatched := strings.Split(dnsName, ":")[0]

	opts := x509.VerifyOptions{
		Roots:         nil,
		DNSName:       dnsNamePatched,
		Intermediates: x509.NewCertPool(),
		CurrentTime:   time.Now(),
	}

	for i, cert := range peerCerts {
		if i == 0 {
			continue
		}

		opts.Intermediates.AddCert(cert)
	}

	var err error
	_, err = peerCerts[0].Verify(opts)
	if err != nil {
		log.Printf("Verify certs error %v", err)
		return false, err
	}

	return true, nil
}
