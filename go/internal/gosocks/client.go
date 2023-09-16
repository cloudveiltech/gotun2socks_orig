package gosocks

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"time"
)

type ClientAuthenticator interface {
	ClientAuthenticate(conn *SocksConn) error
}

type SocksDialer struct {
	Timeout time.Duration
	Auth    ClientAuthenticator
}

type AnonymousClientAuthenticator struct{}

type UserNamePasswordClientAuthenticator struct {
	UserName string
	Password string
}

type HttpAuthenticator struct {
}

func (a *HttpAuthenticator) ClientAuthenticate(conn *SocksConn) (err error) {
	conn.SetWriteDeadline(time.Now().Add(conn.Timeout))
	return
}

func (a *AnonymousClientAuthenticator) ClientAuthenticate(conn *SocksConn) (err error) {
	conn.SetWriteDeadline(time.Now().Add(conn.Timeout))
	var req [3]byte
	req[0] = SocksVersion
	req[1] = 1
	req[2] = SocksNoAuthentication
	_, err = conn.Write(req[:])
	if err != nil {
		return
	}

	conn.SetReadDeadline(time.Now().Add(conn.Timeout))
	var resp [2]byte
	r := bufio.NewReader(conn)
	_, err = io.ReadFull(r, resp[:2])
	if err != nil {
		return
	}
	if resp[0] != SocksVersion || resp[1] != SocksNoAuthentication {
		err = fmt.Errorf("Fail to pass anonymous authentication: (0x%02x, 0x%02x)", resp[0], resp[1])
		return
	}
	return
}

func (a *UserNamePasswordClientAuthenticator) ClientAuthenticate(conn *SocksConn) (err error) {
	conn.SetWriteDeadline(time.Now().Add(conn.Timeout))
	var req [512]byte
	var resp [2]byte

	//send hello
	req[0] = SocksVersion
	req[1] = 1
	req[2] = SocksAuthMethodUsernamePassword
	_, err = conn.Write(req[:3])
	if err != nil {
		return
	}

	conn.SetReadDeadline(time.Now().Add(conn.Timeout))
	r := bufio.NewReader(conn)
	_, err = io.ReadFull(r, resp[:2])
	if err != nil {
		return
	}
	if resp[0] != SocksVersion || resp[1] != SocksAuthMethodUsernamePassword {
		err = fmt.Errorf("Fail to pass anonymous authentication: (0x%02x, 0x%02x)", resp[0], resp[1])
		return
	}

	//send auth
	req[0] = 1
	req[1] = byte(len(a.UserName))
	copy(req[2:len(a.UserName)+2], a.UserName)
	req[2+len(a.UserName)] = byte(len(a.Password))
	copy(req[3+len(a.UserName):], a.Password)

	_, err = conn.Write(req[:3+len(a.UserName)+len(a.Password)])
	if err != nil {
		return
	}

	conn.SetReadDeadline(time.Now().Add(conn.Timeout))
	r = bufio.NewReader(conn)
	_, err = io.ReadFull(r, resp[:2])
	if err != nil {
		return
	}
	if resp[0] != 1 || resp[1] != SocksSucceeded {
		err = fmt.Errorf("Fail to pass username authentication: (0x%02x, 0x%02x)", resp[0], resp[1])
		return
	}
	return
}

func (d *SocksDialer) Dial(address string) (conn *SocksConn, err error) {
	c, err := net.DialTimeout("tcp", address, d.Timeout)
	if err != nil {
		return
	}
	cfg := &tls.Config{
		MinVersion:               tls.VersionTLS12,
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
		InsecureSkipVerify:       true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
	}
	tlsConn := tls.Client(c, cfg)

	err = tlsConn.Handshake()
	if err != nil {
		return nil, err
	}

	conn = &SocksConn{tlsConn, d.Timeout}
	err = d.Auth.ClientAuthenticate(conn)
	if err != nil {
		conn.Close()
		return
	}
	return
}

func ClientAuthAnonymous(conn *SocksConn) (err error) {
	conn.SetWriteDeadline(time.Now().Add(conn.Timeout))
	var req [3]byte
	req[0] = SocksVersion
	req[1] = 1
	req[2] = SocksNoAuthentication
	_, err = conn.Write(req[:])
	if err != nil {
		return
	}

	conn.SetReadDeadline(time.Now().Add(conn.Timeout))
	var resp [2]byte
	r := bufio.NewReader(conn)
	_, err = io.ReadFull(r, resp[:2])
	if err != nil {
		return
	}
	if resp[0] != SocksVersion || resp[1] != SocksNoAuthentication {
		err = fmt.Errorf("Fail to pass anonymous authentication: (0x%02x, 0x%02x)", resp[0], resp[1])
		return
	}
	return
}

func ClientRequest(conn *SocksConn, req *SocksRequest) (reply *SocksReply, err error) {
	conn.SetWriteDeadline(time.Now().Add(conn.Timeout))
	_, err = WriteSocksRequest(conn, req)
	if err != nil {
		return
	}
	conn.SetReadDeadline(time.Now().Add(conn.Timeout))
	reply, err = ReadSocksReply(conn)
	return
}
