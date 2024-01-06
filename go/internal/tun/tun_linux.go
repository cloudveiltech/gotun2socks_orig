package tun

import (
	"io"
	"net"
	"os"
)

const (
	IFF_TUN   = 0x0001
	IFF_TAP   = 0x0002
	IFF_NO_PI = 0x1000
)

type ifReq struct {
	Name  [0x10]byte
	Flags uint16
	pad   [0x28 - 0x10 - 2]byte
}

func NewTunDev(fd uintptr, name string, addr string, gw string) io.ReadWriteCloser {
	return &tunDev{
		f:      os.NewFile(fd, name),
		addr:   addr,
		addrIP: net.ParseIP(addr).To4(),
		gw:     gw,
		gwIP:   net.ParseIP(gw).To4(),
	}
}

type tunDev struct {
	name   string
	addr   string
	addrIP net.IP
	gw     string
	gwIP   net.IP
	marker []byte
	f      *os.File
}

func (dev *tunDev) Read(data []byte) (int, error) {
	if dev.f == nil {
		return 0, nil
	}
	n, e := dev.f.Read(data)

	return n, e
}

func (dev *tunDev) Write(data []byte) (int, error) {
	if dev.f == nil {
		return 0, nil
	}
	return dev.f.Write(data)
}

func (dev *tunDev) Close() error {
	//	dev.f.Close()
	dev.f = nil
	return nil
}
