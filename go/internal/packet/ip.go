package packet

import (
	"net"
	"sync"
	"sync/atomic"
)

// IPProtocol is an enumeration of IP protocol values, and acts as a decoder
// for any type it supports.
type IPProtocol uint8

const (
	IPProtocolIPv6HopByHop    IPProtocol = 0
	IPProtocolICMPv4          IPProtocol = 1
	IPProtocolIGMP            IPProtocol = 2
	IPProtocolIp              IPProtocol = 4
	IPProtocolTCP             IPProtocol = 6
	IPProtocolUDP             IPProtocol = 17
	IPProtocolRUDP            IPProtocol = 27
	IPProtocolIPv6            IPProtocol = 41
	IPProtocolIPv6Routing     IPProtocol = 43
	IPProtocolIPv6Fragment    IPProtocol = 44
	IPProtocolGRE             IPProtocol = 47
	IPProtocolESP             IPProtocol = 50
	IPProtocolAH              IPProtocol = 51
	IPProtocolICMPv6          IPProtocol = 58
	IPProtocolNoNextHeader    IPProtocol = 59
	IPProtocolIPv6Destination IPProtocol = 60
	IPProtocolIPIP            IPProtocol = 94
	IPProtocolEtherIP         IPProtocol = 97
	IPProtocolSCTP            IPProtocol = 132
	IPProtocolUDPLite         IPProtocol = 136
	IPProtocolMPLSInIP        IPProtocol = 137

	IP_PSEUDO_LENGTH int = 12
)

type Ip struct {
	Version uint8  // protocol version
	Src     net.IP // source address
	Dst     net.IP // destination address
	Padding []byte
	Payload []byte
	V4      *IPv4
	V6      *IPv6
}

var (
	globalIPID uint32
)

var (
	ipPool *sync.Pool = &sync.Pool{
		New: func() interface{} {
			return &Ip{}
		},
	}
)

func ReleaseIP(ip *Ip) {
	// clear internal slice references
	ip.Src = nil
	ip.Dst = nil
	ip.Padding = nil
	ip.Payload = nil

	if ip.Version == 4 {
		releaseIPv4(ip.V4)
	} else {
		releaseIPv6(ip.V6)
	}
	ipPool.Put(ip)
}

func NewIP() *Ip {
	var zero Ip
	ip := ipPool.Get().(*Ip)
	*ip = zero
	return ip
}

func NewIP4() *Ip {
	var zero Ip
	ip := ipPool.Get().(*Ip)
	*ip = zero
	ip.V4 = newIPv4()
	ip.Version = 4
	return ip
}

func NewIP6() *Ip {
	var zero Ip
	ip := ipPool.Get().(*Ip)
	*ip = zero
	ip.V6 = newIPv6()
	ip.Version = 6
	return ip
}

func IPID() uint16 {
	return uint16(atomic.AddUint32(&globalIPID, 1) & 0x0000ffff)
}

func ParseIp(pkt []byte, ip *Ip) error {
	ip.Version = uint8(pkt[0]) >> 4
	if ip.Version == 4 {
		ip.V4 = newIPv4()
		return parseIPv4(pkt, ip)
	} else {
		ip.V6 = newIPv6()
		return parseIPv6(pkt, ip)
	}
}

func (ip *Ip) PseudoHeader(buf []byte, proto IPProtocol, dataLen int) error {
	if ip.Version == 4 {
		return ip.V4.pseudoHeader(buf, proto, dataLen, ip)
	} else {
		return ip.V6.pseudoHeader(buf, proto, dataLen, ip)
	}
}

func (ip *Ip) HeaderLength() int {
	if ip.Version == 4 {
		return ip.V4.headerLen()
	} else {
		return ip.V6.headerLen()
	}
}

func (ip *Ip) Serialize(hdr []byte, dataLen int) error {
	if ip.Version == 4 {
		return ip.V4.serialize(hdr, dataLen, ip)
	} else {
		return ip.V6.serialize(hdr, dataLen, ip)
	}
}

func (ip *Ip) SetHopLimit(limit uint8) {
	if ip.Version == 4 {
		ip.V4.TTL = limit
	} else {
		ip.V6.HopLimit = limit
	}
}

func (ip *Ip) SetNextProto(proto IPProtocol) {
	if ip.Version == 4 {
		ip.V4.Protocol = proto
	} else {
		ip.V6.NextHeader = proto
	}
}

func (ip *Ip) GetNextProto() IPProtocol {
	if ip.Version == 4 {
		return ip.V4.Protocol
	} else {
		return ip.V6.NextHeader
	}
}
