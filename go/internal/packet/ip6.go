package packet

import (
	"encoding/binary"
	"fmt"
	"sync"
)

type IPv6 struct {
	TrafficClass uint8
	FlowLabel    uint32
	PayloadLen   uint16
	NextHeader   IPProtocol
	HopLimit     uint8
}

var (
	ipv6Pool *sync.Pool = &sync.Pool{
		New: func() interface{} {
			return &IPv6{}
		},
	}
	HeaderLen = 40 // header length
)

func releaseIPv6(ip6 *IPv6) {
	ipv6Pool.Put(ip6)
}

func newIPv6() *IPv6 {
	var zero IPv6
	ip6 := ipv6Pool.Get().(*IPv6)
	*ip6 = zero
	return ip6
}

func parseIPv6(pkt []byte, ip *Ip) error {
	if len(pkt) < HeaderLen {
		return fmt.Errorf("incorrect buffer size v6: %d buffer given, %d needed", len(pkt), HeaderLen)
	}

	ip.V6.TrafficClass = uint8((binary.BigEndian.Uint16(pkt[0:2]) >> 4) & 0x00FF)
	ip.V6.FlowLabel = binary.BigEndian.Uint32(pkt[0:4]) & 0x000FFFFF
	ip.V6.PayloadLen = binary.BigEndian.Uint16(pkt[4:6])
	ip.V6.NextHeader = IPProtocol(pkt[6])
	ip.V6.HopLimit = pkt[7]

	ip.Src = pkt[8:24]
	ip.Dst = pkt[24:40]

	ip.Payload = pkt[40:]

	return nil
}

func (ip *IPv6) pseudoHeader(buf []byte, proto IPProtocol, dataLen int, genericIp *Ip) error {
	if len(buf) != HeaderLen {
		return fmt.Errorf("incorrect buffer size: %d buffer given, %d needed", len(buf), HeaderLen)
	}
	copy(buf[8:24], genericIp.Src)
	copy(buf[24:40], genericIp.Dst)
	buf[6] = byte(proto)
	buf[7] = 0
	binary.BigEndian.PutUint16(buf[4:], uint16(dataLen))
	return nil
}

func (ip *IPv6) headerLen() int {
	return HeaderLen
}

func (ip *IPv6) serialize(hdr []byte, dataLen int, genericIp *Ip) error {
	if len(hdr) != HeaderLen {
		return fmt.Errorf("incorrect buffer size: %d buffer given, %d needed", len(hdr), HeaderLen)
	}

	hdr[0] = (genericIp.Version << 4) | (ip.TrafficClass >> 4)
	hdr[1] = (ip.TrafficClass << 4) | uint8(ip.FlowLabel>>16)
	binary.BigEndian.PutUint16(hdr[2:], uint16(ip.FlowLabel))
	binary.BigEndian.PutUint16(hdr[4:], ip.PayloadLen)
	hdr[6] = byte(ip.NextHeader)
	hdr[7] = byte(ip.HopLimit)

	copy(hdr[8:], genericIp.Src)
	copy(hdr[24:], genericIp.Dst)
	return nil
}
