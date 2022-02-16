package tun2socks

import (
	"net"

	"github.com/dkwiebe/gotun2socks/internal/packet"
)

type ipPacket struct {
	ip     *packet.Ip
	mtuBuf []byte
	wire   []byte
}

var (
	frags = make(map[uint16]*ipPacket)
)

func procFragment(ip *packet.Ip, raw []byte) (bool, *packet.Ip, []byte) {
	if ip.Version == 6 { //skip for v6 yet
		return true, ip, ip.Payload
	}

	exist, ok := frags[ip.V4.Id]
	if !ok {
		if ip.V4.Flags&0x1 == 0 {
			return false, nil, nil
		}
		// first
		dup := make([]byte, len(raw))
		copy(dup, raw)
		clone := &packet.Ip{}
		packet.ParseIp(dup, clone)
		frags[ip.V4.Id] = &ipPacket{
			ip:   clone,
			wire: dup,
		}
		return false, clone, dup
	} else {
		exist.wire = append(exist.wire, ip.Payload...)
		packet.ParseIp(exist.wire, exist.ip)

		last := false
		if ip.V4.Flags&0x1 == 0 {
			last = true
		}

		return last, exist.ip, exist.wire
	}
}

func genFragments(first *packet.Ip, offset uint16, data []byte) []*ipPacket {
	var ret []*ipPacket

	for {
		var frag *packet.Ip
		if first.Version == 4 {
			frag = packet.NewIP4()
			frag.V4.Id = first.V4.Id
			frag.V4.TTL = first.V4.TTL
			frag.V4.Protocol = first.V4.Protocol
			frag.V4.FragOffset = offset
		} else {
			frag = packet.NewIP6()
		}

		frag.Src = make(net.IP, len(first.Src))
		copy(frag.Src, first.Src)
		frag.Dst = make(net.IP, len(first.Dst))
		copy(frag.Dst, first.Dst)

		if len(data) <= MTU-20 {
			frag.Payload = data
		} else {
			if frag.Version == 4 {
				frag.V4.Flags = 1
			}
			offset += (MTU - 20) / 8
			frag.Payload = data[:MTU-20]
			data = data[MTU-20:]
		}

		pkt := &ipPacket{ip: frag}
		pkt.mtuBuf = newBuffer()

		payloadL := len(frag.Payload)
		payloadStart := MTU - payloadL
		if payloadL != 0 {
			copy(pkt.mtuBuf[payloadStart:], frag.Payload)
		}
		ipHL := frag.HeaderLength()
		ipStart := payloadStart - ipHL
		frag.Serialize(pkt.mtuBuf[ipStart:payloadStart], payloadL)
		pkt.wire = pkt.mtuBuf[ipStart:]
		ret = append(ret, pkt)

		if frag.Version == 4 {
			if frag.V4.Flags == 0 {
				return ret
			}
		} else {
			return ret
		}
	}
}

func releaseIPPacket(pkt *ipPacket) {
	packet.ReleaseIP(pkt.ip)
	if pkt.mtuBuf != nil {
		releaseBuffer(pkt.mtuBuf)
	}
	pkt.mtuBuf = nil
	pkt.wire = nil
}
