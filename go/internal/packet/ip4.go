package packet

import (
	"encoding/binary"
	"fmt"
	"sync"
)

type IPv4Option struct {
	OptionType   uint8
	OptionLength uint8
	OptionData   []byte
}

type IPv4 struct {
	IHL        uint8
	TOS        uint8
	Length     uint16
	Id         uint16
	Flags      uint8
	FragOffset uint16
	TTL        uint8
	Protocol   IPProtocol
	Checksum   uint16
	Options    []IPv4Option

	headerLength int
}

var (
	ipv4Pool *sync.Pool = &sync.Pool{
		New: func() interface{} {
			return &IPv4{}
		},
	}
)

func releaseIPv4(ip4 *IPv4) {
	// clear internal slice references
	ip4.Options = nil

	ipv4Pool.Put(ip4)
}

func newIPv4() *IPv4 {
	var zero IPv4
	ip4 := ipv4Pool.Get().(*IPv4)
	*ip4 = zero
	return ip4
}

func parseIPv4(pkt []byte, ip *Ip) error {
	flagsfrags := binary.BigEndian.Uint16(pkt[6:8])

	ip.Version = uint8(pkt[0]) >> 4
	ip.V4.IHL = uint8(pkt[0]) & 0x0F
	ip.V4.TOS = pkt[1]
	ip.V4.Length = binary.BigEndian.Uint16(pkt[2:4])
	ip.V4.Id = binary.BigEndian.Uint16(pkt[4:6])
	ip.V4.Flags = uint8(flagsfrags >> 13)
	ip.V4.FragOffset = flagsfrags & 0x1FFF
	ip.V4.TTL = pkt[8]
	ip.V4.Protocol = IPProtocol(pkt[9])
	ip.V4.Checksum = binary.BigEndian.Uint16(pkt[10:12])
	ip.Src = pkt[12:16]
	ip.Dst = pkt[16:20]

	if ip.V4.Length < 20 {
		return fmt.Errorf("Invalid (too small) IP length (%d < 20)", ip.V4.Length)
	}
	if ip.V4.IHL < 5 {
		return fmt.Errorf("Invalid (too small) IP header length (%d < 5)", ip.V4.IHL)
	}
	if int(ip.V4.IHL*4) > int(ip.V4.Length) {
		return fmt.Errorf("Invalid IP header length > IP length (%d > %d)", ip.V4.IHL, ip.V4.Length)
	}
	if int(ip.V4.IHL)*4 > len(pkt) {
		return fmt.Errorf("Not all IP header bytes available")
	}
	ip.Payload = pkt[ip.V4.IHL*4:]
	rest := pkt[20 : ip.V4.IHL*4]
	// Pull out IP options
	for len(rest) > 0 {
		if ip.V4.Options == nil {
			// Pre-allocate to avoid growing the slice too much.
			ip.V4.Options = make([]IPv4Option, 0, 4)
		}
		opt := IPv4Option{OptionType: rest[0]}
		switch opt.OptionType {
		case 0: // End of options
			opt.OptionLength = 1
			ip.V4.Options = append(ip.V4.Options, opt)
			ip.Padding = rest[1:]
			break
		case 1: // 1 byte padding
			opt.OptionLength = 1
		default:
			opt.OptionLength = rest[1]
			opt.OptionData = rest[2:opt.OptionLength]
		}
		if len(rest) >= int(opt.OptionLength) {
			rest = rest[opt.OptionLength:]
		} else {
			return fmt.Errorf("IP option length exceeds remaining IP header size, option type %v length %v", opt.OptionType, opt.OptionLength)
		}
		ip.V4.Options = append(ip.V4.Options, opt)
	}
	return nil
}

func (ip *IPv4) pseudoHeader(buf []byte, proto IPProtocol, dataLen int, genericIp *Ip) error {
	if len(buf) != IP4_PSEUDO_LENGTH {
		return fmt.Errorf("incorrect buffer size: %d buffer given, %d needed", len(buf), IP4_PSEUDO_LENGTH)
	}
	copy(buf[0:4], genericIp.Src)
	copy(buf[4:8], genericIp.Dst)
	buf[8] = 0
	buf[9] = byte(proto)
	binary.BigEndian.PutUint16(buf[10:], uint16(dataLen))
	return nil
}

func (ip *IPv4) headerLen() int {
	if ip.headerLength == 0 {
		optionLength := uint8(0)
		for _, opt := range ip.Options {
			switch opt.OptionType {
			case 0:
				// this is the end of option lists
				optionLength++
			case 1:
				// this is the padding
				optionLength++
			default:
				optionLength += opt.OptionLength

			}
		}
		// make sure the options are aligned to 32 bit boundary
		if (optionLength % 4) != 0 {
			optionLength += 4 - (optionLength % 4)
		}
		ip.IHL = 5 + (optionLength / 4)
		ip.headerLength = int(optionLength) + 20
	}
	return ip.headerLength
}

func (ip *IPv4) flagsfrags() (ff uint16) {
	ff |= uint16(ip.Flags) << 13
	ff |= ip.FragOffset
	return
}

func (ip *IPv4) serialize(hdr []byte, dataLen int, genericIp *Ip) error {
	if len(hdr) != ip.headerLen() {
		return fmt.Errorf("incorrect buffer size: %d buffer given, %d needed", len(hdr), ip.headerLen())
	}
	hdr[0] = (genericIp.Version << 4) | ip.IHL
	hdr[1] = ip.TOS
	ip.Length = uint16(ip.headerLength + dataLen)
	binary.BigEndian.PutUint16(hdr[2:], ip.Length)
	binary.BigEndian.PutUint16(hdr[4:], ip.Id)
	binary.BigEndian.PutUint16(hdr[6:], ip.flagsfrags())
	hdr[8] = ip.TTL
	hdr[9] = byte(ip.Protocol)
	copy(hdr[12:16], genericIp.Src)
	copy(hdr[16:20], genericIp.Dst)

	curLocation := 20
	// Now, we will encode the options
	for _, opt := range ip.Options {
		switch opt.OptionType {
		case 0:
			// this is the end of option lists
			hdr[curLocation] = 0
			curLocation++
		case 1:
			// this is the padding
			hdr[curLocation] = 1
			curLocation++
		default:
			hdr[curLocation] = opt.OptionType
			hdr[curLocation+1] = opt.OptionLength

			// sanity checking to protect us from buffer overrun
			if len(opt.OptionData) > int(opt.OptionLength-2) {
				return fmt.Errorf("option length is smaller than length of option data")
			}
			copy(hdr[curLocation+2:curLocation+int(opt.OptionLength)], opt.OptionData)
			curLocation += int(opt.OptionLength)
		}
	}
	hdr[10] = 0
	hdr[11] = 0
	ip.Checksum = Checksum(hdr)
	binary.BigEndian.PutUint16(hdr[10:], ip.Checksum)
	return nil
}
