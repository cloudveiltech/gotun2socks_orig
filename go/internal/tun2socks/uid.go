package tun2socks

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"strconv"
	"strings"
)

func getTcpData(isV6 bool) []string {
	fileName := "/proc/net/tcp"
	if isV6 {
		fileName = "/proc/net/tcp6"
	}

	data, err := ioutil.ReadFile(fileName)
	if err != nil {
		log.Println(err)
		return nil
	}
	lines := strings.Split(string(data), "\n")

	// Return lines without Header line and blank line on the end
	return lines[1 : len(lines)-1]
}

func hexToDec(h string) uint16 {
	// convert hexadecimal to decimal.
	d, err := strconv.ParseInt(h, 16, 32)
	if err != nil {
		log.Println(err)
		return 0
	}

	return uint16(d)
}

func convertIp(ip string) string {
	// Convert the ip to decimal. Have to rearrange the ip because the
	// default value is in little Endian order.

	var out string

	if len(ip) > 8 { //ipv6
		i := []string{ip[30:32],
			ip[28:30],
			ip[26:28],
			ip[24:26],
			ip[22:24],
			ip[20:22],
			ip[18:20],
			ip[16:18],
			ip[14:16],
			ip[12:14],
			ip[10:12],
			ip[8:10],
			ip[6:8],
			ip[4:6],
			ip[2:4],
			ip[0:2]}
		out = strings.ToLower(fmt.Sprintf("%v%v:%v%v:%v%v:%v%v:%v%v:%v%v:%v%v:%v%v",
			i[12], i[13], i[14], i[15],
			i[8], i[9], i[10], i[11],
			i[4], i[5], i[6], i[7],
			i[0], i[1], i[2], i[3]))

	} else if len(ip) > 7 {
		i := []uint16{hexToDec(ip[6:8]),
			hexToDec(ip[4:6]),
			hexToDec(ip[2:4]),
			hexToDec(ip[0:2])}

		out = fmt.Sprintf("%v.%v.%v.%v", i[0], i[1], i[2], i[3])
	}
	return out
}

func expandIPv6(ip string) string {
	parsedIp := net.ParseIP(ip)
	dst := make([]byte, hex.EncodedLen(len(parsedIp)))
	_ = hex.Encode(dst, parsedIp)
	return string(dst[0:4]) + ":" +
		string(dst[4:8]) + ":" +
		string(dst[8:12]) + ":" +
		string(dst[12:16]) + ":" +
		string(dst[16:20]) + ":" +
		string(dst[20:24]) + ":" +
		string(dst[24:28]) + ":" +
		string(dst[28:])
}

func removeEmpty(array []string) []string {
	// remove empty data from line
	var newArray []string
	for _, i := range array {
		if i != "" {
			newArray = append(newArray, i)
		}
	}
	return newArray
}

func (t2s *Tun2Socks) FindAppUid(sourceIp string, sourcePort uint16, destIp string, destPort uint16) int {
	if t2s.uidCallback != nil {
		return t2s.uidCallback.GetUid(sourceIp, sourcePort, destIp, destPort)
	}

	if len(destIp) == 0 || len(sourceIp) == 0 {
		return -1
	}

	isIpV6 := strings.Count(destIp, ":") > 1
	lines := getTcpData(isIpV6)
	if isIpV6 {
		sourceIp = strings.ToLower(expandIPv6(sourceIp))
		destIp = strings.ToLower(expandIPv6(destIp))
	}
	if lines == nil {
		log.Printf("UID for TCP request from %s:%d to %s:%d is -1 No tcp data ", sourceIp, sourcePort, destIp, destPort)
		return -1
	}
	for _, line := range lines {
		// local ip and port
		lineArray := removeEmpty(strings.Split(strings.TrimSpace(line), " "))

		sIpPort := strings.Split(lineArray[1], ":")
		sIp := convertIp(sIpPort[0])
		sPort := hexToDec(sIpPort[1])

		// foreign ip and port
		destIpPort := strings.Split(lineArray[2], ":")
		dIp := convertIp(destIpPort[0])
		dPort := hexToDec(destIpPort[1])

		log.Printf("UID for TCP ipV6 dIp %s sIp %s", dIp, sIp)
		if sPort == sourcePort && dPort == destPort {
			if sIp == sourceIp && destIp == dIp {
				uid, err := strconv.Atoi(lineArray[7])
				if err == nil {
					log.Printf("UID for TCP from %s:%d to %s:%d is %d", sourceIp, sourcePort, destIp, destPort, uid)
					return uid
				}
			}
		}
	}

	log.Printf("UID for TCP request from %s:%d to %s:%d is -1", sourceIp, sourcePort, destIp, destPort)
	return -1
}
