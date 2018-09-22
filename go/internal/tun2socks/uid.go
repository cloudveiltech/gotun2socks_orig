package tun2socks

import (
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
)

func getTcpData() []string {
	fileName := "/proc/net/tcp"

	data, err := ioutil.ReadFile(fileName)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	lines := strings.Split(string(data), "\n")

	// Return lines without Header line and blank line on the end
	return lines[1 : len(lines)-1]
}

func hexToDec(h string) uint16 {
	// convert hexadecimal to decimal.
	d, err := strconv.ParseInt(h, 16, 32)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	return uint16(d)
}

func convertIp(ip string) string {
	// Convert the ipv4 to decimal. Have to rearrange the ip because the
	// default value is in little Endian order.

	var out string

	// Check ip size if greater than 8 is a ipv6 type
	if len(ip) > 8 {
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
		out = fmt.Sprintf("%v%v:%v%v:%v%v:%v%v:%v%v:%v%v:%v%v:%v%v",
			i[14], i[15], i[13], i[12],
			i[10], i[11], i[8], i[9],
			i[6], i[7], i[4], i[5],
			i[2], i[3], i[0], i[1])

	} else {
		i := []uint16{hexToDec(ip[6:8]),
			hexToDec(ip[4:6]),
			hexToDec(ip[2:4]),
			hexToDec(ip[0:2])}

		out = fmt.Sprintf("%v.%v.%v.%v", i[0], i[1], i[2], i[3])
	}
	return out
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

func FindAppUid(sourceIp string, sourcePort uint16, destIp string, destPort uint16) int {
	lines := getTcpData()

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

		if sPort == sourcePort && dPort == destPort {
			if sIp == sourceIp && destIp == dIp {
				uid, err := strconv.Atoi(lineArray[7])
				if err == nil {
					return uid
				}
			}
		}
	}

	return -1
}
