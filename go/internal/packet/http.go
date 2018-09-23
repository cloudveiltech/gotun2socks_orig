package packet

import (
	"fmt"
	"strings"
)

func GetHostnamePlainHttp(data []byte) (string, error) {
	if len(data) < 7 {
		return "", fmt.Errorf("data is too short")
	}

	//looking for host header
	var start = -1
	var end = -1
	hostString := "Host: "
	start = findStringInData(data, hostString, 0)
	if start < 0 {
		return "", fmt.Errorf("Host not found")
	}
	end = findStringInData(data, "\r\n", start+len(hostString))

	return strings.TrimSpace(string(data[start+len(hostString) : end])), nil
}

func (tcp *TCP) PatchHostForPlainHttp(proxyAuthHeader string) []byte {
	if tcp.DstPort != 80 { //only http
		return tcp.Payload
	}
	if len(tcp.Hostname) == 0 {
		return tcp.Payload
	}

	//GET POST PUT DELETE HEAD OPTIONS PATCH
	var word string
	var wordIndex int

	if wordIndex := findStringInData(tcp.Payload, "GET ", 0); wordIndex >= 0 {
		word = "GET "
	} else if wordIndex := findStringInData(tcp.Payload, "POST ", 0); wordIndex >= 0 {
		word = "POST "
	} else if wordIndex := findStringInData(tcp.Payload, "PUT ", 0); wordIndex >= 0 {
		word = "PUT "
	} else if wordIndex := findStringInData(tcp.Payload, "DELETE ", 0); wordIndex >= 0 {
		word = "DELETE "
	} else if wordIndex := findStringInData(tcp.Payload, "HEAD ", 0); wordIndex >= 0 {
		word = "HEAD "
	} else if wordIndex := findStringInData(tcp.Payload, "OPTIONS ", 0); wordIndex >= 0 {
		word = "OPTIONS "
	} else if wordIndex := findStringInData(tcp.Payload, "PATCH ", 0); wordIndex >= 0 {
		word = "PATCH "
	}

	if wordIndex < 0 {
		return tcp.Payload
	}

	var wordLen = len(word)
	var index1 = wordIndex + wordLen
	if tcp.Payload[index1] == 'h' &&
		tcp.Payload[index1+1] == 't' &&
		tcp.Payload[index1+2] == 't' &&
		tcp.Payload[index1+3] == 'p' &&
		tcp.Payload[index1+4] == ':' {
		//already patched
		return tcp.Payload
	}

	httpHost := []byte("http://" + tcp.Hostname)
	httpHostLen := len(httpHost)

	authHeader := []byte(fmt.Sprintf("Proxy-Authorization: Basic %s\r\n", proxyAuthHeader))
	authHeaderLength := len(authHeader)

	newPayloadLength := len(tcp.Payload) + httpHostLen + authHeaderLength
	newPayLoad := make([]byte, newPayloadLength, newPayloadLength)

	headerEndIndex := findStringInData(tcp.Payload, "\r\n", index1) + 2

	//host
	copy(newPayLoad[:index1], tcp.Payload[:index1])
	copy(newPayLoad[index1:index1+httpHostLen], httpHost[:])
	copy(newPayLoad[index1+httpHostLen:headerEndIndex+httpHostLen], tcp.Payload[index1:headerEndIndex])
	//auth
	copy(newPayLoad[headerEndIndex+httpHostLen:headerEndIndex+httpHostLen+authHeaderLength], authHeader[:])
	copy(newPayLoad[headerEndIndex+httpHostLen+authHeaderLength:], tcp.Payload[headerEndIndex:])

	return newPayLoad
}

func findStringInData(data []byte, stringToFind string, startIndex int) int {
	stringLen := len(stringToFind)
	dataLen := len(data)

	for i := startIndex; i < dataLen-stringLen; i++ {
		found := true
		for j := 0; j < stringLen; j++ {
			if data[i+j] != stringToFind[j] {
				found = false
				break
			}
		}
		if found {
			return i
		}
	}
	return -1
}
