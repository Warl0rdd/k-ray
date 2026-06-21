package internal

import (
	"encoding/binary"
	"net"
)

func IntToIP(ipNum uint32) net.IP {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, ipNum)
	return ip
}

func Ntohs(port uint16) uint16 {
	return (port << 8) | (port >> 8)
}

func CommToString(comm [16]int8) string {
	b := make([]byte, 0, 16)
	for _, c := range comm {
		if c == 0 {
			break
		}
		b = append(b, byte(c))
	}
	return string(b)
}
