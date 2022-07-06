package ebpfmap

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
)

// InetNtoa convert a inet address to human readable string of the address
func InetNtoa(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(ip), byte(ip>>8), byte(ip>>16),
		byte(ip>>24))
}

// InetAton convert a human readable ipv4 address to inet address
func InetAton(addr string) uint32 {
	ip := net.ParseIP(addr)
	if ip == nil {
		return 0
	}
	ip = ip.To4()
	return binary.LittleEndian.Uint32(ip)
}

// InetAton convert a human readable port address to net port address
func IportAton(port string) uint16 {
	portInt, err := strconv.Atoi(port)
	if err != nil {
		return 0
	}

	var byteportInt []byte
	byteportInt[1] = uint8(portInt)
	byteportInt[0] = uint8(portInt >> 8)

	return binary.LittleEndian.Uint16(byteportInt)
}

// MacCopy copy a HardwareAddr to [6]byte array
func MacCopy(dest [6]byte, source net.HardwareAddr) {
	for i := range dest {
		dest[i] = source[i]
	}
	return
}

// MacString convert [6]uint8 to a string of mac address
func MacString(src [6]uint8) string {
	var mac net.HardwareAddr
	for _, s := range src {
		mac = append(mac, s)
	}
	return mac.String()
}
