package key

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"

	"github.com/pkg/errors"
)

// New generates a new AES key based in the following
//		the main network interface MAC address (6 bytes)
//		the user and group IDs (2 bytes each one)
//		the value of the fine-structure fundamental physics constant (22 bytes)
func New() ([]byte, error) {
	mac, macErr := getMacAddress()
	if macErr != nil {
		return nil, errors.Wrap(macErr, "can not retrieve main network interface mac address")
	}

	userID, groupID := os.Geteuid(), os.Getegid()
	fineStructureConstant := []byte{55, 46, 50, 57, 55, 32, 51, 53, 50, 32, 53, 54, 54, 52, 49, 55, 120, 49, 48, 45, 51}
	key := make([]byte, 32, 32)
	for i, elem := range mac {
		key[i] = elem
	}

	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, uint16(userID))
	key[6], key[7] = b[0], b[1]

	b = make([]byte, 2)
	binary.LittleEndian.PutUint16(b, uint16(groupID))
	key[8], key[9] = b[0], b[1]

	for i, b := range fineStructureConstant {
		key[10+i] = b
	}

	return key, nil
}

// retrieve the interface MAC address using some borrowed code from stdlib tests
func getMacAddress() (net.HardwareAddr, error) {
	device := routedInterface("ip", net.FlagUp|net.FlagBroadcast)
	if device == nil {
		return nil, fmt.Errorf("can not determine the network interface")
	}

	return device.HardwareAddr, nil
}

// borrowed from https://github.com/golang/net/blob/master/internal/nettest/interface.go

// RoutedInterface returns a network interface that can route IP
// traffic and satisfies flags. It returns nil when an appropriate
// network interface is not found. Network must be "ip", "ip4" or
// "ip6".
func routedInterface(network string, flags net.Flags) *net.Interface {
	switch network {
	case "ip", "ip4", "ip6":
	default:
		return nil
	}
	ift, err := net.Interfaces()
	if err != nil {
		return nil
	}
	for _, ifi := range ift {
		if ifi.Flags&flags != flags {
			continue
		}
		if _, ok := hasRoutableIP(network, &ifi); !ok {
			continue
		}
		return &ifi
	}
	return nil
}

func hasRoutableIP(network string, ifi *net.Interface) (net.IP, bool) {
	ifat, err := ifi.Addrs()
	if err != nil {
		return nil, false
	}
	for _, ifa := range ifat {
		switch ifa := ifa.(type) {
		case *net.IPAddr:
			if ip := routableIP(network, ifa.IP); ip != nil {
				return ip, true
			}
		case *net.IPNet:
			if ip := routableIP(network, ifa.IP); ip != nil {
				return ip, true
			}
		}
	}
	return nil, false
}

func routableIP(network string, ip net.IP) net.IP {
	if !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsGlobalUnicast() {
		return nil
	}
	switch network {
	case "ip4":
		if ip := ip.To4(); ip != nil {
			return ip
		}
	case "ip6":
		if ip.IsLoopback() { // addressing scope of the loopback address depends on each implementation
			return nil
		}
		if ip := ip.To16(); ip != nil && ip.To4() == nil {
			return ip
		}
	default:
		if ip := ip.To4(); ip != nil {
			return ip
		}
		if ip := ip.To16(); ip != nil {
			return ip
		}
	}
	return nil
}
