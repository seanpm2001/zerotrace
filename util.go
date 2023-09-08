package zerotrace

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	errInvalidIPHeader = errors.New("invalid IP header")
)

// extractRemoteIP extracts the remote IP address from the given net.Conn.
func extractRemoteIP(c net.Conn) (net.IP, error) {
	s := c.RemoteAddr().String()
	host, _, err := net.SplitHostPort(s)
	if err != nil {
		return nil, err
	}
	return net.ParseIP(host), nil
}

func extractTTL(ipPkt []byte) (uint8, error) {
	// At the very least, we expect an IP header.
	if len(ipPkt) < 20 {
		return 0, errInvalidIPHeader
	}

	// Try decoding the packet, to see if the header is well-formed.
	ip := layers.IPv4{}
	if err := ip.DecodeFromBytes(ipPkt, gopacket.NilDecodeFeedback); err != nil {
		return 0, err
	}

	return uint8(ipPkt[8]), nil
}

// extractIPID parses the given IP header, extracts its IP ID, and returns it.
func extractIPID(ipPkt []byte) (uint16, error) {
	// At the very least, we expect an IP header.
	if len(ipPkt) < 20 {
		return 0, errInvalidIPHeader
	}

	// Try decoding the packet, to see if the header is well-formed.
	ip := layers.IPv4{}
	if err := ip.DecodeFromBytes(ipPkt, gopacket.NilDecodeFeedback); err != nil {
		return 0, err
	}

	return uint16(ipPkt[4])<<8 | uint16(ipPkt[5]), nil
}

func openPcap(
	iface string,
	snapLen int32,
	port int,
	timeout time.Duration,
) (*pcap.Handle, error) {
	// Set up our pcap handle.
	promiscuous := true
	pcapHdl, err := pcap.OpenLive(
		iface,
		snapLen,
		promiscuous,
		timeout,
	)
	if err != nil {
		return nil, err
	}
	filter := fmt.Sprintf("icmp or (port %d and tcp[13] = 18)", port)
	if err = pcapHdl.SetBPFFilter(filter); err != nil {
		return nil, err
	}
	return pcapHdl, nil
}
