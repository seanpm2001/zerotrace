package zerotrace

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/net/ipv4"
)

var (
	l = log.New(os.Stderr, "0trace: ", log.Ldate|log.Ltime|log.LUTC|log.Lshortfile)
)

type seqNums struct {
	theirs uint32
	ours   uint32
}

type fourTuple struct {
	theirs net.Addr
	ours   net.Addr
}

type receiver chan *respPkt

// Config holds configuration options for the ZeroTrace object.
type Config struct {
	// Port contains the server's port.
	Port int
	// NumProbes determines the number of probes we're sending for a given TTL.
	NumProbes int
	// TTLStart determines the TTL at which we start sending trace packets.
	TTLStart int
	// TTLEnd determines the TTL at which we stop sending trace packets.
	TTLEnd int
	// SnapLen determines the number of bytes per frame that we want libpcap to
	// capture.  500 bytes is enough for ICMP TTL exceeded packets.
	SnapLen int32
	// PktBufTimeout determines the time we're willing to wait for packets to
	// accumulate in our receive buffer.
	PktBufTimeout time.Duration
	// Interface determines the network interface that we're going to use to
	// listen for incoming network packets.
	Interface string
}

// NewDefaultConfig returns a configuration object containing the following
// defaults.  *Note* that you probably need to change the networking interface.
//
//	NumProbes:     3
//	TTLStart:      5
//	TTLEnd:        32
//	SnapLen:       500
//	Port:          443
//	PktBufTimeout: time.Millisecond * 10
//	Interface:     "eth0"
func NewDefaultConfig() *Config {
	return &Config{
		NumProbes:     3,
		TTLStart:      5,
		TTLEnd:        32,
		SnapLen:       500,
		Port:          443,
		PktBufTimeout: time.Millisecond * 10,
		Interface:     "eth0",
	}
}

// ZeroTrace implements the 0trace traceroute technique:
// https://seclists.org/fulldisclosure/2007/Jan/145
type ZeroTrace struct {
	sync.RWMutex
	quit               chan struct{}
	incoming, outgoing chan receiver
	seqsPerTuple       map[*fourTuple]*seqNums // TODO: delete old ones
	cfg                *Config
}

func newFourTuple(conn net.Conn) *fourTuple {
	return &fourTuple{
		ours:   conn.LocalAddr(),
		theirs: conn.RemoteAddr(),
	}
}

func (z *ZeroTrace) getSeqNums(t *fourTuple) (*seqNums, error) {
	z.RLock()
	defer z.RUnlock()

	s, exists := z.seqsPerTuple[t]
	if !exists {
		return nil, errors.New("no sequence numbers for given four-tuple")
	}
	return s, nil
}

func (z *ZeroTrace) setSeqNums(t *fourTuple, s *seqNums) {
	z.Lock()
	defer z.Unlock()

	z.seqsPerTuple[t] = s
}

func (z *ZeroTrace) deleteSeqNums(t *fourTuple) {
	z.Lock()
	defer z.Unlock()

	delete(z.seqsPerTuple, t)
}

// OpenZeroTrace instantiates and starts a new ZeroTrace object that's going to
// use the given configuration for its measurement.
func OpenZeroTrace(c *Config) *ZeroTrace {
	quit := make(chan struct{})
	zt := &ZeroTrace{
		cfg:          c,
		incoming:     make(chan receiver),
		outgoing:     make(chan receiver),
		seqsPerTuple: make(map[*fourTuple]*seqNums),
		quit:         quit,
	}
	go zt.listen(quit)
	return zt
}

// Close closes this instance's
func (z *ZeroTrace) Close() {
	close(z.quit)
}

// CalcRTT coordinates our 0trace traceroute and returns the RTT to the target
// or, if the target won't respond to us, the RTT of the hop that's closest.
// The given net.Conn represents an already-established TCP connection to the
// target.  Note that the TCP connection may be corrupted as part of the 0trace
// measurement.
func (z *ZeroTrace) CalcRTT(conn net.Conn) (time.Duration, error) {
	var (
		state     *trState
		ticker    = time.NewTicker(time.Second)
		quit      = make(chan struct{})
		respChan  = make(chan *respPkt)
		traceChan = make(chan *tracePkt)
	)
	defer close(quit)
	defer close(respChan)
	defer close(traceChan)

	remoteIP, err := extractRemoteIP(conn)
	if err != nil {
		return 0, err
	}
	state = newTrState(remoteIP)

	// Register for receiving a copy of newly-captured ICMP responses.
	z.incoming <- respChan
	defer func() { z.outgoing <- respChan }()

	// Spawn goroutine that sends trace packets.
	go z.sendTracePkts(traceChan, state.createIPID, conn)

loop:
	for {
		select {
		// We just sent a trace packet.
		case tracePkt := <-traceChan:
			state.addTracePkt(tracePkt)

		// We just received a packet in response to a trace packet.
		case respPkt := <-respChan:
			if err := state.addRespPkt(respPkt); err != nil {
				l.Printf("Error adding response packet: %v", err)
			}

		// Check if we're done with the traceroute.
		case <-ticker.C:
			state.summary()
			if state.isFinished() {
				break loop
			}
		}
	}

	return state.calcRTT(), nil
}

// sendTracePkts sends trace packets to our target.  Once a packet was sent,
// it's written to the given channel.  The given function is used to create an
// IP ID that is set in the trace packet's IP header.
func (z *ZeroTrace) sendTracePkts(c chan *tracePkt, createIPID func() uint16, conn net.Conn) {
	remoteIP, err := extractRemoteIP(conn)
	if err != nil {
		l.Printf("Error extracting remote IP address from connection: %v", err)
		return
	}

	tuple := newFourTuple(conn)
	log.Printf("Looking up four-tuple: %v", tuple)

	seqNums, err := z.getSeqNums(tuple)
	if err != nil {
		log.Printf("Error looking up sequence numbers for conn: %v", err)
		return
	}
	log.Printf("Sequence numbers: %v", seqNums)
	defer z.deleteSeqNums(tuple) // TODO: correct?

	for ttl := z.cfg.TTLStart; ttl <= z.cfg.TTLEnd; ttl++ {
		tempConn := conn.(*tls.Conn)
		tcpConn := tempConn.NetConn()
		ipConn := ipv4.NewConn(tcpConn)

		// Set our net.Conn's TTL for future outgoing packets.
		// We cannot parallelize this loop because the TTL is socket-dependent
		// and we only have a single socket to work with.
		if err := ipConn.SetTTL(ttl); err != nil {
			l.Printf("Error setting TTL: %v", err)
			return
		}

		for n := 0; n < z.cfg.NumProbes; n++ {
			ipID := createIPID()
			pkt, err := createPkt(conn, seqNums, ipID)
			if err != nil {
				l.Printf("Error creating packet: %v", err)
				return
			}

			if err := sendRawPkt(
				ipID,
				uint8(ttl),
				remoteIP,
				pkt,
			); err != nil {
				l.Printf("Error sending raw packet: %v", err)
			}

			c <- &tracePkt{
				ttl:  uint8(ttl),
				ipID: ipID,
				sent: time.Now().UTC(),
			}
		}
	}
}

// listen opens a pcap handle and begins listening for incoming ICMP packets.
// New traceroutes register themselves with this function's event loop to
// receive a copy of newly-captured ICMP packets.
func (z *ZeroTrace) listen(quit chan struct{}) {
	var (
		receivers = make(map[receiver]bool)
		stream    *gopacket.PacketSource
	)

	pcapHdl, err := openPcap(z.cfg.Interface, z.cfg.SnapLen, z.cfg.Port, z.cfg.PktBufTimeout)
	if err != nil {
		log.Fatalf("Error opening pcap device: %v", err)
	}
	defer pcapHdl.Close()
	stream = gopacket.NewPacketSource(pcapHdl, pcapHdl.LinkType())

	for {
		select {
		case <-quit:
			return
		case r := <-z.incoming:
			receivers[r] = true
		case r := <-z.outgoing:
			delete(receivers, r)
		case pkt := <-stream.Packets():
			if pkt == nil {
				continue
			}
			tcpLayer := pkt.Layer(layers.LayerTypeTCP)
			if tcpLayer != nil {
				z.handleTCP(pkt)
				continue
			}

			// If it is an ICMP packet, check if it is the ICMP TTL
			// exceeded one we are looking for
			respPkt, err := z.extractRcvdPkt(pkt)
			if err != nil {
				log.Fatalf("Error extracing response packet: %v", err)
			}
			// Fan-out new packet to all running traceroutes.
			for r := range receivers {
				r <- respPkt
			}
		}
	}
}

func (z *ZeroTrace) handleTCP(pkt gopacket.Packet) {
	// Only process SYN/ACK segments.
	tcpPkt, _ := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if !(tcpPkt.SYN && tcpPkt.ACK) {
		return
	}
	log.Println("Processing SYN/ACK segment.")

	ipPkt, _ := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	ours := net.TCPAddrFromAddrPort(
		netip.MustParseAddrPort(
			fmt.Sprintf("%s:%d", ipPkt.SrcIP, tcpPkt.SrcPort),
		),
	)
	theirs := net.TCPAddrFromAddrPort(
		netip.MustParseAddrPort(
			fmt.Sprintf("%s:%d", ipPkt.DstIP, tcpPkt.DstPort),
		),
	)

	tuple := &fourTuple{
		theirs: theirs,
		ours:   ours,
	}
	seqNums := &seqNums{
		theirs: tcpPkt.Seq,
		ours:   tcpPkt.Ack,
	}
	log.Printf("4-tuple:  %v", tuple)
	log.Printf("Seq nums: %v", seqNums)

	z.setSeqNums(tuple, seqNums)

}

// extractRcvdPkt extracts what we need (IP ID, timestamp, address) from the
// given network packet.
func (z *ZeroTrace) extractRcvdPkt(packet gopacket.Packet) (*respPkt, error) {
	ipv4Layer := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	icmpLayer := packet.Layer(layers.LayerTypeICMPv4)
	icmpPkt, _ := icmpLayer.(*layers.ICMPv4)

	ipID, err := extractIPID(icmpPkt.LayerPayload())
	if err != nil {
		return nil, err
	}

	// We're not interested in the response packet's TTL because by
	// definition, it's always going to be 1.
	return &respPkt{
		ipID:      ipID,
		recvd:     packet.Metadata().Timestamp,
		recvdFrom: ipv4Layer.SrcIP,
	}, nil
}
