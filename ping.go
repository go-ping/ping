// Package ping is an ICMP ping library seeking to emulate the unix "ping"
// command.
//
// Here is a very simple example that sends & receives 3 packets:
//
//	pinger, err := ping.NewPinger("www.google.com")
//	if err != nil {
//		panic(err)
//	}
//
//	pinger.Count = 3
//	pinger.Run() // blocks until finished
//	stats := pinger.Statistics() // get send/receive/rtt stats
//
// Here is an example that emulates the unix ping command:
//
//	pinger, err := ping.NewPinger("www.google.com")
//	if err != nil {
//		fmt.Printf("ERROR: %s\n", err.Error())
//		return
//	}
//
//	pinger.OnRecv = func(pkt *ping.Packet) {
//		fmt.Printf("%d bytes from %s: icmp_seq=%d time=%v\n",
//			pkt.Nbytes, pkt.IPAddr, pkt.Seq, pkt.Rtt)
//	}
//	pinger.OnFinish = func(stats *ping.Statistics) {
//		fmt.Printf("\n--- %s ping statistics ---\n", stats.Addr)
//		fmt.Printf("%d packets transmitted, %d packets received, %v%% packet loss\n",
//			stats.PacketsSent, stats.PacketsRecv, stats.PacketLoss)
//		fmt.Printf("round-trip min/avg/max/stddev = %v/%v/%v/%v\n",
//			stats.MinRtt, stats.AvgRtt, stats.MaxRtt, stats.StdDevRtt)
//	}
//
//	fmt.Printf("PING %s (%s):\n", pinger.Addr(), pinger.IPAddr())
//	pinger.Run()
//
// It sends ICMP packet(s) and waits for a response. If it receives a response,
// it calls the "receive" callback. When it's finished, it calls the "finish"
// callback.
//
// For a full ping example, see "cmd/ping/ping.go".
//
package ping

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"net"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	timeSliceLength  = 8
	trackerLength    = 4
	protocolICMP     = 1
	protocolIPv6ICMP = 58
)

// NewPinger returns a new Pinger struct pointer
func NewPinger(addr string) (*Pinger, error) {
	ipaddr, err := net.ResolveIPAddr("ip", addr)

	if err != nil {
		return nil, err
	}

	var net string
	var ipv4 bool

	if isIPv4(ipaddr.IP) {
		net = "udp4"
		ipv4 = true
	} else if isIPv6(ipaddr.IP) {
		net = "udp6"
		ipv4 = false
	}

	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	return &Pinger{
		ipaddr:   ipaddr,
		addr:     addr,
		Interval: time.Second,
		Timeout:  time.Second * 100000,
		Deadline: time.Minute * 100000,
		Count:    -1,
		id:       r.Intn(math.MaxInt16),
		network:  net,
		ipv4:     ipv4,
		Size:     timeSliceLength + trackerLength,
		Tracker:  r.Int31n(math.MaxInt32),
		done:     make(chan bool),
	}, nil
}

// Pinger represents ICMP packet sender/receiver
type Pinger struct {
	// Interval is the wait time between each packet send. Default is 1s.
	Interval time.Duration

	// Timeout specifies a timeout before ping exits, regardless of how many
	// packets have been received.
	Timeout time.Duration

	// Deadline specifies a per-ping timeout before ping exits, regardless of how many
	// packets have been received.
	Deadline time.Duration

	// Count tells pinger to stop after sending (and receiving) Count echo
	// packets. If this option is not specified, pinger will operate until
	// interrupted.
	Count int

	// Debug runs in debug mode
	Debug bool

	// Number of packets sent
	PacketsSent int

	// Number of packets received
	PacketsRecv int

	// rtts is all of the Rtts
	rtts []time.Duration

	// OnRecv is called when Pinger receives and processes a packet
	OnRecv func(*Packet)

	// OnFinish is called when Pinger exits
	OnFinish func(*Statistics)

	// Size of packet being sent
	Size int

	// Tracker: Used to uniquely identify packet when non-priviledged
	Tracker int32

	// stop chan bool
	done chan bool

	ipaddr *net.IPAddr
	addr   string

	ipv4     bool
	size     int
	id       int
	sequence int
	network  string
}

type packet struct {
	bytes  []byte
	nbytes int
	ttl    int
}

// Packet represents a received and processed ICMP echo packet.
type Packet struct {
	// Rtt is the round-trip time it took to ping.
	Rtt time.Duration

	// IPAddr is the address of the host being pinged.
	IPAddr *net.IPAddr

	// Addr is the string address of the host being pinged.
	Addr string

	// NBytes is the number of bytes in the message.
	Nbytes int

	// Seq is the ICMP sequence number.
	Seq int

	// TTL is the Time to Live on the packet.
	Ttl int
}

// Statistics represent the stats of a currently running or finished
// pinger operation.
type Statistics struct {
	// PacketsRecv is the number of packets received.
	PacketsRecv int

	// PacketsSent is the number of packets sent.
	PacketsSent int

	// PacketLoss is the percentage of packets lost.
	PacketLoss float64

	// IPAddr is the address of the host being pinged.
	IPAddr *net.IPAddr

	// Addr is the string address of the host being pinged.
	Addr string

	// Rtts is all of the round-trip times sent via this pinger.
	Rtts []time.Duration

	// MinRtt is the minimum round-trip time sent via this pinger.
	MinRtt time.Duration

	// MaxRtt is the maximum round-trip time sent via this pinger.
	MaxRtt time.Duration

	// AvgRtt is the average round-trip time sent via this pinger.
	AvgRtt time.Duration

	// StdDevRtt is the standard deviation of the round-trip times sent via
	// this pinger.
	StdDevRtt time.Duration
}

// GetIpv4 returns whether ipv4 is used.
func (p *Pinger) GetIpv4() bool {
	return p.ipv4
}

// SetIPAddr sets the ip address of the target host.
func (p *Pinger) SetIPAddr(ipaddr *net.IPAddr) {
	var ipv4 bool
	if isIPv4(ipaddr.IP) {
		ipv4 = true
	} else if isIPv6(ipaddr.IP) {
		ipv4 = false
	}

	p.ipaddr = ipaddr
	p.addr = ipaddr.String()
	p.ipv4 = ipv4
}

// IPAddr returns the ip address of the target host.
func (p *Pinger) IPAddr() *net.IPAddr {
	return p.ipaddr
}

// SetAddr resolves and sets the ip address of the target host, addr can be a
// DNS name like "www.google.com" or IP like "127.0.0.1".
func (p *Pinger) SetAddr(addr string) error {
	ipaddr, err := net.ResolveIPAddr("ip", addr)
	if err != nil {
		return err
	}

	p.SetIPAddr(ipaddr)
	p.addr = addr
	return nil
}

// Addr returns the string ip address of the target host.
func (p *Pinger) Addr() string {
	return p.addr
}

// SetPrivileged sets the type of ping pinger will send.
// false means pinger will send an "unprivileged" UDP ping.
// true means pinger will send a "privileged" raw ICMP ping.
// NOTE: setting to true requires that it be run with super-user privileges.
func (p *Pinger) SetPrivileged(privileged bool) {
	if privileged {
		if p.ipv4 {
			p.network = "ip4:icmp"
		} else {
			p.network = "ip6:ipv6-icmp"
		}
	} else {
		if p.ipv4 {
			p.network = "udp4"
		} else {
			p.network = "udp6"
		}
	}
}

// Privileged returns whether pinger is running in privileged mode.
func (p *Pinger) Privileged() bool {
	return p.network == "ip4:icmp" || p.network == "ip6:ipv6-icmp"
}

// Run runs the pinger. This is a blocking function that will exit when it's
// done. If Count or Interval are not specified, it will run continuously until
// it is interrupted.
func (p *Pinger) Run() {
	p.run()
}

func (p *Pinger) run() {
	var conn *icmp.PacketConn
	var err error

	if conn, err = p.Listen(""); err != nil {
		fmt.Println("Failed to listen")
		return
	}

	defer conn.Close()

	if err = p.DoPing(context.Background(), conn); err != nil {
		fmt.Println(err.Error())
	}
}

func (p *Pinger) DoPing(ctx context.Context, conn *icmp.PacketConn) error {
	defer p.finish()

	if p.ipv4 {
		conn.IPv4PacketConn().SetControlMessage(ipv4.FlagTTL, true)
	} else {
		conn.IPv6PacketConn().SetControlMessage(ipv6.FlagHopLimit, true)
	}

	wg := sync.WaitGroup{}
	recv := make(chan *packet, 100)

	wg.Add(1)
	go p.recvICMP(conn, recv, &wg)

	err := p.sendICMP(conn)
	if err != nil {
		return err
	}

	if p.Interval.Seconds() < .2 {
		p.Interval = time.Second
	}
	interval := time.NewTicker(p.Interval)
	defer interval.Stop()

	var cancel context.CancelFunc
	ctx, cancel = context.WithTimeout(ctx, p.Timeout)
	defer cancel()

	for {
		select {
		case <-p.done:
			wg.Wait()
			return nil
		case <-ctx.Done():
			close(p.done)
			wg.Wait()
			return nil
		case <-interval.C:
			if p.Count > 0 && p.PacketsSent >= p.Count {
				continue
			}
			err = p.sendICMP(conn)
			if err != nil {
				return err
			}
		case r := <-recv:
			err := p.processPacket(r)
			if err != nil {
				return err
			}
		}
		if p.Count > 0 && p.PacketsRecv >= p.Count {
			close(p.done)
			for buffR := range recv {
				// flush bufferred channel
				err := p.processPacket(buffR)
				if err != nil {
					return err
				}
			}

			wg.Wait()
			return nil
		}
	}
}

// Stop ceases the pinging.
func (p *Pinger) Stop() {
	close(p.done)
}

func (p *Pinger) finish() {
	handler := p.OnFinish
	if handler != nil {
		s := p.Statistics()
		handler(s)
	}
}

// Statistics returns the statistics of the pinger. This can be run while the
// pinger is running or after it is finished. OnFinish calls this function to
// get it's finished statistics.
func (p *Pinger) Statistics() *Statistics {
	loss := float64(p.PacketsSent-p.PacketsRecv) / float64(p.PacketsSent) * 100
	var min, max, total time.Duration
	if len(p.rtts) > 0 {
		min = p.rtts[0]
		max = p.rtts[0]
	}
	for _, rtt := range p.rtts {
		if rtt < min {
			min = rtt
		}
		if rtt > max {
			max = rtt
		}
		total += rtt
	}
	s := Statistics{
		PacketsSent: p.PacketsSent,
		PacketsRecv: p.PacketsRecv,
		PacketLoss:  loss,
		Rtts:        p.rtts,
		Addr:        p.addr,
		IPAddr:      p.ipaddr,
		MaxRtt:      max,
		MinRtt:      min,
	}
	if len(p.rtts) > 0 {
		s.AvgRtt = total / time.Duration(len(p.rtts))
		var sumsquares time.Duration
		for _, rtt := range p.rtts {
			sumsquares += (rtt - s.AvgRtt) * (rtt - s.AvgRtt)
		}
		s.StdDevRtt = time.Duration(math.Sqrt(
			float64(sumsquares / time.Duration(len(p.rtts)))))
	}

	return &s
}

func (p *Pinger) recvICMP(conn *icmp.PacketConn, recv chan<- *packet, wg *sync.WaitGroup) {
	defer wg.Done()
	for {
		select {
		case <-p.done:
			close(recv)
			return
		default:
			var n, ttl int
			var err error

			bytesReceived := make([]byte, 65535)
			conn.SetReadDeadline(time.Now().Add(time.Millisecond * 300))
			if p.ipv4 {
				var cm *ipv4.ControlMessage
				n, cm, _, err = conn.IPv4PacketConn().ReadFrom(bytesReceived)
				if cm != nil {
					ttl = cm.TTL
				}
			} else {
				var cm *ipv6.ControlMessage
				n, cm, _, err = conn.IPv6PacketConn().ReadFrom(bytesReceived)
				if cm != nil {
					ttl = cm.HopLimit
				}
			}
			if err != nil {
				if neterr, ok := err.(*net.OpError); ok {
					if neterr.Timeout() {
						if n > 0 {
							fmt.Println("Timed out, got: ", bytesReceived[:n])
						}
						// Read timeout
						continue
					} else {
						close(p.done)
						return
					}
				}
				// do something with other error
				fmt.Println("Some other error - ", err.Error())
			}

			recv <- &packet{bytes: bytesReceived[:n], nbytes: n, ttl: ttl}
		}
	}
}

func (p *Pinger) processPacket(recv *packet) error {
	receivedAt := time.Now()
	var proto int
	if p.ipv4 {
		proto = protocolICMP
	} else {
		proto = protocolIPv6ICMP
	}

	var m *icmp.Message
	var err error
	if m, err = icmp.ParseMessage(proto, recv.bytes[:recv.nbytes]); err != nil {
		return fmt.Errorf("failed to parse icmp message: %v", err)
	}

	if m.Type != ipv4.ICMPTypeEchoReply && m.Type != ipv6.ICMPTypeEchoReply {
		// Likely an `ICMPTypeDestinationUnreachable`, ignore it.
		return nil
	}

	outPkt := &Packet{
		Nbytes: recv.nbytes,
		IPAddr: p.ipaddr,
		Addr:   p.addr,
		Ttl:    recv.ttl,
	}

	switch pkt := m.Body.(type) {
	case *icmp.Echo:
		// If we are privileged, we can match icmp.ID
		if p.network == "ip4:icmp" || p.network == "ip6:ipv6-icmp" {
			// Check if reply from same ID
			if pkt.ID != p.id {
				return nil
			}
		}

		if len(pkt.Data) < timeSliceLength+trackerLength {
			return errors.New("insufficient data received")
		}
		// todo: check if we can cache
		tracker := bytesToInt(pkt.Data[timeSliceLength:])
		timestamp := bytesToTime(pkt.Data[:timeSliceLength])

		if tracker != p.Tracker {
			return nil
		}

		outPkt.Rtt = receivedAt.Sub(timestamp)
		outPkt.Seq = pkt.Seq
		p.PacketsRecv++
	default:
		return fmt.Errorf("invalid ICMP echo reply; type: '%T', '%v'", pkt, pkt)
	}

	p.rtts = append(p.rtts, outPkt.Rtt)
	handler := p.OnRecv
	if handler != nil {
		handler(outPkt)
	}

	return nil
}

func (p *Pinger) sendICMP(conn *icmp.PacketConn) error {
	var typ icmp.Type
	if p.ipv4 {
		typ = ipv4.ICMPTypeEcho
	} else {
		typ = ipv6.ICMPTypeEchoRequest
	}

	t := append(timeToBytes(time.Now()), intToBytes(p.Tracker)...)
	if remainSize := p.Size - timeSliceLength - trackerLength; remainSize > 0 {
		t = append(t, bytes.Repeat([]byte{1}, remainSize)...)
	}

	body := &icmp.Echo{
		ID:   p.id,
		Seq:  p.sequence,
		Data: t,
	}

	msg := &icmp.Message{
		Type: typ,
		Code: 0,
		Body: body,
	}

	msgBytes, err := msg.Marshal(nil)
	if err != nil {
		return err
	}

	if err := conn.SetWriteDeadline(time.Now().Add(p.Deadline)); err != nil {
		return err
	}

	var dst net.Addr = p.ipaddr
	if p.network == "udp4" || p.network == "udp6" {
		dst = &net.UDPAddr{IP: p.ipaddr.IP, Zone: p.ipaddr.Zone}
	}

	if _, err := conn.WriteTo(msgBytes, dst); err != nil {
		return err
	}
	p.PacketsSent++
	p.sequence++

	return nil
}

// Listen listens on a socket for icmp traffic.
// return something consumable by a "pinger" (object, channel, etc)
// map[string]chan if packet comes in for id, send to map[id]channel
// listenAndRead?? read divvys out incoming data
//
// newListener(interface) , has start(), handle()
func (p *Pinger) Listen(addr string) (*icmp.PacketConn, error) {
	// no more than one listener per interface
	conn, err := icmp.ListenPacket(p.network, addr)
	if err != nil {
		close(p.done)
		return nil, fmt.Errorf("error listening for ICMP packets: %v", err)
	}
	return conn, nil
}

func bytesToTime(b []byte) time.Time {
	var nsec int64
	for i := uint8(0); i < 8; i++ {
		nsec += int64(b[i]) << ((7 - i) * 8)
	}
	return time.Unix(nsec/1000000000, nsec%1000000000)
}

func bytesToInt(b []byte) int32 {
	return int32(binary.BigEndian.Uint32(b))
}

func intToBytes(tracker int32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, uint32(tracker))
	return b
}

func isIPv4(ip net.IP) bool {
	return len(ip.To4()) == net.IPv4len
}

func isIPv6(ip net.IP) bool {
	return len(ip) == net.IPv6len
}

func timeToBytes(t time.Time) []byte {
	nsec := t.UnixNano()
	b := make([]byte, 8)
	for i := uint8(0); i < 8; i++ {
		b[i] = byte((nsec >> ((7 - i) * 8)) & 0xff)
	}
	return b
}
