// Package ping is a simple but powerful ICMP echo (ping) library.
//
// Here is a very simple example that sends and receives three packets:
//
//	pinger, err := ping.NewPinger("www.google.com")
//	if err != nil {
//		panic(err)
//	}
//	pinger.Count = 3
//	err = pinger.Run() // blocks until finished
//	if err != nil {
//		panic(err)
//	}
//	stats := pinger.Statistics() // get send/receive/rtt stats
//
// Here is an example that emulates the traditional UNIX ping command:
//
//	pinger, err := ping.NewPinger("www.google.com")
//	if err != nil {
//		panic(err)
//	}
//	// Listen for Ctrl-C.
//	c := make(chan os.Signal, 1)
//	signal.Notify(c, os.Interrupt)
//	go func() {
//		for _ = range c {
//			pinger.Stop()
//		}
//	}()
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
//	fmt.Printf("PING %s (%s):\n", pinger.Addr(), pinger.IPAddr())
//	err = pinger.Run()
//	if err != nil {
//		panic(err)
//	}
//
// It sends ICMP Echo Request packet(s) and waits for an Echo Reply in response.
// If it receives a response, it calls the OnRecv callback. When it's finished,
// it calls the OnFinish callback.
//
// For a full ping example, see "cmd/ping/ping.go".
//
package ping

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"math"
	"math/rand"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/uuid"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sync/errgroup"
)

const (
	timeSliceLength  = 8
	trackerLength    = len(uuid.UUID{})
	protocolICMP     = 1
	protocolIPv6ICMP = 58
)

var (
	ipv4Proto = map[string]string{"icmp": "ip4:icmp", "udp": "udp4"}
	ipv6Proto = map[string]string{"icmp": "ip6:ipv6-icmp", "udp": "udp6"}
)

// New returns a new Pinger struct pointer.
func New(addr string) *Pinger {
	r := rand.New(rand.NewSource(getSeed()))

	return &Pinger{
		Count:             -1,
		Interval:          time.Second,
		RecordRtts:        true,
		Size:              timeSliceLength + trackerLength,
		Timeout:           time.Duration(math.MaxInt64),
		addr:              addr,
		done:              make(chan struct{}),
		id:                r.Intn(math.MaxUint16),
		currentUUID:       uuid.New(),
		ipaddr:            nil,
		ipv4:              false,
		network:           "ip",
		protocol:          "udp",
		awaitingSequences: make(map[string]time.Time),
		TTL:               64,
		logger:            StdLogger{Logger: log.New(log.Writer(), log.Prefix(), log.Flags())},
		PacketTimeout:     100 * time.Millisecond,
	}
}

// NewPinger returns a new Pinger and resolves the address.
func NewPinger(addr string) (*Pinger, error) {
	p := New(addr)
	return p, p.Resolve()
}

// Pinger represents a packet sender/receiver.
type Pinger struct {
	// Interval is the wait time between each packet send. Default is 1s.
	Interval time.Duration

	// Timeout specifies a timeout before ping exits, regardless of how many
	// packets have been received.
	// This is not to be confused with PacketTimeout.
	Timeout time.Duration

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

	// Number of duplicate packets received
	PacketsRecvDuplicates int

	// PacketsLost counts packets that have not been answered (within PacketTimeout)
	PacketsLost int

	// Round trip time statistics
	minRtt    time.Duration
	maxRtt    time.Duration
	avgRtt    time.Duration
	stdDevRtt time.Duration
	stddevm2  time.Duration
	statsMu   sync.RWMutex

	// If true, keep a record of rtts of all received packets.
	// Set to false to avoid memory bloat for long running pings.
	RecordRtts bool

	// rtts is all of the Rtts
	rtts []time.Duration

	// OnSetup is called when Pinger has finished setting up the listening socket
	OnSetup func()

	// OnSend is called when Pinger sends a packet
	OnSend func(*Packet)

	// OnRecv is called when Pinger receives and processes a packet
	OnRecv func(*Packet)

	// OnFinish is called when Pinger exits
	OnFinish func(*Statistics)

	// OnDuplicateRecv is called when a packet is received that has already been received.
	OnDuplicateRecv func(*Packet)

	// OnLost is called when Pinger considers a packet lost.
	// This will happen when there is no matching response for >= PacketTimeout.
	OnLost func(usedUUID uuid.UUID, sequenceID int, noResponseAfter time.Duration)

	// Size of packet being sent
	Size int

	// Tracker: Used to uniquely identify packets - Deprecated
	Tracker uint64

	// Source is the source IP address
	Source string

	// Channel and mutex used to communicate when the Pinger should stop between goroutines.
	done chan struct{}
	lock sync.Mutex

	ipaddr *net.IPAddr
	addr   string

	// currentUUID is the current UUID used to build unique and recognizable packet payloads
	currentUUID uuid.UUID

	ipv4     bool
	id       int
	sequence int

	// awaitingSequences are in-flight sequence numbers we keep track of to help remove duplicate receipts.
	// This map does not need synchronization/locking because it is only ever accessed from one goroutine.
	awaitingSequences map[string]time.Time

	// network is one of "ip", "ip4", or "ip6".
	network string
	// protocol is "icmp" or "udp".
	protocol string

	logger Logger

	// TTL is the number of hops a ping packet is allowed before being discarded.
	// With IPv4 it maps to the TTL header field, with IPv6 to the Hop Limit one.
	// TTL has to be >=1 and <=255 as both header fields are limited to 8 bit and a hop limit of 0 is not valid.
	// TODO: Perhaps this should be enforced by changing the type to uin8 or by hiding the field behind a setter?
	TTL int

	// PacketTimeout is the duration after which a package will be considered lost.
	// Defaults to math.MaxInt64 - which practically means it will never be considered lost.
	// Checking whether a package is lost will be performed every PacketTimeout.
	// If a response arrives after PacketTimeout but before the check gets performed it will NOT be considered lost.
	PacketTimeout time.Duration
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

	// TTL is the Time To Live on the packet.
	Ttl int

	// ID is the ICMP identifier.
	ID int
}

// Statistics represent the stats of a currently running or finished
// pinger operation.
type Statistics struct {
	// PacketsRecv is the number of packets received.
	PacketsRecv int

	// PacketsSent is the number of packets sent.
	PacketsSent int

	// PacketsRecvDuplicates is the number of duplicate responses there were to a sent packet.
	PacketsRecvDuplicates int

	// PacketLoss is the percentage of packets lost.
	PacketLoss float64

	// PacketsLost is the actual amount of lost packets
	PacketsLost int

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

func (p *Pinger) updateStatistics(pkt *Packet) {
	p.statsMu.Lock()
	defer p.statsMu.Unlock()

	p.PacketsRecv++
	if p.RecordRtts {
		p.rtts = append(p.rtts, pkt.Rtt)
	}

	if p.PacketsRecv == 1 || pkt.Rtt < p.minRtt {
		p.minRtt = pkt.Rtt
	}

	if pkt.Rtt > p.maxRtt {
		p.maxRtt = pkt.Rtt
	}

	pktCount := time.Duration(p.PacketsRecv)
	// welford's online method for stddev
	// https://en.wikipedia.org/wiki/Algorithms_for_calculating_variance#Welford's_online_algorithm
	delta := pkt.Rtt - p.avgRtt
	p.avgRtt += delta / pktCount
	delta2 := pkt.Rtt - p.avgRtt
	p.stddevm2 += delta * delta2

	p.stdDevRtt = time.Duration(math.Sqrt(float64(p.stddevm2 / pktCount)))
}

// SetIPAddr sets the ip address of the target host.
func (p *Pinger) SetIPAddr(ipaddr *net.IPAddr) {
	p.ipv4 = isIPv4(ipaddr.IP)

	p.ipaddr = ipaddr
	p.addr = ipaddr.String()
}

// IPAddr returns the ip address of the target host.
func (p *Pinger) IPAddr() *net.IPAddr {
	return p.ipaddr
}

// Resolve does the DNS lookup for the Pinger address and sets IP protocol.
func (p *Pinger) Resolve() error {
	if len(p.addr) == 0 {
		return errors.New("addr cannot be empty")
	}
	ipaddr, err := net.ResolveIPAddr(p.network, p.addr)
	if err != nil {
		return err
	}

	p.ipv4 = isIPv4(ipaddr.IP)

	p.ipaddr = ipaddr

	return nil
}

// SetAddr resolves and sets the ip address of the target host, addr can be a
// DNS name like "www.google.com" or IP like "127.0.0.1".
func (p *Pinger) SetAddr(addr string) error {
	oldAddr := p.addr
	p.addr = addr
	err := p.Resolve()
	if err != nil {
		p.addr = oldAddr
		return err
	}
	return nil
}

// Addr returns the string ip address of the target host.
func (p *Pinger) Addr() string {
	return p.addr
}

// SetNetwork allows configuration of DNS resolution.
// * "ip" will automatically select IPv4 or IPv6.
// * "ip4" will select IPv4.
// * "ip6" will select IPv6.
func (p *Pinger) SetNetwork(n string) {
	switch n {
	case "ip4":
		p.network = "ip4"
	case "ip6":
		p.network = "ip6"
	default:
		p.network = "ip"
	}
}

// SetPrivileged sets the type of ping pinger will send.
// false means pinger will send an "unprivileged" UDP ping.
// true means pinger will send a "privileged" raw ICMP ping.
// NOTE: setting to true requires that it be run with super-user privileges.
func (p *Pinger) SetPrivileged(privileged bool) {
	if privileged {
		p.protocol = "icmp"
	} else {
		p.protocol = "udp"
	}
}

// Privileged returns whether pinger is running in privileged mode.
func (p *Pinger) Privileged() bool {
	return p.protocol == "icmp"
}

// SetLogger sets the logger to be used to log events from the pinger.
func (p *Pinger) SetLogger(logger Logger) {
	p.logger = logger
}

// SetID sets the ICMP identifier.
func (p *Pinger) SetID(id int) {
	p.id = id
}

// ID returns the ICMP identifier.
func (p *Pinger) ID() int {
	return p.id
}

// Run runs the pinger. This is a blocking function that will exit when it's
// done. If Count or Interval are not specified, it will run continuously until
// it is interrupted.
func (p *Pinger) Run() error {
	var conn packetConn
	var err error
	if p.Size < timeSliceLength+trackerLength {
		return fmt.Errorf("size %d is less than minimum required size %d", p.Size, timeSliceLength+trackerLength)
	}

	if p.TTL < 1 || p.TTL > 255 {
		return fmt.Errorf("TTL %d out of range; has to be >= 1 and <= 255", p.TTL)
	}

	if p.ipaddr == nil {
		if err := p.Resolve(); err != nil {
			return err
		}
	}

	if conn, err = p.listen(); err != nil {
		return err
	}
	defer conn.Close()

	conn.SetTTL(p.TTL)
	return p.run(conn)
}

func (p *Pinger) run(conn packetConn) error {
	if err := conn.SetFlagTTL(); err != nil {
		return err
	}
	defer p.finish()

	recv := make(chan *packet, 5)
	defer close(recv)

	if handler := p.OnSetup; handler != nil {
		handler()
	}

	var g errgroup.Group

	g.Go(func() error {
		defer p.Stop()
		return p.recvICMP(conn, recv)
	})

	g.Go(func() error {
		defer p.Stop()
		return p.runLoop(conn, recv)
	})

	return g.Wait()
}

func (p *Pinger) runLoop(
	conn packetConn,
	recvCh <-chan *packet,
) error {
	logger := p.logger
	if logger == nil {
		logger = NoopLogger{}
	}

	timeout := time.NewTicker(p.Timeout)
	interval := time.NewTicker(p.Interval)

	var intervalLostPacketsCheck <-chan time.Time

	// In case it is zero NewTicker would panic, furthermore 0 is defined as "packets never timeout"
	if p.PacketTimeout > 0 {
		t := time.NewTicker(p.PacketTimeout)
		defer t.Stop()

		intervalLostPacketsCheck = t.C
	}

	defer func() {
		interval.Stop()
		timeout.Stop()
	}()

	if err := p.sendICMP(conn); err != nil {
		return err
	}

	for {
		select {
		case <-p.done:
			return nil

		case <-timeout.C:
			return nil

		case r := <-recvCh:
			err := p.processPacket(r)
			if err != nil {
				// FIXME: this logs as FATAL but continues
				logger.Fatalf("processing received packet: %s", err)
			}

		case <-interval.C:
			if p.Count > 0 && p.PacketsSent >= p.Count {
				interval.Stop()
				continue
			}
			err := p.sendICMP(conn)
			if err != nil {
				// FIXME: this logs as FATAL but continues
				logger.Fatalf("sending packet: %s", err)
			}

		case <-intervalLostPacketsCheck:
			p.checkForLostPackets()
		}

		if p.Count > 0 && p.PacketsRecv+p.PacketsLost >= p.Count {
			return nil
		}
	}
}

func (p *Pinger) Stop() {
	p.lock.Lock()
	defer p.lock.Unlock()

	select {
	case <-p.done:
		return
	default:
		close(p.done)
	}
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
	p.statsMu.RLock()
	defer p.statsMu.RUnlock()

	return &Statistics{
		PacketsSent:           p.PacketsSent,
		PacketsRecv:           p.PacketsRecv,
		PacketsRecvDuplicates: p.PacketsRecvDuplicates,
		PacketLoss:            float64(p.PacketsLost) / float64(p.PacketsSent) * 100,
		PacketsLost:           p.PacketsLost,
		Rtts:                  p.rtts,
		Addr:                  p.addr,
		IPAddr:                p.ipaddr,
		MaxRtt:                p.maxRtt,
		MinRtt:                p.minRtt,
		AvgRtt:                p.avgRtt,
		StdDevRtt:             p.stdDevRtt,
	}
}

type expBackoff struct {
	baseDelay time.Duration
	maxExp    int64
	c         int64
}

func (b *expBackoff) Get() time.Duration {
	if b.c < b.maxExp {
		b.c++
	}

	return b.baseDelay * time.Duration(rand.Int63n(1<<b.c))
}

func newExpBackoff(baseDelay time.Duration, maxExp int64) expBackoff {
	return expBackoff{baseDelay: baseDelay, maxExp: maxExp}
}

func (p *Pinger) recvICMP(
	conn packetConn,
	recv chan<- *packet,
) error {
	// Start by waiting for 50 µs and increase to a possible maximum of ~ 100 ms.
	expBackoff := newExpBackoff(50*time.Microsecond, 11)
	delay := expBackoff.Get()

	for {
		select {
		case <-p.done:
			return nil
		default:
			bytes := make([]byte, p.getMessageLength())
			if err := conn.SetReadDeadline(time.Now().Add(delay)); err != nil {
				return err
			}
			var n, ttl int
			var err error
			n, ttl, _, err = conn.ReadFrom(bytes)
			if err != nil {
				if neterr, ok := err.(*net.OpError); ok {
					if neterr.Timeout() {
						// Read timeout
						delay = expBackoff.Get()
						continue
					}
				}
				return err
			}

			select {
			case <-p.done:
				return nil
			case recv <- &packet{bytes: bytes, nbytes: n, ttl: ttl}:
			}
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
	if m, err = icmp.ParseMessage(proto, recv.bytes); err != nil {
		return fmt.Errorf("error parsing icmp message: %w", err)
	}

	if m.Type != ipv4.ICMPTypeEchoReply && m.Type != ipv6.ICMPTypeEchoReply {
		// Not an echo reply, ignore it
		return nil
	}

	inPkt := &Packet{
		Nbytes: recv.nbytes,
		IPAddr: p.ipaddr,
		Addr:   p.addr,
		Ttl:    recv.ttl,
		ID:     p.id,
	}

	switch pkt := m.Body.(type) {
	case *icmp.Echo:
		if !p.matchID(pkt.ID) {
			return nil
		}

		if len(pkt.Data) < timeSliceLength+trackerLength {
			return fmt.Errorf("insufficient data received; got: %d %v",
				len(pkt.Data), pkt.Data)
		}

		pktUUID, err := uuid.FromBytes(pkt.Data[timeSliceLength : timeSliceLength+trackerLength])
		if err != nil {
			return fmt.Errorf("error decoding tracking UUID: %w", err)
		}

		sentAt := bytesToTime(pkt.Data[:timeSliceLength])
		inPkt.Rtt = receivedAt.Sub(sentAt)
		inPkt.Seq = pkt.Seq

		key := buildLookupKey(pktUUID, pkt.Seq)

		// If we've already received this sequence, ignore it.
		if _, inflight := p.awaitingSequences[key]; !inflight {
			// Check whether this isn't a duplicate but a response that has been declared lost already and therefore
			// isn't present in awaitingSequences anymore
			// If PacketTimeout is set to 0, packets shall never time out.
			if p.PacketTimeout != 0 && receivedAt.Sub(sentAt) >= p.PacketTimeout {
				return nil
			}

			p.PacketsRecvDuplicates++
			if p.OnDuplicateRecv != nil {
				p.OnDuplicateRecv(inPkt)
			}

			return nil
		}

		// remove it from the list of sequences we're waiting for, so we don't get duplicates.
		delete(p.awaitingSequences, key)
		p.updateStatistics(inPkt)
	default:
		// Very bad, not sure how this can happen
		return fmt.Errorf("invalid ICMP echo reply; type: '%T', '%v'", pkt, pkt)
	}

	handler := p.OnRecv
	if handler != nil {
		handler(inPkt)
	}

	return nil
}

func (p *Pinger) sendICMP(conn packetConn) error {
	var dst net.Addr = p.ipaddr
	if p.protocol == "udp" {
		dst = &net.UDPAddr{IP: p.ipaddr.IP, Zone: p.ipaddr.Zone}
	}

	uuidEncoded, err := p.currentUUID.MarshalBinary()
	if err != nil {
		return fmt.Errorf("unable to marshal UUID binary: %w", err)
	}

	var (
		sentAt   time.Time
		msgBytes []byte
	)

	for {
		sentAt = time.Now()

		t := append(timeToBytes(sentAt), uuidEncoded...)

		if remainSize := p.Size - timeSliceLength - trackerLength; remainSize > 0 {
			t = append(t, bytes.Repeat([]byte{1}, remainSize)...)
		}

		body := &icmp.Echo{
			ID:   p.id,
			Seq:  p.sequence,
			Data: t,
		}

		msg := &icmp.Message{
			Type: conn.ICMPRequestType(),
			Code: 0,
			Body: body,
		}

		msgBytes, err = msg.Marshal(nil)
		if err != nil {
			return err
		}

		if _, err := conn.WriteTo(msgBytes, dst); err != nil {
			if neterr, ok := err.(*net.OpError); ok {
				if neterr.Err == syscall.ENOBUFS {
					// Slow down the busy loop
					time.Sleep(2 * time.Millisecond)

					continue
				}
			}

			return err
		}

		break
	}

	handler := p.OnSend
	if handler != nil {
		handler(&Packet{
			Nbytes: len(msgBytes),
			IPAddr: p.ipaddr,
			Addr:   p.addr,
			Seq:    p.sequence,
			ID:     p.id,
		})
	}

	// mark this sequence as in-flight
	p.awaitingSequences[buildLookupKey(p.currentUUID, p.sequence)] = sentAt
	p.PacketsSent++
	p.sequence++
	if p.sequence > 65535 {
		p.currentUUID = uuid.New()
		p.sequence = 0
	}

	return nil
}

func (p *Pinger) listen() (packetConn, error) {
	var (
		conn packetConn
		err  error
	)

	if p.ipv4 {
		var c icmpv4Conn
		c.c, err = icmp.ListenPacket(ipv4Proto[p.protocol], p.Source)
		conn = &c
	} else {
		var c icmpV6Conn
		c.c, err = icmp.ListenPacket(ipv6Proto[p.protocol], p.Source)
		conn = &c
	}

	if err != nil {
		p.Stop()
		return nil, err
	}
	return conn, nil
}

func (p *Pinger) checkForLostPackets() {
	if p.PacketTimeout == 0 {
		// Packets shall not time out
		return
	}

	now := time.Now()

	for k, sentAt := range p.awaitingSequences {
		if delta := now.Sub(sentAt); delta >= p.PacketTimeout {
			delete(p.awaitingSequences, k)

			p.statsMu.Lock()
			p.PacketsLost++
			p.statsMu.Unlock()

			if p.OnLost != nil {
				usedUUID, sequenceID, err := parseLookupKey(k)
				// This should never happen as all keys used in the map are build using buildLookupKey()
				if err != nil {
					p.logger.Errorf("invalid lookup key %q: %s", k, err)
				}

				p.OnLost(usedUUID, sequenceID, delta)
			}
		}
	}
}

func bytesToTime(b []byte) time.Time {
	var nsec int64
	for i := uint8(0); i < 8; i++ {
		nsec += int64(b[i]) << ((7 - i) * 8)
	}
	return time.Unix(nsec/1_000_000_000, nsec%1_000_000_000)
}

func isIPv4(ip net.IP) bool {
	return len(ip.To4()) == net.IPv4len
}

func timeToBytes(t time.Time) []byte {
	nsec := t.UnixNano()
	b := make([]byte, 8)
	for i := uint8(0); i < 8; i++ {
		b[i] = byte((nsec >> ((7 - i) * 8)) & 0xff)
	}
	return b
}

var seed int64 = time.Now().UnixNano()

// getSeed returns a goroutine-safe unique seed
func getSeed() int64 {
	return atomic.AddInt64(&seed, 1)
}

// buildLookupKey builds the key required for lookups on awaitingSequences map
func buildLookupKey(id uuid.UUID, sequenceId int) string {
	return string(id[:]) + strconv.Itoa(sequenceId)
}

// parseLookupKey retries UUID and sequence ID from a lookup key build with buildLookupKey
func parseLookupKey(key string) (uuid.UUID, int, error) {
	// 16 bytes for the UUID and at least one byte for the sequence ID
	if len(key) < 17 {
		return uuid.UUID{}, 0, fmt.Errorf("lookup key to short, expected length to be at least 17 but was %d", len(key))
	}

	// The first 16 bytes represent the UUID
	readUUID, err := uuid.FromBytes([]byte(key[:16]))
	if err != nil {
		return uuid.UUID{}, 0, fmt.Errorf("unmarshalling UUID from lookup key: %w", err)
	}

	sequenceID, err := strconv.Atoi(key[16:])
	if err != nil {
		return uuid.UUID{}, 0, fmt.Errorf("reading sequence ID from lookup key: %w", err)
	}

	return readUUID, sequenceID, nil
}
