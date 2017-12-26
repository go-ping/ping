package ping

import (
	"net"
	"time"
	"fmt"
	"sync"
	"syscall"
	"os"
	"math"
	"os/signal"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"go/src/strconv"
)

var GlobalID = 0

type BatchPinger struct {
	pingers []*Pinger2


	// 如果收到回应包，反查pinger
	PackPinger map[string]*Pinger2

	// Interval is the wait time between each packet send. Default is 1s.
	Interval time.Duration

	// Timeout specifies a timeout before ping exits, regardless of how many
	// packets have been received.
	Timeout time.Duration

	// Count tells pinger to stop after sending (and receiving) Count echo
	// packets. If this option is not specified, pinger will operate until
	// interrupted.
	Count int

	// record send count
	SendCount int

	// Debug runs in debug mode
	Debug bool

	// OnRecv is called when Pinger receives and processes a packet
	OnRecv func(*icmp.Echo)

	// OnFinish is called when Pinger exits
	OnFinish func([]*Statistics)

	// stop chan bool
	done chan bool

	ipv4    bool
	size    int
	source  string
	network string
}

type Pinger2 struct {
	ipaddr *net.IPAddr
	addr   string

	// Number of packets sent
	PacketsSent int

	// Number of packets received
	PacketsRecv int

	// rtts is all of the Rtts
	rtts []time.Duration

	// ICMP id (2 bytes)
	id int
	// ICMP sequence (2 bytes)
	sequence int

	ipv4 bool
	size int
	network string

}



func NewPinger2(ipaddr *net.IPAddr, id int, ipv4 bool) (*Pinger2) {
	x := Pinger2{}
	x.ipaddr = ipaddr
	x.PacketsSent = 0
	x.PacketsRecv = 0
	x.rtts = []time.Duration{}
	x.id = id
	x.sequence = 0
	x.ipv4 = ipv4
	x.size = timeSliceLength
	x.addr = ipaddr.String()
	return &x
}

// NewPinger returns a new Pinger struct pointer
// interval in secs
func NewBatchPinger(ipSlice []string, count int, interval time.Duration,
	timeout time.Duration) (*BatchPinger, error) {
	pingers := []*Pinger2{}


	fmt.Printf("count ipSlice:%v\n", len(ipSlice))

	var ipv4 bool
	for _, ip := range ipSlice {
		fmt.Printf("ip:%v\n", ip)

		ipaddr, err := net.ResolveIPAddr("ip", ip)
		if err != nil {
			return nil, err
		}

		if isIPv4(ipaddr.IP) {
			ipv4 = true
		} else if isIPv6(ipaddr.IP) {
			ipv4 = false
		}

		id := GenNextID(GlobalID)
		GlobalID = id
		pinger := NewPinger2(ipaddr, id, ipv4)
		pingers = append(pingers, pinger)

	}

	fmt.Printf("count pingers:%v\n", len(pingers))

	return &BatchPinger{
		Interval: interval,
		Timeout:  timeout,
		Count:    count,
		done:     make(chan bool),
		network:  "ip",
		ipv4:     ipv4,
		size:     timeSliceLength,
		pingers:   pingers,
		PackPinger: make(map[string]*Pinger2),
	}, nil
}

func GenNextID(id int) int {
	if id < 0 {
		id = 0
	}

	id++
	if id > 65535 {
		id = 0
	}
	return id
}

func (bp *BatchPinger) Run() {
	var conn *icmp.PacketConn
	if bp.ipv4 {
		fmt.Printf("source:%v, network:%v\n", bp.source, bp.network)
		if conn = bp.Listen(ipv4Proto[bp.network], bp.source); conn == nil {
			return
		}
	} else {
		if conn = bp.Listen(ipv6Proto[bp.network], bp.source); conn == nil {
			return
		}
	}
	defer conn.Close()
	defer bp.finish()

	var wg sync.WaitGroup
	recv := make(chan *packet, 2000)

	go bp.RecvICMP(conn, recv, &wg)

	err := bp.BatchSendICMP(conn)
	if err != nil {
		fmt.Println(err.Error())
	}

	fmt.Printf("Count:%v\n", bp.Count)
	fmt.Printf("SendCount:%v\n", bp.SendCount)
	fmt.Printf("Timeout:%v\n", bp.Timeout)
	fmt.Printf("Interval:%v\n", bp.Interval)

	timeout := time.NewTicker(bp.Timeout)
	interval := time.NewTicker(bp.Interval)
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	signal.Notify(c, syscall.SIGTERM)

	for {
		select {
		case sig := <-c:
			fmt.Printf("get signal %s, prepare exit \n", sig)
			close(bp.done)

		case <-bp.done:
			wg.Wait()
			return

		case <-timeout.C:
			fmt.Println("tick timeout")
			close(bp.done)
			wg.Wait()
			return

		case <-interval.C:
			fmt.Println("tick interval")
			err = bp.BatchSendICMP(conn)
			if err != nil {
				fmt.Println("FATAL: ", err.Error())
			}
		case r := <-recv:
			err := bp.ProcessPacket(r)
			if err != nil {
				fmt.Println("FATAL: ", err.Error())
			}
		default:
			time.Sleep(time.Millisecond * 100)
			allSent, allRecv := bp.GetAllPacketsRecv()
			//fmt.Printf("Count:%v, SendCount:%v, allSent:%v, allRecv:%v\n",
				//bp.Count, bp.SendCount, allSent, allRecv)
			if bp.Count > 0 && bp.SendCount == bp.Count && allRecv >= allSent {
				close(bp.done)
				wg.Wait()
				return
			}
		}
	}
}

func (bp *BatchPinger) GetAllPacketsRecv()(int, int){
	allRecv := 0
	allSent := 0
	for _, pinger := range bp.pingers{
		allRecv += pinger.PacketsRecv
		allSent += pinger.PacketsSent
	}
	return allSent, allRecv
}

func (p *BatchPinger) Listen(netProto string, source string) *icmp.PacketConn {
	conn, err := icmp.ListenPacket(netProto, source)
	if err != nil {
		fmt.Printf("Error listening for ICMP packets: %s\n", err.Error())
		close(p.done)
		return nil
	}
	return conn
}

func (p *BatchPinger) RecvICMP(conn *icmp.PacketConn, recv chan<- *packet, wg *sync.WaitGroup) {
	wg.Add(1)
	defer wg.Done()

	for {
		select {
		case <-p.done:
			return
		default:
			bytes := make([]byte, 512)
			conn.SetReadDeadline(time.Now().Add(time.Millisecond * 100))
			n, _, err := conn.ReadFrom(bytes)
			if err != nil {
				if neterr, ok := err.(*net.OpError); ok {
					if neterr.Timeout() {
						// Read timeout
						continue
					} else {
						close(p.done)
						return
					}
				}
			}

			recv <- &packet{bytes: bytes, nbytes: n}
		}
	}
}

func (bp *BatchPinger) BatchSendICMP(conn *icmp.PacketConn) error {
	if bp.SendCount >= bp.Count{
		return nil
	}

	for _, pinger := range bp.pingers {
		// id +  ":" + seq
		key := strconv.Itoa(pinger.id) + ":" + strconv.Itoa(pinger.sequence)
		bp.PackPinger[key] = pinger

		fmt.Printf("add:%v, id:%v, seq:%v\n", pinger.addr, pinger.id, pinger.sequence)
		err := pinger.SendICMP(conn)
		if err != nil {
			fmt.Printf("err:%v\n", err)
			return err
		}

	}

	bp.SendCount++
	return nil
}

func (p *Pinger2) SendICMP(conn *icmp.PacketConn) error {
	var typ icmp.Type
	if p.ipv4 {
		typ = ipv4.ICMPTypeEcho
	} else {
		typ = ipv6.ICMPTypeEchoRequest
	}

	var dst net.Addr = p.ipaddr
	if p.network == "udp" {
		dst = &net.UDPAddr{IP: p.ipaddr.IP, Zone: p.ipaddr.Zone}
	}

	t := timeToBytes(time.Now())

	bytes, err := (&icmp.Message{
		Type: typ, Code: 0,
		Body: &icmp.Echo{
			ID:   p.id,
			Seq:  p.sequence,
			Data: t,
		},
	}).Marshal(nil)
	if err != nil {
		fmt.Println("err", err)
		return err
	}

	for {
		if _, err := conn.WriteTo(bytes, dst); err != nil {
			fmt.Printf("send error, %v，%v\n", err, err.Error())
			if neterr, ok := err.(*net.OpError); ok {
				if neterr.Err == syscall.ENOBUFS {
					continue
				}
			}
		}
		p.PacketsSent += 1
		p.sequence += 1
		break
	}
	return nil
}

func (bp *BatchPinger) ProcessPacket(recv *packet) error {
	var bytes []byte
	var proto int
	if bp.ipv4 {
		if bp.network == "ip" {
			bytes = ipv4Payload(recv.bytes)
		} else {
			bytes = recv.bytes
		}
		proto = protocolICMP
	} else {
		bytes = recv.bytes
		proto = protocolIPv6ICMP
	}

	var m *icmp.Message
	var err error
	if m, err = icmp.ParseMessage(proto, bytes[:recv.nbytes]); err != nil {
		return fmt.Errorf("Error parsing icmp message")
	}

	if m.Type != ipv4.ICMPTypeEchoReply && m.Type != ipv6.ICMPTypeEchoReply {
		// Not an echo reply, ignore it
		return nil
	}

	body := m.Body.(*icmp.Echo)
	rtt := time.Since(bytesToTime(body.Data[:timeSliceLength]))

	key := strconv.Itoa(body.ID) + ":" +  strconv.Itoa(body.Seq)
	pinger := bp.PackPinger[key]

	pinger.rtts = append(pinger.rtts, rtt)
	pinger.PacketsRecv += 1


	handler := bp.OnRecv
	if handler != nil {
		handler(body)
	}

	return nil
}



func (bp *BatchPinger) finish() {
	handler := bp.OnFinish
	if handler != nil {
		s := bp.Statistics()
		handler(s)
	}
}


func (bp *BatchPinger) Statistics() []*Statistics {
	stSlice := [](*Statistics){}
	for  _, pinger := range bp.pingers{
		x := pinger.Statistics()
		stSlice = append(stSlice, x)
	}
	return stSlice
}

// Statistics returns the statistics of the pinger. This can be run while the
// pinger is running or after it is finished. OnFinish calls this function to
// get it's finished statistics.
func (p *Pinger2) Statistics() *Statistics {
	loss := float64(p.PacketsSent-p.PacketsRecv) / float64(p.PacketsSent) * 100
	var min, max, total time.Duration
	fmt.Println(p.rtts)

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