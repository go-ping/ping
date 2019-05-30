package ping

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"runtime/debug"
	"testing"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

func TestNewPingerValid(t *testing.T) {
	p, err := NewPinger("www.google.com")
	AssertNoError(t, err)
	AssertEqualStrings(t, "www.google.com", p.Addr())
	// DNS names should resolve into IP addresses
	AssertNotEqualStrings(t, "www.google.com", p.IPAddr().String())
	AssertTrue(t, isIPv4(p.IPAddr().IP))
	AssertFalse(t, p.Privileged())
	// Test that SetPrivileged works
	p.SetPrivileged(true)
	AssertTrue(t, p.Privileged())
	// Test setting to ipv4 address
	err = p.SetAddr("www.google.com")
	AssertNoError(t, err)
	AssertTrue(t, isIPv4(p.IPAddr().IP))
	// Test setting to ipv6 address
	err = p.SetAddr("ipv6.google.com")
	AssertNoError(t, err)
	AssertTrue(t, isIPv6(p.IPAddr().IP))

	p, err = NewPinger("localhost")
	AssertNoError(t, err)
	AssertEqualStrings(t, "localhost", p.Addr())
	// DNS names should resolve into IP addresses
	AssertNotEqualStrings(t, "localhost", p.IPAddr().String())
	AssertTrue(t, isIPv4(p.IPAddr().IP))
	AssertFalse(t, p.Privileged())
	// Test that SetPrivileged works
	p.SetPrivileged(true)
	AssertTrue(t, p.Privileged())
	// Test setting to ipv4 address
	err = p.SetAddr("www.google.com")
	AssertNoError(t, err)
	AssertTrue(t, isIPv4(p.IPAddr().IP))
	// Test setting to ipv6 address
	err = p.SetAddr("ipv6.google.com")
	AssertNoError(t, err)
	AssertTrue(t, isIPv6(p.IPAddr().IP))

	p, err = NewPinger("127.0.0.1")
	AssertNoError(t, err)
	AssertEqualStrings(t, "127.0.0.1", p.Addr())
	AssertTrue(t, isIPv4(p.IPAddr().IP))
	AssertFalse(t, p.Privileged())
	// Test that SetPrivileged works
	p.SetPrivileged(true)
	AssertTrue(t, p.Privileged())
	// Test setting to ipv4 address
	err = p.SetAddr("www.google.com")
	AssertNoError(t, err)
	AssertTrue(t, isIPv4(p.IPAddr().IP))
	// Test setting to ipv6 address
	err = p.SetAddr("ipv6.google.com")
	AssertNoError(t, err)
	AssertTrue(t, isIPv6(p.IPAddr().IP))

	p, err = NewPinger("ipv6.google.com")
	AssertNoError(t, err)
	AssertEqualStrings(t, "ipv6.google.com", p.Addr())
	// DNS names should resolve into IP addresses
	AssertNotEqualStrings(t, "ipv6.google.com", p.IPAddr().String())
	AssertTrue(t, isIPv6(p.IPAddr().IP))
	AssertFalse(t, p.Privileged())
	// Test that SetPrivileged works
	p.SetPrivileged(true)
	AssertTrue(t, p.Privileged())
	// Test setting to ipv4 address
	err = p.SetAddr("www.google.com")
	AssertNoError(t, err)
	AssertTrue(t, isIPv4(p.IPAddr().IP))
	// Test setting to ipv6 address
	err = p.SetAddr("ipv6.google.com")
	AssertNoError(t, err)
	AssertTrue(t, isIPv6(p.IPAddr().IP))

	// ipv6 localhost:
	p, err = NewPinger("::1")
	AssertNoError(t, err)
	AssertEqualStrings(t, "::1", p.Addr())
	AssertTrue(t, isIPv6(p.IPAddr().IP))
	AssertFalse(t, p.Privileged())
	// Test that SetPrivileged works
	p.SetPrivileged(true)
	AssertTrue(t, p.Privileged())
	// Test setting to ipv4 address
	err = p.SetAddr("www.google.com")
	AssertNoError(t, err)
	AssertTrue(t, isIPv4(p.IPAddr().IP))
	// Test setting to ipv6 address
	err = p.SetAddr("ipv6.google.com")
	AssertNoError(t, err)
	AssertTrue(t, isIPv6(p.IPAddr().IP))
}

func TestNewPingerInvalid(t *testing.T) {
	_, err := NewPinger("127.0.0.0.1")
	AssertError(t, err, "127.0.0.0.1")

	_, err = NewPinger("127..0.0.1")
	AssertError(t, err, "127..0.0.1")

	_, err = NewPinger("wtf")
	AssertError(t, err, "wtf")

	_, err = NewPinger(":::1")
	AssertError(t, err, ":::1")

	_, err = NewPinger("ipv5.google.com")
	AssertError(t, err, "ipv5.google.com")
}

func TestSetIPAddr(t *testing.T) {
	googleaddr, err := net.ResolveIPAddr("ip", "www.google.com")
	if err != nil {
		t.Fatal("Can't resolve www.google.com, can't run tests")
	}

	// Create a localhost ipv4 pinger
	p, err := NewPinger("localhost")
	AssertNoError(t, err)
	AssertEqualStrings(t, "localhost", p.Addr())

	// set IPAddr to google
	p.SetIPAddr(googleaddr)
	AssertEqualStrings(t, googleaddr.String(), p.Addr())
}

func TestStatisticsSunny(t *testing.T) {
	// Create a localhost ipv4 pinger
	p, err := NewPinger("localhost")
	AssertNoError(t, err)
	AssertEqualStrings(t, "localhost", p.Addr())

	p.PacketsSent = 10
	p.PacketsRecv = 10
	p.rtts = []time.Duration{
		time.Duration(1000),
		time.Duration(1000),
		time.Duration(1000),
		time.Duration(1000),
		time.Duration(1000),
		time.Duration(1000),
		time.Duration(1000),
		time.Duration(1000),
		time.Duration(1000),
		time.Duration(1000),
	}

	stats := p.Statistics()
	if stats.PacketsRecv != 10 {
		t.Errorf("Expected %v, got %v", 10, stats.PacketsRecv)
	}
	if stats.PacketsSent != 10 {
		t.Errorf("Expected %v, got %v", 10, stats.PacketsSent)
	}
	if stats.PacketLoss != 0 {
		t.Errorf("Expected %v, got %v", 0, stats.PacketLoss)
	}
	if stats.MinRtt != time.Duration(1000) {
		t.Errorf("Expected %v, got %v", time.Duration(1000), stats.MinRtt)
	}
	if stats.MaxRtt != time.Duration(1000) {
		t.Errorf("Expected %v, got %v", time.Duration(1000), stats.MaxRtt)
	}
	if stats.AvgRtt != time.Duration(1000) {
		t.Errorf("Expected %v, got %v", time.Duration(1000), stats.AvgRtt)
	}
	if stats.StdDevRtt != time.Duration(0) {
		t.Errorf("Expected %v, got %v", time.Duration(0), stats.StdDevRtt)
	}
}

func TestStatisticsLossy(t *testing.T) {
	// Create a localhost ipv4 pinger
	p, err := NewPinger("localhost")
	AssertNoError(t, err)
	AssertEqualStrings(t, "localhost", p.Addr())

	p.PacketsSent = 20
	p.PacketsRecv = 10
	p.rtts = []time.Duration{
		time.Duration(10),
		time.Duration(1000),
		time.Duration(1000),
		time.Duration(10000),
		time.Duration(1000),
		time.Duration(800),
		time.Duration(1000),
		time.Duration(40),
		time.Duration(100000),
		time.Duration(1000),
	}

	stats := p.Statistics()
	if stats.PacketsRecv != 10 {
		t.Errorf("Expected %v, got %v", 10, stats.PacketsRecv)
	}
	if stats.PacketsSent != 20 {
		t.Errorf("Expected %v, got %v", 20, stats.PacketsSent)
	}
	if stats.PacketLoss != 50 {
		t.Errorf("Expected %v, got %v", 50, stats.PacketLoss)
	}
	if stats.MinRtt != time.Duration(10) {
		t.Errorf("Expected %v, got %v", time.Duration(10), stats.MinRtt)
	}
	if stats.MaxRtt != time.Duration(100000) {
		t.Errorf("Expected %v, got %v", time.Duration(100000), stats.MaxRtt)
	}
	if stats.AvgRtt != time.Duration(11585) {
		t.Errorf("Expected %v, got %v", time.Duration(11585), stats.AvgRtt)
	}
	if stats.StdDevRtt != time.Duration(29603) {
		t.Errorf("Expected %v, got %v", time.Duration(29603), stats.StdDevRtt)
	}
}

// Test helpers
func AssertNoError(t *testing.T, err error) {
	if err != nil {
		t.Errorf("Expected No Error but got %s, Stack:\n%s",
			err, string(debug.Stack()))
	}
}

func AssertError(t *testing.T, err error, info string) {
	if err == nil {
		t.Errorf("Expected Error but got %s, %s, Stack:\n%s",
			err, info, string(debug.Stack()))
	}
}

func AssertEqualStrings(t *testing.T, expected, actual string) {
	if expected != actual {
		t.Errorf("Expected %s, got %s, Stack:\n%s",
			expected, actual, string(debug.Stack()))
	}
}

func AssertNotEqualStrings(t *testing.T, expected, actual string) {
	if expected == actual {
		t.Errorf("Expected %s, got %s, Stack:\n%s",
			expected, actual, string(debug.Stack()))
	}
}

func AssertTrue(t *testing.T, b bool) {
	if !b {
		t.Errorf("Expected True, got False, Stack:\n%s", string(debug.Stack()))
	}
}

func AssertFalse(t *testing.T, b bool) {
	if b {
		t.Errorf("Expected False, got True, Stack:\n%s", string(debug.Stack()))
	}
}

func BenchmarkProcessPacket(b *testing.B) {
	pinger, _ := NewPinger("127.0.0.1")

	pinger.ipv4 = true
	pinger.addr = "127.0.0.1"
	pinger.network = "ip4:icmp"
	pinger.id = 123
	pinger.Tracker = 456

	t := append(timeToBytes(time.Now()), intToBytes(pinger.Tracker)...)
	if remainSize := pinger.Size - timeSliceLength - trackerLength; remainSize > 0 {
		t = append(t, bytes.Repeat([]byte{1}, remainSize)...)
	}

	body := &icmp.Echo{
		ID:   pinger.id,
		Seq:  pinger.sequence,
		Data: t,
	}

	msg := &icmp.Message{
		Type: ipv4.ICMPTypeEchoReply,
		Code: 0,
		Body: body,
	}

	msgBytes, _ := msg.Marshal(nil)

	pkt := packet{
		nbytes: len(msgBytes),
		bytes:  msgBytes,
		ttl:    24,
	}

	for k := 0; k < b.N; k++ {
		pinger.processPacket(&pkt)
	}
}

func BenchmarkProcessPacketOld(b *testing.B) {
	pinger, _ := NewPinger("127.0.0.1")

	pinger.ipv4 = true
	pinger.addr = "127.0.0.1"
	pinger.network = "ip4:icmp"
	pinger.id = 123
	pinger.Tracker = 456

	type IcmpData struct {
		Bytes   []byte
		Tracker int64
	}

	byteSliceOfSize := func(n int) []byte {
		b := make([]byte, n)
		for i := 0; i < len(b); i++ {
			b[i] = 1
		}

		return b
	}

	t := timeToBytes(time.Now())
	if pinger.Size-timeSliceLength != 0 {
		t = append(t, byteSliceOfSize(pinger.Size-timeSliceLength)...)
	}

	data, _ := json.Marshal(IcmpData{Bytes: t, Tracker: pinger.Tracker})

	body := &icmp.Echo{
		ID:   pinger.id,
		Seq:  pinger.sequence,
		Data: data,
	}

	msg := &icmp.Message{
		Type: ipv4.ICMPTypeEchoReply,
		Code: 0,
		Body: body,
	}

	msgBytes, _ := msg.Marshal(nil)

	pkt := packet{
		nbytes: len(msgBytes),
		bytes:  msgBytes,
	}

	processPacket := func(p *Pinger, recv *packet) error {
		var bytes []byte
		var proto int
		if p.ipv4 {
			if p.network == "ip" {
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
		// If we are priviledged, we can match icmp.ID
		if p.network == "ip" {
			// Check if reply from same ID
			if body.ID != p.id {
				return nil
			}
		} else {
			// If we are not priviledged, we cannot set ID - require kernel ping_table map
			// need to use contents to identify packet
			data := IcmpData{}
			err := json.Unmarshal(body.Data, &data)
			if err != nil {
				return err
			}
			if data.Tracker != p.Tracker {
				return nil
			}
		}

		outPkt := &Packet{
			Nbytes: recv.nbytes,
			IPAddr: p.ipaddr,
			Addr:   p.addr,
			Ttl:    recv.ttl,
		}

		switch pkt := m.Body.(type) {
		case *icmp.Echo:
			data := IcmpData{}
			err := json.Unmarshal(m.Body.(*icmp.Echo).Data, &data)
			if err != nil {
				return err
			}
			outPkt.Rtt = time.Since(bytesToTime(data.Bytes))
			outPkt.Seq = pkt.Seq
			p.PacketsRecv++
		default:
			// Very bad, not sure how this can happen
			return fmt.Errorf("Error, invalid ICMP echo reply. Body type: %T, %s",
				pkt, pkt)
		}

		p.rtts = append(p.rtts, outPkt.Rtt)
		handler := p.OnRecv
		if handler != nil {
			handler(outPkt)
		}

		return nil
	}

	for k := 0; k < b.N; k++ {
		processPacket(pinger, &pkt)
	}
}
