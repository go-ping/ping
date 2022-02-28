package ping

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

func TestProcessPacket(t *testing.T) {
	pinger := makeTestPinger()
	shouldBe1 := 0
	// this function should be called
	pinger.OnRecv = func(pkt *Packet) {
		shouldBe1++
	}

	uuidEncoded, err := pinger.currentUUID.MarshalBinary()
	if err != nil {
		t.Fatal(fmt.Sprintf("unable to marshal UUID binary: %s", err))
	}
	data := append(timeToBytes(time.Now()), uuidEncoded...)
	if remainSize := pinger.Size - timeSliceLength - trackerLength; remainSize > 0 {
		data = append(data, bytes.Repeat([]byte{1}, remainSize)...)
	}

	body := &icmp.Echo{
		ID:   pinger.id,
		Seq:  pinger.sequence,
		Data: data,
	}
	pinger.awaitingSequences[buildLookupKey(pinger.currentUUID, pinger.sequence)] = time.Now()

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

	err = pinger.processPacket(&pkt)
	AssertNoError(t, err)
	AssertTrue(t, shouldBe1 == 1)
}

func TestProcessPacket_IgnoreNonEchoReplies(t *testing.T) {
	pinger := makeTestPinger()
	shouldBe0 := 0
	// this function should not be called because the tracker is mismatched
	pinger.OnRecv = func(pkt *Packet) {
		shouldBe0++
	}

	currentUUID, err := pinger.currentUUID.MarshalBinary()
	if err != nil {
		t.Fatal(fmt.Sprintf("unable to marshal UUID binary: %s", err))
	}
	data := append(timeToBytes(time.Now()), currentUUID...)
	if remainSize := pinger.Size - timeSliceLength - trackerLength; remainSize > 0 {
		data = append(data, bytes.Repeat([]byte{1}, remainSize)...)
	}

	body := &icmp.Echo{
		ID:   pinger.id,
		Seq:  pinger.sequence,
		Data: data,
	}

	msg := &icmp.Message{
		Type: ipv4.ICMPTypeDestinationUnreachable,
		Code: 0,
		Body: body,
	}

	msgBytes, _ := msg.Marshal(nil)

	pkt := packet{
		nbytes: len(msgBytes),
		bytes:  msgBytes,
		ttl:    24,
	}

	err = pinger.processPacket(&pkt)
	AssertNoError(t, err)
	AssertTrue(t, shouldBe0 == 0)
}

func TestProcessPacket_IDMismatch(t *testing.T) {
	pinger := makeTestPinger()
	pinger.protocol = "icmp" // ID is only checked on "icmp" protocol
	shouldBe0 := 0
	// this function should not be called because the tracker is mismatched
	pinger.OnRecv = func(pkt *Packet) {
		shouldBe0++
	}

	currentUUID, err := pinger.currentUUID.MarshalBinary()
	if err != nil {
		t.Fatal(fmt.Sprintf("unable to marshal UUID binary: %s", err))
	}
	data := append(timeToBytes(time.Now()), currentUUID...)
	if remainSize := pinger.Size - timeSliceLength - trackerLength; remainSize > 0 {
		data = append(data, bytes.Repeat([]byte{1}, remainSize)...)
	}

	body := &icmp.Echo{
		ID:   999999,
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
		ttl:    24,
	}

	err = pinger.processPacket(&pkt)
	AssertNoError(t, err)
	AssertTrue(t, shouldBe0 == 0)
}

func TestProcessPacket_TrackerMismatch(t *testing.T) {
	pinger := makeTestPinger()
	shouldBe0 := 0
	// this function should not be called because the tracker is mismatched
	pinger.OnRecv = func(pkt *Packet) {
		shouldBe0++
	}

	testUUID, err := uuid.New().MarshalBinary()
	if err != nil {
		t.Fatal(fmt.Sprintf("unable to marshal UUID binary: %s", err))
	}
	data := append(timeToBytes(time.Now()), testUUID...)
	if remainSize := pinger.Size - timeSliceLength - trackerLength; remainSize > 0 {
		data = append(data, bytes.Repeat([]byte{1}, remainSize)...)
	}

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
		ttl:    24,
	}

	err = pinger.processPacket(&pkt)
	AssertNoError(t, err)
	AssertTrue(t, shouldBe0 == 0)
}

func TestProcessPacket_LargePacket(t *testing.T) {
	pinger := makeTestPinger()
	pinger.Size = 4096

	currentUUID, err := pinger.currentUUID.MarshalBinary()
	if err != nil {
		t.Fatal(fmt.Sprintf("unable to marshal UUID binary: %s", err))
	}
	data := append(timeToBytes(time.Now()), currentUUID...)
	if remainSize := pinger.Size - timeSliceLength - trackerLength; remainSize > 0 {
		data = append(data, bytes.Repeat([]byte{1}, remainSize)...)
	}

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
		ttl:    24,
	}

	err = pinger.processPacket(&pkt)
	AssertNoError(t, err)
}

func TestProcessPacket_PacketTooSmall(t *testing.T) {
	pinger := makeTestPinger()
	data := []byte("foo")

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
		ttl:    24,
	}

	err := pinger.processPacket(&pkt)
	AssertError(t, err, "")
}

func TestNewPingerValid(t *testing.T) {
	p := New("www.google.com")
	err := p.Resolve()
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
	AssertFalse(t, isIPv4(p.IPAddr().IP))

	p = New("localhost")
	err = p.Resolve()
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
	AssertFalse(t, isIPv4(p.IPAddr().IP))

	p = New("127.0.0.1")
	err = p.Resolve()
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
	AssertFalse(t, isIPv4(p.IPAddr().IP))

	p = New("ipv6.google.com")
	err = p.Resolve()
	AssertNoError(t, err)
	AssertEqualStrings(t, "ipv6.google.com", p.Addr())
	// DNS names should resolve into IP addresses
	AssertNotEqualStrings(t, "ipv6.google.com", p.IPAddr().String())
	AssertFalse(t, isIPv4(p.IPAddr().IP))
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
	AssertFalse(t, isIPv4(p.IPAddr().IP))

	// ipv6 localhost:
	p = New("::1")
	err = p.Resolve()
	AssertNoError(t, err)
	AssertEqualStrings(t, "::1", p.Addr())
	AssertFalse(t, isIPv4(p.IPAddr().IP))
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
	AssertFalse(t, isIPv4(p.IPAddr().IP))
}

func TestNewPingerInvalid(t *testing.T) {
	_, err := NewPinger("127.0.0.0.1")
	AssertError(t, err, "127.0.0.0.1")

	_, err = NewPinger("127..0.0.1")
	AssertError(t, err, "127..0.0.1")

	// The .invalid tld is guaranteed not to exist by RFC2606.
	_, err = NewPinger("wtf.invalid.")
	AssertError(t, err, "wtf.invalid.")

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
	p := New("localhost")
	err = p.Resolve()
	AssertNoError(t, err)
	AssertEqualStrings(t, "localhost", p.Addr())

	// set IPAddr to google
	p.SetIPAddr(googleaddr)
	AssertEqualStrings(t, googleaddr.String(), p.Addr())
}

func TestEmptyIPAddr(t *testing.T) {
	_, err := NewPinger("")
	AssertError(t, err, "empty pinger did not return an error")
}

func TestStatisticsSunny(t *testing.T) {
	// Create a localhost ipv4 pinger
	p := New("localhost")
	err := p.Resolve()
	AssertNoError(t, err)
	AssertEqualStrings(t, "localhost", p.Addr())

	p.PacketsSent = 10
	p.updateStatistics(&Packet{Rtt: time.Duration(1000)})
	p.updateStatistics(&Packet{Rtt: time.Duration(1000)})
	p.updateStatistics(&Packet{Rtt: time.Duration(1000)})
	p.updateStatistics(&Packet{Rtt: time.Duration(1000)})
	p.updateStatistics(&Packet{Rtt: time.Duration(1000)})
	p.updateStatistics(&Packet{Rtt: time.Duration(1000)})
	p.updateStatistics(&Packet{Rtt: time.Duration(1000)})
	p.updateStatistics(&Packet{Rtt: time.Duration(1000)})
	p.updateStatistics(&Packet{Rtt: time.Duration(1000)})
	p.updateStatistics(&Packet{Rtt: time.Duration(1000)})

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
	p := New("localhost")
	err := p.Resolve()
	AssertNoError(t, err)
	AssertEqualStrings(t, "localhost", p.Addr())

	p.PacketsSent = 20
	p.updateStatistics(&Packet{Rtt: time.Duration(10)})
	p.updateStatistics(&Packet{Rtt: time.Duration(1000)})
	p.updateStatistics(&Packet{Rtt: time.Duration(1000)})
	p.updateStatistics(&Packet{Rtt: time.Duration(10000)})
	p.updateStatistics(&Packet{Rtt: time.Duration(1000)})
	p.updateStatistics(&Packet{Rtt: time.Duration(800)})
	p.updateStatistics(&Packet{Rtt: time.Duration(1000)})
	p.updateStatistics(&Packet{Rtt: time.Duration(40)})
	p.updateStatistics(&Packet{Rtt: time.Duration(100000)})
	p.updateStatistics(&Packet{Rtt: time.Duration(1000)})

	stats := p.Statistics()
	if stats.PacketsRecv != 10 {
		t.Errorf("Expected %v, got %v", 10, stats.PacketsRecv)
	}
	if stats.PacketsSent != 20 {
		t.Errorf("Expected %v, got %v", 20, stats.PacketsSent)
	}
	if stats.PacketLoss != 0 {
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
func makeTestPinger() *Pinger {
	pinger := New("127.0.0.1")

	pinger.ipv4 = true
	pinger.addr = "127.0.0.1"
	pinger.protocol = "icmp"
	pinger.id = 123
	pinger.Size = timeSliceLength + trackerLength

	return pinger
}

func AssertNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Errorf("Expected No Error but got %q", err)
	}
}

func AssertError(t *testing.T, err error, info string) {
	t.Helper()
	if err == nil {
		t.Errorf("Expected Error %q but got %q",
			err, info)
	}
}

func AssertEqualStrings(t *testing.T, expected, actual string) {
	t.Helper()
	if expected != actual {
		t.Errorf("Expected %s, got %s", expected, actual)
	}
}

func AssertNotEqualStrings(t *testing.T, expected, actual string) {
	t.Helper()
	if expected == actual {
		t.Errorf("Expected %q, got %q", expected, actual)
	}
}

func AssertTrue(t *testing.T, b bool) {
	t.Helper()
	if !b {
		t.Errorf("Expected True, got False")
	}
}

func AssertFalse(t *testing.T, b bool) {
	t.Helper()
	if b {
		t.Errorf("Expected False, got True")
	}
}

func BenchmarkProcessPacket(b *testing.B) {
	pinger := New("127.0.0.1")

	pinger.ipv4 = true
	pinger.addr = "127.0.0.1"
	pinger.protocol = "ip4:icmp"
	pinger.id = 123

	currentUUID, err := pinger.currentUUID.MarshalBinary()
	if err != nil {
		b.Fatal(fmt.Sprintf("unable to marshal UUID binary: %s", err))
	}
	data := append(timeToBytes(time.Now()), currentUUID...)
	if remainSize := pinger.Size - timeSliceLength - trackerLength; remainSize > 0 {
		data = append(data, bytes.Repeat([]byte{1}, remainSize)...)
	}

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
		ttl:    24,
	}

	for k := 0; k < b.N; k++ {
		_ = pinger.processPacket(&pkt)
	}
}

func TestProcessPacket_IgnoresDuplicateSequence(t *testing.T) {
	pinger := makeTestPinger()
	// pinger.protocol = "icmp" // ID is only checked on "icmp" protocol
	var received, dups, lost int

	pinger.OnRecv = func(pkt *Packet) {
		received++
	}

	pinger.OnDuplicateRecv = func(pkt *Packet) {
		dups++
	}

	pinger.OnLost = func(_ uuid.UUID, _ int, noResponseAfter time.Duration) {
		lost++
	}

	buildPacket := func(ts time.Time) *packet {
		uuidEncoded, err := pinger.currentUUID.MarshalBinary()
		if err != nil {
			t.Fatal(fmt.Sprintf("unable to marshal UUID binary: %s", err))
		}

		data := append(timeToBytes(ts), uuidEncoded...)
		if remainSize := pinger.Size - timeSliceLength - trackerLength; remainSize > 0 {
			data = append(data, bytes.Repeat([]byte{1}, remainSize)...)
		}

		body := &icmp.Echo{
			ID:   123,
			Seq:  0,
			Data: data,
		}
		// register the sequence as sent
		pinger.awaitingSequences[buildLookupKey(pinger.currentUUID, 0)] = ts

		msg := &icmp.Message{
			Type: ipv4.ICMPTypeEchoReply,
			Code: 0,
			Body: body,
		}

		msgBytes, _ := msg.Marshal(nil)

		return &packet{
			nbytes: len(msgBytes),
			bytes:  msgBytes,
			ttl:    24,
		}
	}

	pktInTime := buildPacket(time.Now())
	pktDelayed := buildPacket(time.Now().Add(-pinger.PacketTimeout))

	AssertNoError(t, pinger.processPacket(pktInTime))
	// receive a duplicate
	AssertNoError(t, pinger.processPacket(pktInTime))
	// simulate receiving another package with the same UUID and seq, so basically another duplicate - but as we make it
	// look like as it has been in transfer for the duration of pinger.PacketTimeout, it should not be considered a
	// duplicate but rather a packet that has already been declared lost. Therefore, the lost counter will NOT be
	// increased, as otherwise lost packages would be counted twice in case they actually do arrive but just after their
	// timeout.
	AssertNoError(t, pinger.processPacket(pktDelayed))

	AssertTrue(t, received == 1)
	AssertTrue(t, pinger.PacketsRecv == 1)
	AssertTrue(t, dups == 1)
	AssertTrue(t, pinger.PacketsRecvDuplicates == 1)
	AssertTrue(t, lost == 0)
	AssertTrue(t, pinger.PacketsLost == 0)
}

type testPacketConn struct{}

func (c testPacketConn) Close() error                      { return nil }
func (c testPacketConn) ICMPRequestType() icmp.Type        { return ipv4.ICMPTypeEcho }
func (c testPacketConn) SetFlagTTL() error                 { return nil }
func (c testPacketConn) SetReadDeadline(_ time.Time) error { return nil }
func (c testPacketConn) SetTTL(_ int)                      {}

func (c testPacketConn) ReadFrom(_ []byte) (n int, ttl int, src net.Addr, err error) {
	return 0, 0, nil, nil
}

func (c testPacketConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	return len(b), nil
}

type testPacketConnBadWrite struct {
	testPacketConn
}

func (c testPacketConnBadWrite) WriteTo(_ []byte, _ net.Addr) (int, error) {
	return 0, errors.New("bad write")
}

func TestRunBadWrite(t *testing.T) {
	pinger := New("127.0.0.1")
	pinger.Count = 1

	err := pinger.Resolve()
	AssertNoError(t, err)

	var conn testPacketConnBadWrite

	err = pinger.run(conn)
	AssertTrue(t, err != nil)

	stats := pinger.Statistics()
	AssertTrue(t, stats != nil)
	if stats == nil {
		t.FailNow()
	}
	AssertTrue(t, stats.PacketsSent == 0)
	AssertTrue(t, stats.PacketsRecv == 0)
}

type testPacketConnBadRead struct {
	testPacketConn
}

func (c testPacketConnBadRead) ReadFrom(_ []byte) (n int, ttl int, src net.Addr, err error) {
	return 0, 0, nil, errors.New("bad read")
}

func TestRunBadRead(t *testing.T) {
	pinger := New("127.0.0.1")
	pinger.Count = 1

	err := pinger.Resolve()
	AssertNoError(t, err)

	var conn testPacketConnBadRead

	err = pinger.run(conn)
	AssertTrue(t, err != nil)

	stats := pinger.Statistics()
	AssertTrue(t, stats != nil)
	if stats == nil {
		t.FailNow()
	}
	AssertTrue(t, stats.PacketsSent == 1)
	AssertTrue(t, stats.PacketsRecv == 0)
}

type testPacketConnOK struct {
	testPacketConn
	writeDone int32
	buf       []byte
	dst       net.Addr
}

func (c *testPacketConnOK) WriteTo(b []byte, dst net.Addr) (int, error) {
	c.buf = make([]byte, len(b))
	c.dst = dst
	n := copy(c.buf, b)
	atomic.StoreInt32(&c.writeDone, 1)
	return n, nil
}

func (c *testPacketConnOK) ReadFrom(b []byte) (n int, ttl int, src net.Addr, err error) {
	if atomic.LoadInt32(&c.writeDone) == 0 {
		return 0, 0, nil, nil
	}
	msg, err := icmp.ParseMessage(ipv4.ICMPTypeEcho.Protocol(), c.buf)
	if err != nil {
		return 0, 0, nil, err
	}
	msg.Type = ipv4.ICMPTypeEchoReply
	buf, err := msg.Marshal(nil)
	if err != nil {
		return 0, 0, nil, err
	}
	time.Sleep(10 * time.Millisecond)
	return copy(b, buf), 64, c.dst, nil
}

func TestRunOK(t *testing.T) {
	pinger := New("127.0.0.1")
	pinger.Count = 1

	err := pinger.Resolve()
	AssertNoError(t, err)

	conn := new(testPacketConnOK)

	err = pinger.run(conn)
	AssertTrue(t, err == nil)

	stats := pinger.Statistics()
	AssertTrue(t, stats != nil)
	if stats == nil {
		t.FailNow()
	}
	AssertTrue(t, stats.PacketsSent == 1)
	AssertTrue(t, stats.PacketsRecv == 1)
	AssertTrue(t, stats.MinRtt >= 10*time.Millisecond)
	AssertTrue(t, stats.MinRtt <= 12*time.Millisecond)
}

func TestPinger_LostPackets(t *testing.T) {
	// We configure the pinger to send to packets, that will obviously not being answered because they are black-holed.
	// When then wait for them to be declared lost.
	pinger := makeTestPinger()

	pinger.Interval = 10 * time.Millisecond
	pinger.Count = 2
	pinger.PacketTimeout = 1 * time.Millisecond

	lostPacketsWg := sync.WaitGroup{}
	lostPacketsWg.Add(2)

	pinger.OnLost = func(usedUUID uuid.UUID, sequenceID int, noResponseAfter time.Duration) {
		AssertTrue(t, usedUUID == pinger.currentUUID)
		// Order of the lost packets should be ensured by having set pinger.Interval higher than pinger.PacketTimeout;
		// iterating over the map of outstanding responses in the checkForLostPackets() should therefore not be an issue
		// as always just one packet should be waiting for a response.
		AssertTrue(t, sequenceID == pinger.sequence-1)
		AssertTrue(t, noResponseAfter > 1*time.Millisecond)

		lostPacketsWg.Done()
	}

	AssertNoError(t, pinger.run(testPacketConn{}))

	lostPacketsWg.Wait()

	AssertTrue(t, pinger.PacketsSent == 2)
	AssertTrue(t, pinger.PacketsLost == 2)
	AssertTrue(t, pinger.PacketsRecv == 0)

	stats := pinger.Statistics()

	AssertTrue(t, stats.PacketsLost == 2)
	AssertTrue(t, stats.PacketLoss == 100)
}
