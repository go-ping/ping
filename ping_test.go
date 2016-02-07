package ping

import (
	"net"
	"runtime/debug"
	"testing"
	"time"
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
