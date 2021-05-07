package ping

import (
	"net"
	"runtime"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type packetConn interface {
	Close() error
	ICMPRequestType() icmp.Type
	ReadFrom(b []byte) (n int, ttl int, src net.Addr, err error)
	SetFlagTTL() error
	SetReadDeadline(t time.Time) error
	WriteTo(b []byte, dst net.Addr) (int, error)
}

type icmpConn struct {
	c *icmp.PacketConn
}

func (c *icmpConn) Close() error {
	return c.c.Close()
}

func (c *icmpConn) SetReadDeadline(t time.Time) error {
	return c.c.SetReadDeadline(t)
}

func (c *icmpConn) WriteTo(b []byte, dst net.Addr) (int, error) {
	return c.c.WriteTo(b, dst)
}

type icmpv4Conn struct {
	icmpConn
}

func (c *icmpv4Conn) SetFlagTTL() error {
	err := c.c.IPv4PacketConn().SetControlMessage(ipv4.FlagTTL, true)
	if runtime.GOOS == "windows" {
		return nil
	}
	return err
}

func (c *icmpv4Conn) ReadFrom(b []byte) (int, int, net.Addr, error) {
	var ttl int
	n, cm, src, err := c.c.IPv4PacketConn().ReadFrom(b)
	if cm != nil {
		ttl = cm.TTL
	}
	return n, ttl, src, err
}

func (c icmpv4Conn) ICMPRequestType() icmp.Type {
	return ipv4.ICMPTypeEcho
}

type icmpV6Conn struct {
	icmpConn
}

func (c *icmpV6Conn) SetFlagTTL() error {
	err := c.c.IPv6PacketConn().SetControlMessage(ipv6.FlagHopLimit, true)
	if runtime.GOOS == "windows" {
		return nil
	}
	return err
}

func (c *icmpV6Conn) ReadFrom(b []byte) (int, int, net.Addr, error) {
	var ttl int
	n, cm, src, err := c.c.IPv6PacketConn().ReadFrom(b)
	if cm != nil {
		ttl = cm.HopLimit
	}
	return n, ttl, src, err
}

func (c icmpV6Conn) ICMPRequestType() icmp.Type {
	return ipv6.ICMPTypeEchoRequest
}

type icmpV4RawConn struct {
	netConn net.PacketConn
	c       *ipv4.RawConn
	src     net.IP
}

func newIcmpV4RawConn(src string) (*icmpV4RawConn, error) {
	netConn, err := net.ListenPacket("ip4:icmp", src)
	if err != nil {
		return nil, err
	}

	c, err := ipv4.NewRawConn(netConn)
	if err != nil {
		_ = netConn.Close()
		return nil, err
	}

	return &icmpV4RawConn{netConn: netConn, c: c, src: net.ParseIP(src)}, nil
}

func (c *icmpV4RawConn) Close() error {
	err := c.c.Close()
	err2 := c.netConn.Close()
	if err != nil {
		return err
	}
	return err2
}

func (c *icmpV4RawConn) SetFlagTTL() error {
	err := c.c.SetControlMessage(ipv4.FlagTTL, true)
	if runtime.GOOS == "windows" {
		return nil
	}
	return err
}

func (c *icmpV4RawConn) ReadFrom(b []byte) (int, int, net.Addr, error) {
	h, p, cm, err := c.c.ReadFrom(b)
	if err != nil {
		return 0, 0, nil, err
	}

	copy(b, p)

	ttl := 0
	if cm != nil {
		ttl = cm.TTL
	}

	return len(p), ttl, &net.IPAddr{IP: h.Src}, nil
}

func (c icmpV4RawConn) ICMPRequestType() icmp.Type {
	return ipv4.ICMPTypeEcho
}

func (c *icmpV4RawConn) SetReadDeadline(t time.Time) error {
	return c.c.SetReadDeadline(t)
}

func (c *icmpV4RawConn) WriteTo(b []byte, dst net.Addr) (int, error) {
	header := ipv4.Header{
		Version:  ipv4.Version,
		Len:      ipv4.HeaderLen,
		Protocol: ipv4.ICMPTypeEcho.Protocol(),
		TotalLen: ipv4.HeaderLen + len(b),
		TTL:      64,
		Dst:      net.ParseIP(dst.String()),
		Src:      c.src,
		Flags:    ipv4.DontFragment,
	}

	return len(b), c.c.WriteTo(&header, b, nil)
}
