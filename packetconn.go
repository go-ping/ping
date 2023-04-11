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
	SetTTL(ttl int)
	SetIfaceIndex(iface string)
}

type icmpConn struct {
	c          *icmp.PacketConn
	ttl        int
	ifaceIndex int
}

func (c *icmpConn) Close() error {
	return c.c.Close()
}

func (c *icmpConn) SetTTL(ttl int) {
	c.ttl = ttl
}

func (c *icmpConn) SetIfaceIndex(iface string) {
	i, err := net.InterfaceByName(iface)
	if err != nil {
		c.ifaceIndex = 0
	}
	c.ifaceIndex = i.Index
}

func (c *icmpConn) SetReadDeadline(t time.Time) error {
	return c.c.SetReadDeadline(t)
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
	ttl := -1
	n, cm, src, err := c.c.IPv4PacketConn().ReadFrom(b)
	if cm != nil {
		ttl = cm.TTL
	}
	return n, ttl, src, err
}

func (c icmpv4Conn) ICMPRequestType() icmp.Type {
	return ipv4.ICMPTypeEcho
}

func (c *icmpv4Conn) WriteTo(b []byte, dst net.Addr) (int, error) {
	if err := c.c.IPv4PacketConn().SetTTL(c.ttl); err != nil {
		return 0, err
	}
	var cm *ipv4.ControlMessage
	if 1 <= c.ifaceIndex {
		// set interface
		if err := c.c.IPv4PacketConn().SetControlMessage(ipv4.FlagInterface, true); err != nil {
			return 0, err
		}
		cm = &ipv4.ControlMessage{IfIndex: c.ifaceIndex}
	}

	return c.c.IPv4PacketConn().WriteTo(b, cm, dst)
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
	ttl := -1
	n, cm, src, err := c.c.IPv6PacketConn().ReadFrom(b)
	if cm != nil {
		ttl = cm.HopLimit
	}
	return n, ttl, src, err
}

func (c icmpV6Conn) ICMPRequestType() icmp.Type {
	return ipv6.ICMPTypeEchoRequest
}

func (c *icmpV6Conn) WriteTo(b []byte, dst net.Addr) (int, error) {
	if err := c.c.IPv6PacketConn().SetHopLimit(c.ttl); err != nil {
		return 0, err
	}
	var cm *ipv6.ControlMessage
	if 1 <= c.ifaceIndex {
		// set interface
		if err := c.c.IPv6PacketConn().SetControlMessage(ipv6.FlagInterface, true); err != nil {
			return 0, err
		}
		cm = &ipv6.ControlMessage{IfIndex: c.ifaceIndex}
	}

	return c.c.IPv6PacketConn().WriteTo(b, cm, dst)
}
