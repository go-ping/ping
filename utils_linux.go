// +build linux

package ping

import (
	"errors"
	"reflect"
	"syscall"

	"golang.org/x/net/icmp"
)

// Returns the length of an ICMP message.
func (p *Pinger) getMessageLength() int {
	return p.Size + 8
}

// Attempts to match the ID of an ICMP packet.
func (p *Pinger) matchID(ID int) bool {
	// On Linux we can only match ID if we are privileged.
	if p.protocol == "icmp" {
		if ID != p.id {
			return false
		}
	}
	return true
}

func getConnFD(conn *icmp.PacketConn) (fd int) {
	var packetConn reflect.Value

	defer func() {
		if r := recover(); r != nil {
			fd = -1
		}
	}()

	if conn.IPv4PacketConn() != nil {
		packetConn = reflect.ValueOf(conn.IPv4PacketConn().PacketConn)
	} else if conn.IPv6PacketConn() != nil {
		packetConn = reflect.ValueOf(conn.IPv6PacketConn().PacketConn)
	} else {
		return -1
	}

	netFD := reflect.Indirect(reflect.Indirect(packetConn).FieldByName("fd"))
	pollFD := netFD.FieldByName("pfd")
	systemFD := pollFD.FieldByName("Sysfd")
	return int(systemFD.Int())
}

func (c *icmpConn) BindToDevice(ifName string) error {
	if fd := getConnFD(c.c); fd >= 0 {
		return syscall.BindToDevice(fd, ifName)
	}
	return errors.New("bind to interface unsupported")
}
