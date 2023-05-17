//go:build windows
// +build windows

package ping

import (
	"errors"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// Returns the length of an ICMP message, plus the IP packet header.
func (p *Pinger) getMessageLength() int {
	if p.ipv4 {
		return p.Size + 8 + ipv4.HeaderLen
	}
	return p.Size + 8 + ipv6.HeaderLen
}

// Attempts to match the ID of an ICMP packet.
func (p *Pinger) matchID(ID int) bool {
	if ID != p.id {
		return false
	}
	return true
}

// SetMark sets the SO_MARK socket option on outgoing ICMP packets.
// Setting this option requires CAP_NET_ADMIN.
func (c *icmpConn) SetMark(mark uint) error {
	return errors.New("setting SO_MARK socket option is not supported on this platform")
}

// SetMark sets the SO_MARK socket option on outgoing ICMP packets.
// Setting this option requires CAP_NET_ADMIN.
func (c *icmpv4Conn) SetMark(mark uint) error {
	return errors.New("setting SO_MARK socket option is not supported on this platform")
}

// SetMark sets the SO_MARK socket option on outgoing ICMP packets.
// Setting this option requires CAP_NET_ADMIN.
func (c *icmpV6Conn) SetMark(mark uint) error {
	return errors.New("setting SO_MARK socket option is not supported on this platform")
}
