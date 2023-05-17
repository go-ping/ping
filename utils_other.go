//go:build !linux && !windows
// +build !linux,!windows

package ping

import (
	"errors"
)

// Returns the length of an ICMP message.
func (p *Pinger) getMessageLength() int {
	return p.Size + 8
}

// Attempts to match the ID of an ICMP packet.
func (p *Pinger) matchID(ID int) bool {
	return ID == p.id
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
