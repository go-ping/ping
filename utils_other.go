// +build !linux,!windows

package ping

import "errors"

// Returns the length of an ICMP message.
func (p *Pinger) getMessageLength() int {
	return p.Size + 8
}

// Attempts to match the ID of an ICMP packet.
func (p *Pinger) matchID(ID int) bool {
	if ID != p.id {
		return false
	}
	return true
}

func (c *icmpConn) BindToDevice(ifName string) error {
	return errors.New("bind to interface unsupported")
}
