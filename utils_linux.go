//go:build linux
// +build linux

package ping

// Returns the length of an ICMP message.
func (p *Pinger) getMessageLength() int {
	const extraSize = 8
	return p.Size + extraSize
}

// Attempts to match the id of an ICMP packet.
func (p *Pinger) matchID(id int) bool {
	if p.protocol != icmpStr {
		return true
	}
	// On Linux we can only match ID if we are privileged.
	return id == p.id
}
