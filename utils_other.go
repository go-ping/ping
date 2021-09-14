//go:build !linux && !windows
// +build !linux,!windows

package ping

// Returns the length of an ICMP message.
func (p *Pinger) getMessageLength() int {
	const extraSize = 8
	return p.Size + extraSize
}

// Attempts to match the id of an ICMP packet.
func (p *Pinger) matchID(id int) bool {
	return id == p.id
}
