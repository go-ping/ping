//go:build windows
// +build windows

package ping

import (
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// Returns the length of an ICMP message, plus the IP packet header.
func (p *Pinger) getMessageLength() int {
	const extraSize = 8
	if p.ipv4 {
		return p.Size + extraSize + ipv4.HeaderLen
	}
	return p.Size + extraSize + ipv6.HeaderLen
}

// Attempts to match the id of an ICMP packet.
func (p *Pinger) matchID(id int) bool {
	return id == p.id
}
