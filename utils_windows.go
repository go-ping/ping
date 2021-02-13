// +build windows

package ping

import (
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
