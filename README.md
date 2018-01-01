# go-ping
[![GoDoc](https://godoc.org/github.com/sparrc/go-ping?status.svg)](https://godoc.org/github.com/sparrc/go-ping)
[![Circle CI](https://circleci.com/gh/sparrc/go-ping.svg?style=svg)](https://circleci.com/gh/sparrc/go-ping)

ICMP Ping library for Go, inspired by
[go-fastping](https://github.com/tatsushid/go-fastping)

Here is a very simple example that sends & receives 3 packets:

```go
pinger, err := ping.NewPinger("www.google.com")
if err != nil {
        panic(err)
}
pinger.Count = 3
pinger.Run() // blocks until finished
stats := pinger.Statistics() // get send/receive/rtt stats
```

Here is an example that emulates the unix ping command:

```go
pinger, err := ping.NewPinger("www.google.com")
if err != nil {
        panic(err)
}

pinger.OnRecv = func(pkt *ping.Packet) {
        fmt.Printf("%d bytes from %s: icmp_seq=%d time=%v\n",
                pkt.Nbytes, pkt.IPAddr, pkt.Seq, pkt.Rtt)
}
pinger.OnFinish = func(stats *ping.Statistics) {
        fmt.Printf("\n--- %s ping statistics ---\n", stats.Addr)
        fmt.Printf("%d packets transmitted, %d packets received, %v%% packet loss\n",
                stats.PacketsSent, stats.PacketsRecv, stats.PacketLoss)
        fmt.Printf("round-trip min/avg/max/stddev = %v/%v/%v/%v\n",
                stats.MinRtt, stats.AvgRtt, stats.MaxRtt, stats.StdDevRtt)
}

fmt.Printf("PING %s (%s):\n", pinger.Addr(), pinger.IPAddr())
pinger.Run()
```
another example
```
	ipSlice := []string{}
	ipSlice = append(ipSlice, "122.228.74.183")
	ipSlice = append(ipSlice, "wwww.baidu.com")
	ipSlice = append(ipSlice, "github.com")
	ipSlice = append(ipSlice, "121.42.9.143")

	bp, err := ping.NewBatchPinger(ipSlice, 4, time.Second*1, time.Second*10)

	if err != nil {
		fmt.Println(err)
	}

	bp.OnRecv = func(pkt *icmp.Echo) {
		//
		fmt.Printf("recv icmp_id=%d, icmp_seq=%d\n",
			pkt.ID, pkt.Seq)
	}

	bp.OnFinish = func(stSlice []*ping.Statistics) {
		for _, st := range stSlice{
			fmt.Printf("\n--- %s ping statistics ---\n", st.Addr)
			fmt.Printf("%d packets transmitted, %d packets received, %v%% packet loss\n",
				st.PacketsSent, st.PacketsRecv, st.PacketLoss)
			fmt.Printf("round-trip min/avg/max/stddev = %v/%v/%v/%v\n",
				st.MinRtt, st.AvgRtt, st.MaxRtt, st.StdDevRtt)
		}

	}

	bp.Run()
```
It sends ICMP packet(s) and waits for a response. If it receives a response,
it calls the "receive" callback. When it's finished, it calls the "finish"
callback.

For a full ping example, see
one address
[cmd/ping/ping.go](https://github.com/vearne/go-ping/blob/master/cmd/ping/ping.go)
multiple addresses
[cmd/ping/ping2.go](https://github.com/vearne/go-ping/blob/master/cmd/ping/ping2.go)

## Installation:

```
go get github.com/vearne/go-ping
```

To install the native Go ping executable:

```bash
go get github.com/vearne/go-ping/...
$GOPATH/bin/ping
```

## Note on Linux Support:

This library attempts to send an
"unprivileged" ping via UDP. On linux, this must be enabled by setting

```
sudo sysctl -w net.ipv4.ping_group_range="0   2147483647"
```

If you do not wish to do this, you can set `pinger.SetPrivileged(true)` and
use setcap to allow your binary using go-ping to bind to raw sockets
(or just run as super-user):

```
setcap cap_net_raw=+ep /bin/goping-binary
```

See [this blog](https://sturmflut.github.io/linux/ubuntu/2015/01/17/unprivileged-icmp-sockets-on-linux/)
and [the Go icmp library](https://godoc.org/golang.org/x/net/icmp) for more details.
