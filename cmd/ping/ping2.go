package main

import "github.com/vearne/go-ping"
import "fmt"
import "time"
import "golang.org/x/net/icmp"

func main() {

	ipSlice := []string{}
	ipSlice = append(ipSlice, "122.228.74.183")
	ipSlice = append(ipSlice, "wwww.baidu.com")
	ipSlice = append(ipSlice, "github.com")
	ipSlice = append(ipSlice, "121.42.9.143")

	bp, err := ping.NewBatchPinger(ipSlice, 4, time.Second*1, time.Second*20)

	if err != nil {
		fmt.Println(err)
	}

	bp.OnRecv = func(pkt *icmp.Echo) {
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
}
