package main

import (
	"bytes"
	"flag"
	"fmt"
	"net"
	"os"

	"github.com/brooksbp/go.netflow/pkg/nfv9"
)

var (
	flagListen = flag.String("listen", ":9999", "host:port to listen on.")
)

func main() {
	flag.Parse()

	listenStr := *flagListen

	addr, err := net.ResolveUDPAddr("udp", listenStr)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	s := nfv9.NewSession()
	var buf [4096]byte
	for {
		n, _, err := conn.ReadFromUDP(buf[0:])
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		framer := nfv9.NewFramer(bytes.NewBuffer(buf[:n]), s)
		frame, err := framer.ReadFrame()
		if err != nil {
			fmt.Println("Error: ", err, frame)
		}
	}
}
