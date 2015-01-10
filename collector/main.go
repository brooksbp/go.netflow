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

	template_cache := nfv9.NewTemplateCache()

	var buf [4096]byte
	for {
		n, _, err := conn.ReadFromUDP(buf[0:])
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		framer := nfv9.NewFramer(bytes.NewBuffer(buf[:n]), template_cache)
		frame, err := framer.ReadFrame()
		if err != nil {
			fmt.Println("Error: ", err, frame)
		}

		for _, fs := range frame.FlowSets {
			switch flowset := fs.(type) {
			case nfv9.TemplateFlowSet:
				break
			case nfv9.DataFlowSet:
				// Print the data.
				if template, ok := template_cache.Get(flowset.FlowSetID); ok {
					i := 0
					for _, field := range template.Fields {
						ty := int(field.Type)
						len := int(field.Length)
						entry := nfv9.FieldMap[ty]
						fmt.Print(entry.Name, ": ", entry.String(flowset.Fields[i:i+len]), " ")
						i += len
					}
					fmt.Print("\n")
				}
				break
			default:
				fmt.Println("Unknown flowset")
			}
		}
	}
}
