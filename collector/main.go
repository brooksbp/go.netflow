package main

import (
	"bytes"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/brooksbp/go.netflow/pkg/net2"
	"github.com/brooksbp/go.netflow/pkg/nfv9"
)

var (
	flagListen = flag.String("listen", ":9999", "host:port to listen on.")
)

type LookupAddrCacheEntry struct {
	names []string
	ts    time.Time
}
type LookupAddrCache struct {
	addrs map[string]*LookupAddrCacheEntry
}

const LookupAddrCacheTime = 5 * time.Minute

func (lac *LookupAddrCache) Get(ip string) (*[]string, bool) {
	if lac.addrs == nil {
		lac.addrs = make(map[string]*LookupAddrCacheEntry)
	}
	now := time.Now()
	entry, ok := lac.addrs[ip]
	if !ok || (ok && (now.After(entry.ts.Add(LookupAddrCacheTime)))) {
		name, err := net.LookupAddr(ip)
		if err != nil {
			return nil, false
		}
		lac.addrs[ip] = &LookupAddrCacheEntry{
			names: name,
			ts:    now,
		}
		return &lac.addrs[ip].names, true
	}
	return &entry.names, true
}

var lookup_addr_cache LookupAddrCache

func PrintDataFlowSet(dfs *nfv9.DataFlowSet, tc *nfv9.TemplateCache) {
	template, ok := tc.Get(dfs.FlowSetID)
	if !ok {
		return
	}
	for _, record := range dfs.Records {
		var i int
		var protocol string
		for _, field := range template.Fields {
			ty := int(field.Type)
			len := int(field.Length)

			entry := nfv9.FieldMap[ty]

			data := record.Fields[i : i+len]
			dataStr := entry.String(data)

			i += len

			fmt.Print(entry.Name, ": ")
			switch entry.Name {
			case "IPV4_SRC_ADDR":
				fallthrough
			case "IPV4_DST_ADDR":
				fallthrough
			case "IPV4_NEXT_HOP":
				if names, ok := lookup_addr_cache.Get(dataStr); ok {
					fmt.Print(*names)
					fmt.Print(" (", dataStr, ")")
				} else {
					fmt.Print(dataStr)
				}
			case "PROTOCOL":
				protocol = dataStr
				fmt.Print(dataStr)
			case "L4_SRC_PORT":
				fallthrough
			case "L4_DST_PORT":
				mapped := false
				if port, err := strconv.Atoi(dataStr); err == nil {
					if portMapEntry, ok := net2.TCPUDPPortMap[port]; ok {
						if proto, ok := portMapEntry[protocol]; ok {
							fmt.Print(proto)
							mapped = true
						}
					}
				}
				if !mapped {
					fmt.Print(dataStr)
				}
			default:
				fmt.Print(dataStr)
			}
			fmt.Print(" ")
		}
		fmt.Print("\n\n")
	}
}

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
		fmt.Println(frame.Header.String())
		for _, fs := range frame.FlowSets {
			switch flowset := fs.(type) {
			case nfv9.TemplateFlowSet:
				break
			case nfv9.DataFlowSet:
				PrintDataFlowSet(&flowset, template_cache)
				break
			default:
				fmt.Println("Unknown flowset")
			}
		}
	}
}
