// +build ignore

// Command line tool to perform SPF checks.
//
// For development and experimentation only.
// No backwards compatibility guarantees.
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"

	"blitiri.com.ar/go/spf"
)

var (
	debug   = flag.Bool("debug", false, "include debugging output")
	dnsAddr = flag.String("dns_addr", "", "address of the DNS server to use")
)

func main() {
	flag.Usage = func() {
		fmt.Printf("Usage: spf-check [options] 1.2.3.4 name@sender.com\n\n")
		flag.PrintDefaults()
	}

	flag.Parse()
	args := flag.Args()
	if len(args) < 2 {
		flag.Usage()
		os.Exit(1)
	}

	opts := []spf.Option{}
	if *debug {
		traceF := func(f string, a ...interface{}) {
			fmt.Printf("debug: "+f+"\n", a...)
		}
		opts = append(opts, spf.WithTraceFunc(traceF))
	}

	if *dnsAddr != "" {
		dialFunc := func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, *dnsAddr)
		}
		opts = append(opts, spf.WithResolver(
			&net.Resolver{
				PreferGo: true,
				Dial:     dialFunc,
			}))
	}

	ip := net.ParseIP(args[0])
	sender := args[1]
	fmt.Printf("Sender: %v\n", sender)
	fmt.Printf("IP: %v\n", ip)

	r, err := spf.CheckHostWithSender(ip, "", sender, opts...)
	fmt.Printf("Result: %v\n", r)
	fmt.Printf("Error: %v\n", err)
}
