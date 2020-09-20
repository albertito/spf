package spf

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
)

// DNS overrides for testing.

type DNS struct {
	txt    map[string][]string
	mx     map[string][]*net.MX
	ip     map[string][]net.IP
	addr   map[string][]string
	errors map[string]error
}

func NewDNS() DNS {
	return DNS{
		txt:    map[string][]string{},
		mx:     map[string][]*net.MX{},
		ip:     map[string][]net.IP{},
		addr:   map[string][]string{},
		errors: map[string]error{},
	}
}

// Single global variable that the overridden resolvers use.
// This way it's easier to get a clean slate between tests.
var dns DNS

func LookupTXT(ctx context.Context, domain string) (txts []string, err error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	domain = strings.ToLower(domain)
	domain = strings.TrimRight(domain, ".")
	return dns.txt[domain], dns.errors[domain]
}

func LookupMX(ctx context.Context, domain string) (mxs []*net.MX, err error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	domain = strings.ToLower(domain)
	domain = strings.TrimRight(domain, ".")
	return dns.mx[domain], dns.errors[domain]
}

func LookupIP(ctx context.Context, net, host string) (ips []net.IP, err error) {
	if net != "ip" {
		panic(fmt.Sprintf("got net %q, expected ip", net))
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	host = strings.ToLower(host)
	host = strings.TrimRight(host, ".")
	return dns.ip[host], dns.errors[host]
}

func LookupAddr(ctx context.Context, host string) (addrs []string, err error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	host = strings.ToLower(host)
	host = strings.TrimRight(host, ".")
	return dns.addr[host], dns.errors[host]
}

func TestMain(m *testing.M) {
	dns = NewDNS()

	lookupTXT = LookupTXT
	lookupMX = LookupMX
	lookupIP = LookupIP
	lookupAddr = LookupAddr

	flag.Parse()
	os.Exit(m.Run())
}
