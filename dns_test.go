package spf

import (
	"flag"
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

func LookupTXT(domain string) (txts []string, err error) {
	domain = strings.ToLower(domain)
	domain = strings.TrimRight(domain, ".")
	return dns.txt[domain], dns.errors[domain]
}

func LookupMX(domain string) (mxs []*net.MX, err error) {
	domain = strings.ToLower(domain)
	domain = strings.TrimRight(domain, ".")
	return dns.mx[domain], dns.errors[domain]
}

func LookupIP(host string) (ips []net.IP, err error) {
	host = strings.ToLower(host)
	host = strings.TrimRight(host, ".")
	return dns.ip[host], dns.errors[host]
}

func LookupAddr(host string) (addrs []string, err error) {
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
