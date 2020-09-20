package spf

import (
	"context"
	"net"
	"strings"
)

// DNS overrides for testing.

type TestResolver struct {
	txt    map[string][]string
	mx     map[string][]*net.MX
	ip     map[string][]net.IP
	addr   map[string][]string
	errors map[string]error
}

func NewResolver() *TestResolver {
	return &TestResolver{
		txt:    map[string][]string{},
		mx:     map[string][]*net.MX{},
		ip:     map[string][]net.IP{},
		addr:   map[string][]string{},
		errors: map[string]error{},
	}
}

func NewDefaultResolver() *TestResolver {
	dns := NewResolver()
	defaultResolver = dns
	return dns
}

func (r *TestResolver) LookupTXT(ctx context.Context, domain string) (txts []string, err error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	domain = strings.ToLower(domain)
	domain = strings.TrimRight(domain, ".")
	return r.txt[domain], r.errors[domain]
}

func (r *TestResolver) LookupMX(ctx context.Context, domain string) (mxs []*net.MX, err error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	domain = strings.ToLower(domain)
	domain = strings.TrimRight(domain, ".")
	return r.mx[domain], r.errors[domain]
}

func (r *TestResolver) LookupIPAddr(ctx context.Context, host string) (as []net.IPAddr, err error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	host = strings.ToLower(host)
	host = strings.TrimRight(host, ".")
	return ipsToAddrs(r.ip[host]), r.errors[host]
}

func ipsToAddrs(ips []net.IP) []net.IPAddr {
	as := []net.IPAddr{}
	for _, ip := range ips {
		as = append(as, net.IPAddr{IP: ip, Zone: ""})
	}
	return as
}

func (r *TestResolver) LookupAddr(ctx context.Context, host string) (addrs []string, err error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	host = strings.ToLower(host)
	host = strings.TrimRight(host, ".")
	return r.addr[host], r.errors[host]
}

func init() {
	// Override the default resolver to make sure the tests are not using the
	// one from net. Individual tests will override this as well, but just in
	// case.
	NewDefaultResolver()
}
