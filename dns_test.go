// DNS resolver for testing purposes.
package spf

import (
	"context"
	"net"
	"strings"
)

// Testing DNS resolver.
//
// Not exported since this is not part of the public API and only used
// internally on tests.
type testResolver struct {
	Txt    map[string][]string
	Mx     map[string][]*net.MX
	Ip     map[string][]net.IP
	Addr   map[string][]string
	Cname  map[string]string
	Errors map[string]error
}

func newTestResolver() *testResolver {
	return &testResolver{
		Txt:    map[string][]string{},
		Mx:     map[string][]*net.MX{},
		Ip:     map[string][]net.IP{},
		Addr:   map[string][]string{},
		Cname:  map[string]string{},
		Errors: map[string]error{},
	}
}

var nxDomainErr = &net.DNSError{
	Err:        "domain not found (for testing)",
	IsNotFound: true,
}

func (r *testResolver) LookupTXT(ctx context.Context, domain string) (txts []string, err error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	domain = strings.ToLower(domain)
	domain = strings.TrimRight(domain, ".")
	if cname, ok := r.Cname[domain]; ok {
		return r.LookupTXT(ctx, cname)
	}
	if _, ok := r.Txt[domain]; !ok && r.Errors[domain] == nil {
		return nil, nxDomainErr
	}
	return r.Txt[domain], r.Errors[domain]
}

func (r *testResolver) LookupMX(ctx context.Context, domain string) (mxs []*net.MX, err error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	domain = strings.ToLower(domain)
	domain = strings.TrimRight(domain, ".")
	if cname, ok := r.Cname[domain]; ok {
		return r.LookupMX(ctx, cname)
	}
	if _, ok := r.Mx[domain]; !ok && r.Errors[domain] == nil {
		return nil, nxDomainErr
	}
	return r.Mx[domain], r.Errors[domain]
}

func (r *testResolver) LookupIPAddr(ctx context.Context, host string) (as []net.IPAddr, err error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	host = strings.ToLower(host)
	host = strings.TrimRight(host, ".")
	if cname, ok := r.Cname[host]; ok {
		return r.LookupIPAddr(ctx, cname)
	}
	if _, ok := r.Ip[host]; !ok && r.Errors[host] == nil {
		return nil, nxDomainErr
	}
	return ipsToAddrs(r.Ip[host]), r.Errors[host]
}

func ipsToAddrs(ips []net.IP) []net.IPAddr {
	as := []net.IPAddr{}
	for _, ip := range ips {
		as = append(as, net.IPAddr{IP: ip, Zone: ""})
	}
	return as
}

func (r *testResolver) LookupAddr(ctx context.Context, host string) (addrs []string, err error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	host = strings.ToLower(host)
	host = strings.TrimRight(host, ".")
	if cname, ok := r.Cname[host]; ok {
		return r.LookupAddr(ctx, cname)
	}
	if _, ok := r.Addr[host]; !ok && r.Errors[host] == nil {
		return nil, nxDomainErr
	}
	return r.Addr[host], r.Errors[host]
}
