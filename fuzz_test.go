// Fuzz testing for package spf.
//
// Run it with:
//
//   go test -tags gofuzz -fuzz=FuzzCheckHostWithSender
//

//go:build gofuzz
// +build gofuzz

package spf

import (
	"net"
	"testing"
)

func FuzzCheckHostWithSender(f *testing.F) {
	// Make sure there's no trace function active (a previous test may have
	// set this for their own purposes).
	defaultTrace = nullTrace

	// Set up a common DNS environment. The seed corpus will expect this, and
	// it helps increase coverage.
	dns := NewDefaultResolver()
	dns.Ip["d1111"] = []net.IP{ip1111}
	dns.Ip["d1110"] = []net.IP{ip1110}
	dns.Mx["d1110"] = []*net.MX{{"d1110", 5}, {"nothing", 10}}
	dns.Ip["d6666"] = []net.IP{ip6666}
	dns.Ip["d6660"] = []net.IP{ip6660}
	dns.Mx["d6660"] = []*net.MX{{"d6660", 5}, {"nothing", 10}}
	dns.Addr["2001:db8::68"] = []string{"sonlas6.", "domain.", "d6666."}
	dns.Addr["1.1.1.1"] = []string{"lalala.", "domain.", "d1111."}

	f.Fuzz(func(t *testing.T, record string) {
		// The domain's TXT record comes from the fuzzer.
		dns.Txt["domain"] = []string{record}

		CheckHostWithSender(
			ip1111, "helo", "domain", WithResolver(dns))
		CheckHostWithSender(
			ip6666, "helo", "domain", WithResolver(dns))
	})
}
