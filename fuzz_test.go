// Fuzz testing for package spf.
//
// Use `go test -fuzz=.` to do a fuzzing run.
//
// The seed corpus (in testdata/fuzz/) is exercised as part of the regular
// "go test" run.

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
	dns.Mx["d1110"] = []*net.MX{mx("d1110", 5), mx("nothing", 10)}
	dns.Ip["d6666"] = []net.IP{ip6666}
	dns.Ip["d6660"] = []net.IP{ip6660}
	dns.Mx["d6660"] = []*net.MX{mx("d6660", 5), mx("nothing", 10)}
	dns.Addr["2001:db8::68"] = []string{"sonlas6.", "domain.", "d6666."}
	dns.Addr["1.1.1.1"] = []string{"lalala.", "domain.", "d1111."}

	f.Fuzz(func(t *testing.T, record string) {
		// The domain's TXT record comes from the fuzzer.
		dns.Txt["domain"] = []string{record}

		// Note the sender must have a domain part, otherwise the check falls
		// back to the helo domain and the record above is never looked up.
		CheckHostWithSender(
			ip1111, "helo", "user@domain", WithResolver(dns))
		CheckHostWithSender(
			ip6666, "helo", "user@domain", WithResolver(dns))
	})
}
