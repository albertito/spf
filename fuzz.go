// Fuzz testing for package spf.
//
// Run it with:
//
//   go-fuzz-build blitiri.com.ar/go/spf
//   go-fuzz -bin=./spf-fuzz.zip -workdir=testdata/fuzz
//

// +build gofuzz

package spf

import "net"

// Parsed IP addresses, for convenience.
var (
	ip1110 = net.ParseIP("1.1.1.0")
	ip1111 = net.ParseIP("1.1.1.1")
	ip6666 = net.ParseIP("2001:db8::68")
	ip6660 = net.ParseIP("2001:db8::0")
)

// Results for TXT lookups. This one is global as the values will be set by
// the fuzzer. The other lookup types are static and configured in init, see
// below).
var txtResults = map[string][]string{}

func init() {
	// Make the resolving functions return our test data.
	// The test data is fixed, the fuzzer doesn't change it.
	// TODO: Once go-fuzz can run functions from _test.go files, move this to
	// spf_test.go to avoid duplicating all this boilerplate.
	var (
		mxResults   = map[string][]*net.MX{}
		ipResults   = map[string][]net.IP{}
		addrResults = map[string][]string{}
	)

	lookupTXT = func(domain string) (txts []string, err error) {
		return txtResults[domain], nil
	}
	lookupMX = func(domain string) (mxs []*net.MX, err error) {
		return mxResults[domain], nil
	}
	lookupIP = func(host string) (ips []net.IP, err error) {
		return ipResults[host], nil
	}
	lookupAddr = func(host string) (addrs []string, err error) {
		return addrResults[host], nil
	}

	ipResults["d1111"] = []net.IP{ip1111}
	ipResults["d1110"] = []net.IP{ip1110}
	mxResults["d1110"] = []*net.MX{{"d1110", 5}, {"nothing", 10}}
	ipResults["d6666"] = []net.IP{ip6666}
	ipResults["d6660"] = []net.IP{ip6660}
	mxResults["d6660"] = []*net.MX{{"d6660", 5}, {"nothing", 10}}
	addrResults["2001:db8::68"] = []string{"sonlas6.", "domain.", "d6666."}
	addrResults["1.1.1.1"] = []string{"lalala.", "domain.", "d1111."}
}

func Fuzz(data []byte) int {
	// The domain's TXT record comes from the fuzzer.
	txtResults["domain"] = []string{string(data)}

	v4result, _ := CheckHost(ip1111, "domain") // IPv4
	v6result, _ := CheckHost(ip6666, "domain") // IPv6

	// Raise priority if any of the results was something other than
	// PermError, as it means the data was better formed.
	if v4result != PermError || v6result != PermError {
		return 1
	}
	return 0
}
