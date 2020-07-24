package spf

import (
	"fmt"
	"net"
	"testing"
)

var ip1110 = net.ParseIP("1.1.1.0")
var ip1111 = net.ParseIP("1.1.1.1")
var ip6666 = net.ParseIP("2001:db8::68")
var ip6660 = net.ParseIP("2001:db8::0")

func TestBasic(t *testing.T) {
	dns = NewDNS()
	trace = t.Logf

	cases := []struct {
		txt string
		res Result
		err error
	}{
		{"", None, errNoResult},
		{"blah", None, errNoResult},
		{"v=spf1", Neutral, nil},
		{"v=spf1 ", Neutral, nil},
		{"v=spf1 -", PermError, errUnknownField},
		{"v=spf1 all", Pass, errMatchedAll},
		{"v=spf1 exp=blah +all", Pass, errMatchedAll},
		{"v=spf1  +all", Pass, errMatchedAll},
		{"v=spf1 -all ", Fail, errMatchedAll},
		{"v=spf1 ~all", SoftFail, errMatchedAll},
		{"v=spf1 ?all", Neutral, errMatchedAll},
		{"v=spf1 a ~all", SoftFail, errMatchedAll},
		{"v=spf1 a/24", Neutral, nil},
		{"v=spf1 a:d1110/24", Pass, errMatchedA},
		{"v=spf1 a:d1110/montoto", PermError, errInvalidMask},
		{"v=spf1 a:d1110/99", PermError, errInvalidMask},
		{"v=spf1 a:d1110/32", Neutral, nil},
		{"v=spf1 a:d1110", Neutral, nil},
		{"v=spf1 a:d1111", Pass, errMatchedA},
		{"v=spf1 a:nothing/24", Neutral, nil},
		{"v=spf1 mx", Neutral, nil},
		{"v=spf1 mx/24", Neutral, nil},
		{"v=spf1 mx:a/montoto ~all", PermError, errInvalidMask},
		{"v=spf1 mx:d1110/24 ~all", Pass, errMatchedMX},
		{"v=spf1 mx:d1110/24//100 ~all", Pass, errMatchedMX},
		{"v=spf1 mx:d1110/24//129 ~all", PermError, errInvalidMask},
		{"v=spf1 mx:d1110/24/100 ~all", PermError, errInvalidMask},
		{"v=spf1 mx:d1110/99 ~all", PermError, errInvalidMask},
		{"v=spf1 ip4:1.2.3.4 ~all", SoftFail, errMatchedAll},
		{"v=spf1 ip6:12 ~all", PermError, errInvalidIP},
		{"v=spf1 ip4:1.1.1.1 -all", Pass, errMatchedIP},
		{"v=spf1 ip4:1.1.1.1/24 -all", Pass, errMatchedIP},
		{"v=spf1 ip4:1.1.1.1/lala -all", PermError, errInvalidMask},
		{"v=spf1 ip4:1.1.1.1/33 -all", PermError, errInvalidMask},
		{"v=spf1 include:doesnotexist", PermError, errNoResult},
		{"v=spf1 ptr -all", Pass, errMatchedPTR},
		{"v=spf1 ptr:d1111 -all", Pass, errMatchedPTR},
		{"v=spf1 ptr:lalala -all", Pass, errMatchedPTR},
		{"v=spf1 ptr:doesnotexist -all", Fail, errMatchedAll},
		{"v=spf1 blah", PermError, errUnknownField},
		{"v=spf1 exists:d1111 -all", Pass, errMatchedExists},
		{"v=spf1 redirect=", PermError, errInvalidDomain},
	}

	dns.ip["d1111"] = []net.IP{ip1111}
	dns.ip["d1110"] = []net.IP{ip1110}
	dns.mx["d1110"] = []*net.MX{mx("d1110", 5), mx("nothing", 10)}
	dns.addr["1.1.1.1"] = []string{"lalala.", "xx.domain.", "d1111."}
	dns.ip["lalala"] = []net.IP{ip1111}
	dns.ip["xx.domain"] = []net.IP{ip1111}

	for _, c := range cases {
		dns.txt["domain"] = []string{c.txt}
		res, err := CheckHost(ip1111, "domain")
		if (res == TempError || res == PermError) && (err == nil) {
			t.Errorf("%q: expected error, got nil", c.txt)
		}
		if res != c.res {
			t.Errorf("%q: expected %q, got %q", c.txt, c.res, res)
		}
		if err != c.err {
			t.Errorf("%q: expected error [%v], got [%v]", c.txt, c.err, err)
		}
	}
}

func TestIPv6(t *testing.T) {
	dns = NewDNS()
	trace = t.Logf

	cases := []struct {
		txt string
		res Result
		err error
	}{
		{"v=spf1 all", Pass, errMatchedAll},
		{"v=spf1 a ~all", SoftFail, errMatchedAll},
		{"v=spf1 a/24", Neutral, nil},
		{"v=spf1 a:d6660//24", Pass, errMatchedA},
		{"v=spf1 a:d6660/24//100", Pass, errMatchedA},
		{"v=spf1 a:d6660", Neutral, nil},
		{"v=spf1 a:d6666", Pass, errMatchedA},
		{"v=spf1 a:nothing//24", Neutral, nil},
		{"v=spf1 mx:d6660//24 ~all", Pass, errMatchedMX},
		{"v=spf1 mx:d6660/24//100 ~all", Pass, errMatchedMX},
		{"v=spf1 mx:d6660/24/100 ~all", PermError, errInvalidMask},
		{"v=spf1 ip6:2001:db8::68 ~all", Pass, errMatchedIP},
		{"v=spf1 ip6:2001:db8::1/24 ~all", Pass, errMatchedIP},
		{"v=spf1 ip6:2001:db8::1/100 ~all", Pass, errMatchedIP},
		{"v=spf1 ptr -all", Pass, errMatchedPTR},
		{"v=spf1 ptr:d6666 -all", Pass, errMatchedPTR},
		{"v=spf1 ptr:sonlas6 -all", Pass, errMatchedPTR},
		{"v=spf1 ptr:sonlas7 -all", Fail, errMatchedAll},
	}

	dns.ip["d6666"] = []net.IP{ip6666}
	dns.ip["d6660"] = []net.IP{ip6660}
	dns.mx["d6660"] = []*net.MX{mx("d6660", 5), mx("nothing", 10)}
	dns.addr["2001:db8::68"] = []string{"sonlas6.", "domain.", "d6666."}
	dns.ip["domain"] = []net.IP{ip1111}
	dns.ip["sonlas6"] = []net.IP{ip6666}

	for _, c := range cases {
		dns.txt["domain"] = []string{c.txt}
		res, err := CheckHost(ip6666, "domain")
		if (res == TempError || res == PermError) && (err == nil) {
			t.Errorf("%q: expected error, got nil", c.txt)
		}
		if res != c.res {
			t.Errorf("%q: expected %q, got %q", c.txt, c.res, res)
		}
		if err != c.err {
			t.Errorf("%q: expected error [%v], got [%v]", c.txt, c.err, err)
		}
	}
}

func TestInclude(t *testing.T) {
	// Test that the include is doing a recursive lookup.
	// If we got a match on 1.1.1.1, is because include:domain2 did not match.
	dns = NewDNS()
	dns.txt["domain"] = []string{"v=spf1 include:domain2 ip4:1.1.1.1"}
	trace = t.Logf

	cases := []struct {
		txt string
		res Result
		err error
	}{
		{"", PermError, errNoResult},
		{"v=spf1 all", Pass, errMatchedAll},

		// domain2 did not pass, so continued and matched parent's ip4.
		{"v=spf1", Pass, errMatchedIP},
		{"v=spf1 -all", Pass, errMatchedIP},
	}

	for _, c := range cases {
		dns.txt["domain2"] = []string{c.txt}
		res, err := CheckHost(ip1111, "domain")
		if res != c.res || err != c.err {
			t.Errorf("%q: expected [%v/%v], got [%v/%v]",
				c.txt, c.res, c.err, res, err)
		}
	}
}

func TestRecursionLimit(t *testing.T) {
	dns = NewDNS()
	dns.txt["domain"] = []string{"v=spf1 include:domain ~all"}
	trace = t.Logf

	res, err := CheckHost(ip1111, "domain")
	if res != PermError || err != errLookupLimitReached {
		t.Errorf("expected permerror, got %v (%v)", res, err)
	}
}

func TestRedirect(t *testing.T) {
	dns = NewDNS()
	dns.txt["domain"] = []string{"v=spf1 redirect=domain2"}
	dns.txt["domain2"] = []string{"v=spf1 ip4:1.1.1.1 -all"}
	trace = t.Logf

	res, err := CheckHost(ip1111, "domain")
	if res != Pass {
		t.Errorf("expected pass, got %v (%v)", res, err)
	}
}

func TestInvalidRedirect(t *testing.T) {
	// Redirect to a non-existing host; the inner check returns None, but due
	// to the redirection, this lookup should return PermError.
	// https://tools.ietf.org/html/rfc7208#section-6.1
	dns = NewDNS()
	dns.txt["domain"] = []string{"v=spf1 redirect=doesnotexist"}
	trace = t.Logf

	res, err := CheckHost(ip1111, "doesnotexist")
	if res != None {
		t.Errorf("expected none, got %v (%v)", res, err)
	}

	res, err = CheckHost(ip1111, "domain")
	if res != PermError || err != errNoResult {
		t.Errorf("expected permerror, got %v (%v)", res, err)
	}
}

func TestRedirectOrder(t *testing.T) {
	// We should only check redirects after all mechanisms, even if the
	// redirect modifier appears before them.
	dns = NewDNS()
	dns.txt["faildom"] = []string{"v=spf1 -all"}
	trace = t.Logf

	dns.txt["domain"] = []string{"v=spf1 redirect=faildom"}
	res, err := CheckHost(ip1111, "domain")
	if res != Fail || err != errMatchedAll {
		t.Errorf("expected fail, got %v (%v)", res, err)
	}

	dns.txt["domain"] = []string{"v=spf1 redirect=faildom all"}
	res, err = CheckHost(ip1111, "domain")
	if res != Pass || err != errMatchedAll {
		t.Errorf("expected pass, got %v (%v)", res, err)
	}
}

func TestNoRecord(t *testing.T) {
	dns = NewDNS()
	dns.txt["d1"] = []string{""}
	dns.txt["d2"] = []string{"loco", "v=spf2"}
	dns.errors["nospf"] = fmt.Errorf("no such domain")
	trace = t.Logf

	for _, domain := range []string{"d1", "d2", "d3", "nospf"} {
		res, err := CheckHost(ip1111, domain)
		if res != None {
			t.Errorf("expected none, got %v (%v)", res, err)
		}
	}
}

func TestDNSTemporaryErrors(t *testing.T) {
	dns = NewDNS()
	dnsError := &net.DNSError{
		Err:         "temporary error for testing",
		IsTemporary: true,
	}

	// Domain "tmperr" will fail resolution with a temporary error.
	dns.errors["tmperr"] = dnsError
	dns.errors["1.1.1.1"] = dnsError
	dns.mx["tmpmx"] = []*net.MX{mx("tmperr", 10)}
	trace = t.Logf

	cases := []struct {
		txt string
		res Result
	}{
		{"v=spf1 include:tmperr", TempError},
		{"v=spf1 a:tmperr", TempError},
		{"v=spf1 mx:tmperr", TempError},
		{"v=spf1 ptr:tmperr", TempError},
		{"v=spf1 mx:tmpmx", TempError},
	}

	for _, c := range cases {
		dns.txt["domain"] = []string{c.txt}
		res, err := CheckHost(ip1111, "domain")
		if res != c.res {
			t.Errorf("%q: expected %v, got %v (%v)",
				c.txt, c.res, res, err)
		}
	}
}

func TestDNSPermanentErrors(t *testing.T) {
	dns = NewDNS()
	dnsError := &net.DNSError{
		Err:         "permanent error for testing",
		IsTemporary: false,
	}

	// Domain "tmperr" will fail resolution with a temporary error.
	dns.errors["tmperr"] = dnsError
	dns.errors["1.1.1.1"] = dnsError
	dns.mx["tmpmx"] = []*net.MX{mx("tmperr", 10)}
	trace = t.Logf

	cases := []struct {
		txt string
		res Result
	}{
		{"v=spf1 include:tmperr", PermError},
		{"v=spf1 a:tmperr", Neutral},
		{"v=spf1 mx:tmperr", Neutral},
		{"v=spf1 ptr:tmperr", Neutral},
		{"v=spf1 mx:tmpmx", Neutral},
	}

	for _, c := range cases {
		dns.txt["domain"] = []string{c.txt}
		res, err := CheckHost(ip1111, "domain")
		if res != c.res {
			t.Errorf("%q: expected %v, got %v (%v)",
				c.txt, c.res, res, err)
		}
	}
}

func TestMacros(t *testing.T) {
	dns = NewDNS()
	trace = t.Logf

	// Most of the cases are covered by the standard test suite, so this is
	// targeted at gaps in coverage.
	cases := []struct {
		txt string
		res Result
		err error
	}{
		{"v=spf1 ptr:%{fff} -all", PermError, errInvalidMacro},
		{"v=spf1 mx:%{fff} -all", PermError, errInvalidMacro},
		{"v=spf1 redirect=%{fff}", PermError, errInvalidMacro},
		{"v=spf1 a:%{o0}", PermError, errInvalidMacro},
		{"v=spf1 +a:sss-%{s}-sss", Pass, errMatchedA},
		{"v=spf1 +a:ooo-%{o}-ooo", Pass, errMatchedA},
		{"v=spf1 +a:OOO-%{O}-OOO", Pass, errMatchedA},
		{"v=spf1 +a:ppp-%{p}-ppp", Pass, errMatchedA},
		{"v=spf1 +a:vvv-%{v}-vvv", Pass, errMatchedA},
		{"v=spf1 a:%{x}", PermError, errInvalidMacro},
		{"v=spf1 +a:ooo-%{o7}-ooo", Pass, errMatchedA},
	}

	dns.ip["sss-user@domain-sss"] = []net.IP{ip6666}
	dns.ip["ooo-domain-ooo"] = []net.IP{ip6666}
	dns.ip["ppp-unknown-ppp"] = []net.IP{ip6666}
	dns.ip["vvv-ip6-vvv"] = []net.IP{ip6666}

	for _, c := range cases {
		dns.txt["domain"] = []string{c.txt}
		res, err := CheckHostWithSender(ip6666, "helo", "user@domain")
		if (res == TempError || res == PermError) && (err == nil) {
			t.Errorf("%q: expected error, got nil", c.txt)
		}
		if res != c.res {
			t.Errorf("%q: expected %q, got %q", c.txt, c.res, res)
		}
		if err != c.err {
			t.Errorf("%q: expected error [%v], got [%v]", c.txt, c.err, err)
		}
	}
}

func TestMacrosV4(t *testing.T) {
	dns = NewDNS()
	trace = t.Logf

	// Like TestMacros above, but specifically for IPv4.
	// It's easier to have a separate suite.
	// While at it, test some of the reversals, for variety.
	cases := []struct {
		txt string
		res Result
		err error
	}{
		{"v=spf1 +a:sr-%{sr}-sr", Pass, errMatchedA},
		{"v=spf1 +a:sra-%{sr.}-sra", Pass, errMatchedA},
		{"v=spf1 +a:o7-%{o7}-o7", Pass, errMatchedA},
		{"v=spf1 +a:o1-%{o1}-o1", Pass, errMatchedA},
		{"v=spf1 +a:o1r-%{o1r}-o1r", Pass, errMatchedA},
		{"v=spf1 +a:vvv-%{v}-vvv", Pass, errMatchedA},
	}

	dns.ip["sr-com.user@domain-sr"] = []net.IP{ip1111}
	dns.ip["sra-com.user@domain-sra"] = []net.IP{ip1111}
	dns.ip["o7-domain.com-o7"] = []net.IP{ip1111}
	dns.ip["o1-com-o1"] = []net.IP{ip1111}
	dns.ip["o1r-domain-o1r"] = []net.IP{ip1111}
	dns.ip["vvv-in-addr-vvv"] = []net.IP{ip1111}

	for _, c := range cases {
		dns.txt["domain.com"] = []string{c.txt}
		res, err := CheckHostWithSender(ip1111, "helo", "user@domain.com")
		if (res == TempError || res == PermError) && (err == nil) {
			t.Errorf("%q: expected error, got nil", c.txt)
		}
		if res != c.res {
			t.Errorf("%q: expected %q, got %q", c.txt, c.res, res)
		}
		if err != c.err {
			t.Errorf("%q: expected error [%v], got [%v]", c.txt, c.err, err)
		}
	}
}

func mx(host string, pref uint16) *net.MX {
	return &net.MX{Host: host, Pref: pref}
}

func TestIPMatchHelper(t *testing.T) {
	cases := []struct {
		ip      net.IP
		tomatch net.IP
		masks   dualMasks
		ok      bool
		err     error
	}{
		{ip1111, ip1110, dualMasks{24, -1}, true, nil},
		{ip1111, ip1111, dualMasks{-1, -1}, true, nil},
		{ip1111, ip1110, dualMasks{-1, -1}, false, nil},
		{ip1111, ip1110, dualMasks{32, -1}, false, nil},
		{ip1111, ip1110, dualMasks{99, -1}, false, errInvalidMask},

		{ip6666, ip6660, dualMasks{-1, 100}, true, nil},
		{ip6666, ip6666, dualMasks{-1, -1}, true, nil},
		{ip6666, ip6660, dualMasks{-1, -1}, false, nil},
		{ip6666, ip6660, dualMasks{-1, 128}, false, nil},
		{ip6666, ip6660, dualMasks{-1, 200}, false, errInvalidMask},
	}
	for _, c := range cases {
		ok, err := ipMatch(c.ip, c.tomatch, c.masks)
		if ok != c.ok || err != c.err {
			t.Errorf("[%s %s/%v]: expected %v/%v, got %v/%v",
				c.ip, c.tomatch, c.masks, c.ok, c.err, ok, err)
		}
	}
}

func TestInvalidMacro(t *testing.T) {
	// Test that the macro expansion detects some invalid macros.
	macros := []string{
		"%{x}", "%{z}", "%{c}", "%{r}", "%{t}",
	}
	for _, macro := range macros {
		r := resolution{
			ip:     ip1111,
			count:  0,
			sender: "sender.com",
		}

		out, err := r.expandMacros(macro, "sender.com")
		if out != "" || err != errInvalidMacro {
			t.Errorf(`[%s]:expected ""/%v, got %q/%v`,
				macro, errInvalidMacro, out, err)
		}
	}
}
