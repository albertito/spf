package spf

import (
	"context"
	"fmt"
	"net"
	"testing"

	"blitiri.com.ar/go/spf/internal/dnstest"
)

func NewDefaultResolver() *dnstest.TestResolver {
	dns := dnstest.NewResolver()
	defaultResolver = dns
	return dns
}

func init() {
	// Override the default resolver to make sure the tests are not using the
	// one from net. Individual tests will override this as well, but just in
	// case.
	NewDefaultResolver()
}

var ip1110 = net.ParseIP("1.1.1.0")
var ip1111 = net.ParseIP("1.1.1.1")
var ip6666 = net.ParseIP("2001:db8::68")
var ip6660 = net.ParseIP("2001:db8::0")

func TestBasic(t *testing.T) {
	dns := NewDefaultResolver()
	defaultTrace = t.Logf

	cases := []struct {
		txt string
		res Result
		err error
	}{
		{"", None, ErrNoResult},
		{"blah", None, ErrNoResult},
		{"v=spf1", Neutral, nil},
		{"v=spf1 ", Neutral, nil},
		{"v=spf1 -", PermError, ErrUnknownField},
		{"v=spf1 all", Pass, ErrMatchedAll},
		{"v=spf1 exp=blah +all", Pass, ErrMatchedAll},
		{"v=spf1  +all", Pass, ErrMatchedAll},
		{"v=spf1 -all ", Fail, ErrMatchedAll},
		{"v=spf1 ~all", SoftFail, ErrMatchedAll},
		{"v=spf1 ?all", Neutral, ErrMatchedAll},
		{"v=spf1 a ~all", SoftFail, ErrMatchedAll},
		{"v=spf1 a/24", Neutral, nil},
		{"v=spf1 a:d1110/24", Pass, ErrMatchedA},
		{"v=spf1 a:d1110/montoto", PermError, ErrInvalidMask},
		{"v=spf1 a:d1110/99", PermError, ErrInvalidMask},
		{"v=spf1 a:d1110/32", Neutral, nil},
		{"v=spf1 a:d1110", Neutral, nil},
		{"v=spf1 a:d1111", Pass, ErrMatchedA},
		{"v=spf1 a:nothing/24", Neutral, nil},
		{"v=spf1 mx", Neutral, nil},
		{"v=spf1 mx/24", Neutral, nil},
		{"v=spf1 mx:a/montoto ~all", PermError, ErrInvalidMask},
		{"v=spf1 mx:d1110/24 ~all", Pass, ErrMatchedMX},
		{"v=spf1 mx:d1110/24//100 ~all", Pass, ErrMatchedMX},
		{"v=spf1 mx:d1110/24//129 ~all", PermError, ErrInvalidMask},
		{"v=spf1 mx:d1110/24/100 ~all", PermError, ErrInvalidMask},
		{"v=spf1 mx:d1110/99 ~all", PermError, ErrInvalidMask},
		{"v=spf1 ip4:1.2.3.4 ~all", SoftFail, ErrMatchedAll},
		{"v=spf1 ip6:12 ~all", PermError, ErrInvalidIP},
		{"v=spf1 ip4:1.1.1.1 -all", Pass, ErrMatchedIP},
		{"v=spf1 ip4:1.1.1.1/24 -all", Pass, ErrMatchedIP},
		{"v=spf1 ip4:1.1.1.1/lala -all", PermError, ErrInvalidMask},
		{"v=spf1 ip4:1.1.1.1/33 -all", PermError, ErrInvalidMask},
		{"v=spf1 include:doesnotexist", PermError, ErrNoResult},
		{"v=spf1 ptr -all", Pass, ErrMatchedPTR},
		{"v=spf1 ptr:d1111 -all", Pass, ErrMatchedPTR},
		{"v=spf1 ptr:lalala -all", Pass, ErrMatchedPTR},
		{"v=spf1 ptr:doesnotexist -all", Fail, ErrMatchedAll},
		{"v=spf1 blah", PermError, ErrUnknownField},
		{"v=spf1 exists:d1111 -all", Pass, ErrMatchedExists},
		{"v=spf1 redirect=", PermError, ErrInvalidDomain},
	}

	dns.Ip["d1111"] = []net.IP{ip1111}
	dns.Ip["d1110"] = []net.IP{ip1110}
	dns.Mx["d1110"] = []*net.MX{mx("d1110", 5), mx("nothing", 10)}
	dns.Addr["1.1.1.1"] = []string{"lalala.", "xx.domain.", "d1111."}
	dns.Ip["lalala"] = []net.IP{ip1111}
	dns.Ip["xx.domain"] = []net.IP{ip1111}

	for _, c := range cases {
		dns.Txt["domain"] = []string{c.txt}
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
	dns := NewDefaultResolver()
	defaultTrace = t.Logf

	cases := []struct {
		txt string
		res Result
		err error
	}{
		{"v=spf1 all", Pass, ErrMatchedAll},
		{"v=spf1 a ~all", SoftFail, ErrMatchedAll},
		{"v=spf1 a/24", Neutral, nil},
		{"v=spf1 a:d6660//24", Pass, ErrMatchedA},
		{"v=spf1 a:d6660/24//100", Pass, ErrMatchedA},
		{"v=spf1 a:d6660", Neutral, nil},
		{"v=spf1 a:d6666", Pass, ErrMatchedA},
		{"v=spf1 a:nothing//24", Neutral, nil},
		{"v=spf1 mx:d6660//24 ~all", Pass, ErrMatchedMX},
		{"v=spf1 mx:d6660/24//100 ~all", Pass, ErrMatchedMX},
		{"v=spf1 mx:d6660/24/100 ~all", PermError, ErrInvalidMask},
		{"v=spf1 ip6:2001:db8::68 ~all", Pass, ErrMatchedIP},
		{"v=spf1 ip6:2001:db8::1/24 ~all", Pass, ErrMatchedIP},
		{"v=spf1 ip6:2001:db8::1/100 ~all", Pass, ErrMatchedIP},
		{"v=spf1 ptr -all", Pass, ErrMatchedPTR},
		{"v=spf1 ptr:d6666 -all", Pass, ErrMatchedPTR},
		{"v=spf1 ptr:sonlas6 -all", Pass, ErrMatchedPTR},
		{"v=spf1 ptr:sonlas7 -all", Fail, ErrMatchedAll},
	}

	dns.Ip["d6666"] = []net.IP{ip6666}
	dns.Ip["d6660"] = []net.IP{ip6660}
	dns.Mx["d6660"] = []*net.MX{mx("d6660", 5), mx("nothing", 10)}
	dns.Addr["2001:db8::68"] = []string{"sonlas6.", "domain.", "d6666."}
	dns.Ip["domain"] = []net.IP{ip1111}
	dns.Ip["sonlas6"] = []net.IP{ip6666}

	for _, c := range cases {
		dns.Txt["domain"] = []string{c.txt}
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
	dns := NewDefaultResolver()
	dns.Txt["domain"] = []string{"v=spf1 include:domain2 ip4:1.1.1.1"}
	defaultTrace = t.Logf

	cases := []struct {
		txt string
		res Result
		err error
	}{
		{"", PermError, ErrNoResult},
		{"v=spf1 all", Pass, ErrMatchedAll},

		// domain2 did not pass, so continued and matched parent's ip4.
		{"v=spf1", Pass, ErrMatchedIP},
		{"v=spf1 -all", Pass, ErrMatchedIP},
	}

	for _, c := range cases {
		dns.Txt["domain2"] = []string{c.txt}
		res, err := CheckHost(ip1111, "domain")
		if res != c.res || err != c.err {
			t.Errorf("%q: expected [%v/%v], got [%v/%v]",
				c.txt, c.res, c.err, res, err)
		}
	}
}

func TestRecursionLimit(t *testing.T) {
	dns := NewDefaultResolver()
	dns.Txt["domain"] = []string{"v=spf1 include:domain ~all"}
	defaultTrace = t.Logf

	res, err := CheckHost(ip1111, "domain")
	if res != PermError || err != ErrLookupLimitReached {
		t.Errorf("expected permerror, got %v (%v)", res, err)
	}
}

func TestRedirect(t *testing.T) {
	dns := NewDefaultResolver()
	dns.Txt["domain"] = []string{"v=spf1 redirect=domain2"}
	dns.Txt["domain2"] = []string{"v=spf1 ip4:1.1.1.1 -all"}
	defaultTrace = t.Logf

	res, err := CheckHost(ip1111, "domain")
	if res != Pass {
		t.Errorf("expected pass, got %v (%v)", res, err)
	}
}

func TestInvalidRedirect(t *testing.T) {
	// Redirect to a non-existing host; the inner check returns None, but due
	// to the redirection, this lookup should return PermError.
	// https://tools.ietf.org/html/rfc7208#section-6.1
	dns := NewDefaultResolver()
	dns.Txt["domain"] = []string{"v=spf1 redirect=doesnotexist"}
	defaultTrace = t.Logf

	res, err := CheckHost(ip1111, "doesnotexist")
	if res != None {
		t.Errorf("expected none, got %v (%v)", res, err)
	}

	res, err = CheckHost(ip1111, "domain")
	if res != PermError || err != ErrNoResult {
		t.Errorf("expected permerror, got %v (%v)", res, err)
	}
}

func TestRedirectOrder(t *testing.T) {
	// We should only check redirects after all mechanisms, even if the
	// redirect modifier appears before them.
	dns := NewDefaultResolver()
	dns.Txt["faildom"] = []string{"v=spf1 -all"}
	defaultTrace = t.Logf

	dns.Txt["domain"] = []string{"v=spf1 redirect=faildom"}
	res, err := CheckHost(ip1111, "domain")
	if res != Fail || err != ErrMatchedAll {
		t.Errorf("expected fail, got %v (%v)", res, err)
	}

	dns.Txt["domain"] = []string{"v=spf1 redirect=faildom all"}
	res, err = CheckHost(ip1111, "domain")
	if res != Pass || err != ErrMatchedAll {
		t.Errorf("expected pass, got %v (%v)", res, err)
	}
}

func TestNoRecord(t *testing.T) {
	dns := NewDefaultResolver()
	dns.Txt["d1"] = []string{""}
	dns.Txt["d2"] = []string{"loco", "v=spf2"}
	dns.Errors["nospf"] = fmt.Errorf("no such domain")
	defaultTrace = t.Logf

	for _, domain := range []string{"d1", "d2", "d3", "nospf"} {
		res, err := CheckHost(ip1111, domain)
		if res != None {
			t.Errorf("expected none, got %v (%v)", res, err)
		}
	}
}

func TestDNSTemporaryErrors(t *testing.T) {
	dns := NewDefaultResolver()
	dnsError := &net.DNSError{
		Err:         "temporary error for testing",
		IsTemporary: true,
	}

	// Domain "tmperr" will fail resolution with a temporary error.
	dns.Errors["tmperr"] = dnsError
	dns.Errors["1.1.1.1"] = dnsError
	dns.Mx["tmpmx"] = []*net.MX{mx("tmperr", 10)}
	defaultTrace = t.Logf

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
		dns.Txt["domain"] = []string{c.txt}
		res, err := CheckHost(ip1111, "domain")
		if res != c.res {
			t.Errorf("%q: expected %v, got %v (%v)",
				c.txt, c.res, res, err)
		}
	}
}

func TestDNSPermanentErrors(t *testing.T) {
	dns := NewDefaultResolver()
	dnsError := &net.DNSError{
		Err:         "permanent error for testing",
		IsTemporary: false,
	}

	// Domain "tmperr" will fail resolution with a temporary error.
	dns.Errors["tmperr"] = dnsError
	dns.Errors["1.1.1.1"] = dnsError
	dns.Mx["tmpmx"] = []*net.MX{mx("tmperr", 10)}
	defaultTrace = t.Logf

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
		dns.Txt["domain"] = []string{c.txt}
		res, err := CheckHost(ip1111, "domain")
		if res != c.res {
			t.Errorf("%q: expected %v, got %v (%v)",
				c.txt, c.res, res, err)
		}
	}
}

func TestMacros(t *testing.T) {
	dns := NewDefaultResolver()
	defaultTrace = t.Logf

	// Most of the cases are covered by the standard test suite, so this is
	// targeted at gaps in coverage.
	cases := []struct {
		txt string
		res Result
		err error
	}{
		{"v=spf1 ptr:%{fff} -all", PermError, ErrInvalidMacro},
		{"v=spf1 mx:%{fff} -all", PermError, ErrInvalidMacro},
		{"v=spf1 redirect=%{fff}", PermError, ErrInvalidMacro},
		{"v=spf1 a:%{o0}", PermError, ErrInvalidMacro},
		{"v=spf1 +a:sss-%{s}-sss", Pass, ErrMatchedA},
		{"v=spf1 +a:ooo-%{o}-ooo", Pass, ErrMatchedA},
		{"v=spf1 +a:OOO-%{O}-OOO", Pass, ErrMatchedA},
		{"v=spf1 +a:ppp-%{p}-ppp", Pass, ErrMatchedA},
		{"v=spf1 +a:hhh-%{h}-hhh", Pass, ErrMatchedA},
		{"v=spf1 +a:vvv-%{v}-vvv", Pass, ErrMatchedA},
		{"v=spf1 a:%{x}", PermError, ErrInvalidMacro},
		{"v=spf1 +a:ooo-%{o7}-ooo", Pass, ErrMatchedA},
		{"v=spf1 exists:%{ir}.vvv -all", Pass, ErrMatchedExists},
	}

	dns.Ip["sss-user@domain-sss"] = []net.IP{ip6666}
	dns.Ip["ooo-domain-ooo"] = []net.IP{ip6666}
	dns.Ip["ppp-unknown-ppp"] = []net.IP{ip6666}
	dns.Ip["vvv-ip6-vvv"] = []net.IP{ip6666}
	dns.Ip["hhh-helo-hhh"] = []net.IP{ip6666}
	dns.Ip["8.6.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.vvv"] = []net.IP{ip1111}

	for _, c := range cases {
		dns.Txt["domain"] = []string{c.txt}
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
	dns := NewDefaultResolver()
	defaultTrace = t.Logf

	// Like TestMacros above, but specifically for IPv4.
	// It's easier to have a separate suite.
	// While at it, test some of the reversals, for variety.
	cases := []struct {
		txt string
		res Result
		err error
	}{
		{"v=spf1 +a:sr-%{sr}-sr", Pass, ErrMatchedA},
		{"v=spf1 +a:sra-%{sr.}-sra", Pass, ErrMatchedA},
		{"v=spf1 +a:o7-%{o7}-o7", Pass, ErrMatchedA},
		{"v=spf1 +a:o1-%{o1}-o1", Pass, ErrMatchedA},
		{"v=spf1 +a:o1r-%{o1r}-o1r", Pass, ErrMatchedA},
		{"v=spf1 +a:vvv-%{v}-vvv", Pass, ErrMatchedA},
	}

	dns.Ip["sr-com.user@domain-sr"] = []net.IP{ip1111}
	dns.Ip["sra-com.user@domain-sra"] = []net.IP{ip1111}
	dns.Ip["o7-domain.com-o7"] = []net.IP{ip1111}
	dns.Ip["o1-com-o1"] = []net.IP{ip1111}
	dns.Ip["o1r-domain-o1r"] = []net.IP{ip1111}
	dns.Ip["vvv-in-addr-vvv"] = []net.IP{ip1111}

	for _, c := range cases {
		dns.Txt["domain.com"] = []string{c.txt}
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

func mkDM(v4, v6 int) dualMasks {
	return dualMasks{net.CIDRMask(v4, 32), net.CIDRMask(v6, 128)}
}

func TestIPMatchHelper(t *testing.T) {
	cases := []struct {
		ip      net.IP
		tomatch net.IP
		masks   dualMasks
		ok      bool
	}{
		{ip1111, ip1110, mkDM(24, -1), true},
		{ip1111, ip1111, mkDM(-1, -1), true},
		{ip1111, ip1110, mkDM(-1, -1), false},
		{ip1111, ip1110, mkDM(32, -1), false},
		{ip1111, ip1110, mkDM(99, -1), false},

		{ip6666, ip6660, mkDM(-1, 100), true},
		{ip6666, ip6666, mkDM(-1, -1), true},
		{ip6666, ip6660, mkDM(-1, -1), false},
		{ip6666, ip6660, mkDM(-1, 128), false},
		{ip6666, ip6660, mkDM(-1, 200), false},
	}
	for _, c := range cases {
		ok := ipMatch(c.ip, c.tomatch, c.masks)
		if ok != c.ok {
			t.Errorf("[%s %s/%v]: expected %v, got %v",
				c.ip, c.tomatch, c.masks, c.ok, ok)
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
			trace:  t.Logf,
		}

		out, err := r.expandMacros(macro, "sender.com")
		if out != "" || err != ErrInvalidMacro {
			t.Errorf(`[%s]:expected ""/%v, got %q/%v`,
				macro, ErrInvalidMacro, out, err)
		}
	}
}

// Test that the null tracer doesn't cause unexpected issues, since all the
// other tests override it.
func TestNullTrace(t *testing.T) {
	dns := NewDefaultResolver()
	defaultTrace = nullTrace

	dns.Txt["domain1"] = []string{"v=spf1 include:domain2"}
	dns.Txt["domain2"] = []string{"v=spf1 +all"}

	// Do a normal resolution, check it passes.
	res, err := CheckHostWithSender(ip1111, "helo", "user@domain1")
	if res != Pass {
		t.Errorf("expected pass, got %q / %q", res, err)
	}
}

func TestOverrideLookupLimit(t *testing.T) {
	dns := NewDefaultResolver()
	defaultTrace = t.Logf

	dns.Txt["domain1"] = []string{"v=spf1 include:domain2"}
	dns.Txt["domain2"] = []string{"v=spf1 include:domain3"}
	dns.Txt["domain3"] = []string{"v=spf1 include:domain4"}
	dns.Txt["domain4"] = []string{"v=spf1 +all"}

	// The default of 10 should be enough.
	res, err := CheckHostWithSender(ip1111, "helo", "user@domain1")
	if res != Pass {
		t.Errorf("expected pass, got %q / %q", res, err)
	}

	// Set the limit to 4, which is enough.
	res, err = CheckHostWithSender(ip1111, "helo", "user@domain1",
		OverrideLookupLimit(4))
	if res != Pass {
		t.Errorf("expected pass, got %q / %q", res, err)
	}

	// Set the limit to 3, which is not enough.
	res, err = CheckHostWithSender(ip1111, "helo", "user@domain1",
		OverrideLookupLimit(3))
	if res != PermError || err != ErrLookupLimitReached {
		t.Errorf("expected permerror/lookup limit reached, got %q / %q",
			res, err)
	}
}

func TestOverrideVoidLookupLimit(t *testing.T) {
	dns := NewDefaultResolver()
	defaultTrace = t.Logf

	dns.Txt["domain1"] = []string{"v=spf1 exists:%{i}.one include:domain2"}
	dns.Txt["domain2"] = []string{"v=spf1 exists:%{i}.two include:domain3"}
	dns.Txt["domain3"] = []string{"v=spf1 exists:%{i}.three include:domain4"}
	dns.Txt["domain4"] = []string{"v=spf1 +all"}
	dns.Errors["1.1.1.1.one"] = fmt.Errorf("no such domain")
	dns.Errors["1.1.1.1.two"] = fmt.Errorf("no such domain")
	dns.Errors["1.1.1.1.three"] = fmt.Errorf("no such domain")

	// The default of 2
	res, err := CheckHostWithSender(ip1111, "helo", "user@domain1")
	if res != PermError {
		t.Errorf("expected permerror, got %q / %q", res, err)
	}

	// Set the limit to 10, which is excessive.
	res, err = CheckHostWithSender(ip1111, "helo", "user@domain1",
		OverrideVoidLookupLimit(10))
	if res != Pass {
		t.Errorf("expected pass, got %q / %q", res, err)
	}

	// Set the limit to 1, which is not enough.
	res, err = CheckHostWithSender(ip1111, "helo", "user@domain1",
		OverrideVoidLookupLimit(1))
	if res != PermError || err != ErrVoidLookupLimitReached {
		t.Errorf("expected permerror/void lookup limit reached, got %q / %q",
			res, err)
	}
}

func TestWithContext(t *testing.T) {
	dns := NewDefaultResolver()
	defaultTrace = t.Logf

	dns.Txt["domain1"] = []string{"v=spf1 include:domain2"}
	dns.Txt["domain2"] = []string{"v=spf1 +all"}

	// With a normal context.
	ctx := context.Background()
	res, err := CheckHostWithSender(ip1111, "helo", "user@domain1",
		WithContext(ctx))
	if res != Pass {
		t.Errorf("expected pass, got %q / %q", res, err)
	}

	// With a cancelled context.
	ctx, cancelF := context.WithCancel(context.Background())
	cancelF()
	res, err = CheckHostWithSender(ip1111, "helo", "user@domain1",
		WithContext(ctx))
	if res != None || err != context.Canceled {
		t.Errorf("expected none/context cancelled, got %q / %q", res, err)
	}
}

func TestWithResolver(t *testing.T) {
	// Use a custom resolver, making sure it's different from the default.
	defaultResolver = dnstest.NewResolver()
	dns := dnstest.NewResolver()
	defaultTrace = t.Logf

	dns.Txt["domain1"] = []string{"v=spf1 include:domain2"}
	dns.Txt["domain2"] = []string{"v=spf1 +all"}

	res, err := CheckHostWithSender(ip1111, "helo", "user@domain1",
		WithResolver(dns))
	if res != Pass {
		t.Errorf("expected pass, got %q / %q", res, err)
	}
}

// Test some corner cases when resolver.LookupIPAddr returns an invalid
// address. This can happen if using a buggy custom resolver.
func TestBadResolverResponse(t *testing.T) {
	dns := dnstest.NewResolver()
	defaultTrace = t.Logf

	// When LookupIPAddr returns an invalid ip, for an "a" field.
	dns.Ip["domain1"] = []net.IP{nil}
	dns.Txt["domain1"] = []string{"v=spf1 a:domain1 -all"}
	res, err := CheckHostWithSender(ip1111, "helo", "user@domain1",
		WithResolver(dns))
	if res != Fail {
		t.Errorf("expected fail, got %q / %q", res, err)
	}

	// Same as above, except the field has a mask.
	dns.Ip["domain1"] = []net.IP{nil}
	dns.Txt["domain1"] = []string{"v=spf1 a:domain1//24 -all"}
	res, err = CheckHostWithSender(ip1111, "helo", "user@domain1",
		WithResolver(dns))
	if res != Fail {
		t.Errorf("expected fail, got %q / %q", res, err)
	}

	// When LookupIPAddr returns an invalid ip, for an "mx" field.
	dns.Ip["mx.domain1"] = []net.IP{nil}
	dns.Mx["domain1"] = []*net.MX{mx("mx.domain1", 5)}
	dns.Txt["domain1"] = []string{"v=spf1 mx:domain1 -all"}
	res, err = CheckHostWithSender(ip1111, "helo", "user@domain1",
		WithResolver(dns))
	if res != Fail {
		t.Errorf("expected fail, got %q / %q", res, err)
	}

	// Same as above, except the field has a mask.
	dns.Ip["mx.domain1"] = []net.IP{nil}
	dns.Mx["domain1"] = []*net.MX{mx("mx.domain1", 5)}
	dns.Txt["domain1"] = []string{"v=spf1 mx:domain1//24 -all"}
	res, err = CheckHostWithSender(ip1111, "helo", "user@domain1",
		WithResolver(dns))
	if res != Fail {
		t.Errorf("expected fail, got %q / %q", res, err)
	}
}

func TestWithTraceFunc(t *testing.T) {
	calls := 0
	var trace TraceFunc = func(f string, a ...interface{}) {
		calls++
		t.Logf("tracing "+f, a...)
	}

	dns := NewDefaultResolver()

	dns.Txt["domain1"] = []string{"v=spf1 include:domain2"}
	dns.Txt["domain2"] = []string{"v=spf1 +all"}

	// Do a normal resolution, check it passes.
	res, err := CheckHostWithSender(ip1111, "helo", "user@domain1",
		WithTraceFunc(trace))
	if res != Pass {
		t.Errorf("expected pass, got %q / %q", res, err)
	}

	if calls == 0 {
		t.Errorf("expected >0 trace function calls, got 0")
	}
}
