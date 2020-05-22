package spf

import (
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v2"
)

var (
	ymlSingle = flag.String("yml_single", "",
		"run only the test with this name")
	ymlSkipMarked = flag.Bool("yml_skip_marked", true,
		"skip tests marked with the 'skip' value")
)

//////////////////////////////////////////////////////
// YAML test suite parsing.
//

type Suite struct {
	Description string
	Tests       map[string]Test
	ZoneData    map[string][]Record `yaml:"zonedata"`
}

type Test struct {
	Description string
	Comment     string
	Spec        stringSlice
	Helo        string
	Host        string
	MailFrom    string `yaml:"mailfrom"`
	Result      stringSlice
	Explanation string
	Skip        string
}

// Only one of these will be set.
type Record struct {
	A       stringSlice `yaml:"A"`
	AAAA    stringSlice `yaml:"AAAA"`
	MX      *MX         `yaml:"MX"`
	SPF     stringSlice `yaml:"SPF"`
	TXT     stringSlice `yaml:"TXT"`
	PTR     stringSlice `yaml:"PTR"`
	CNAME   stringSlice `yaml:"CNAME"`
	TIMEOUT bool        `yaml:"TIMEOUT"`
}

func (r Record) String() string {
	if len(r.A) > 0 {
		return fmt.Sprintf("A: %v", r.A)
	}
	if len(r.AAAA) > 0 {
		return fmt.Sprintf("AAAA: %v", r.AAAA)
	}
	if r.MX != nil {
		return fmt.Sprintf("MX: %v", *r.MX)
	}
	if len(r.SPF) > 0 {
		return fmt.Sprintf("SPF: %v", r.SPF)
	}
	if len(r.TXT) > 0 {
		return fmt.Sprintf("TXT: %v", r.TXT)
	}
	if len(r.PTR) > 0 {
		return fmt.Sprintf("PTR: %v", r.PTR)
	}
	if len(r.CNAME) > 0 {
		return fmt.Sprintf("CNAME: %v", r.CNAME)
	}
	if r.TIMEOUT {
		return "TIMEOUT"
	}
	return fmt.Sprintf("<empty>")
}

// String slice with a custom yaml unmarshaller, because the yaml parser can't
// handle single-element entries.
// https://github.com/go-yaml/yaml/issues/100
type stringSlice []string

func (sl *stringSlice) UnmarshalYAML(unmarshal func(interface{}) error) error {
	// Try a slice first, and if it works, return it.
	slice := []string{}
	if err := unmarshal(&slice); err == nil {
		*sl = slice
		return nil
	}

	// Get a single string, and append it.
	single := ""
	if err := unmarshal(&single); err != nil {
		return err
	}
	*sl = []string{single}
	return nil
}

// MX is encoded as:
//     MX: [0, mail.example.com]
// so we have a custom decoder to handle the multi-typed list.
type MX struct {
	Prio uint16
	Host string
}

func (mx *MX) UnmarshalYAML(unmarshal func(interface{}) error) error {
	seq := []interface{}{}
	if err := unmarshal(&seq); err != nil {
		return err
	}

	mx.Prio = uint16(seq[0].(int))
	mx.Host = seq[1].(string)
	return nil
}

//////////////////////////////////////////////////////
// Test runners.
//

func testRFC(t *testing.T, fname string) {
	input, err := os.Open(fname)
	if err != nil {
		t.Fatal(err)
	}

	suites := []Suite{}
	dec := yaml.NewDecoder(input)
	for {
		s := Suite{}
		err = dec.Decode(&s)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		suites = append(suites, s)
	}

	trace = t.Logf

	for _, suite := range suites {
		t.Logf("suite: %v", suite.Description)

		// Set up zone for the suite based on zonedata.
		dns = NewDNS()
		for domain, records := range suite.ZoneData {
			t.Logf("  domain %v", domain)
			for _, record := range records {
				t.Logf("    %v", record)
				if record.TIMEOUT {
					err := &net.DNSError{
						Err:       "test timeout error",
						IsTimeout: true,
					}
					dns.errors[domain] = err
				}
				for _, s := range record.A {
					dns.ip[domain] = append(dns.ip[domain], net.ParseIP(s))
				}
				for _, s := range record.AAAA {
					dns.ip[domain] = append(dns.ip[domain], net.ParseIP(s))
				}
				for _, s := range record.TXT {
					dns.txt[domain] = append(dns.txt[domain], s)
				}
				if record.MX != nil {
					dns.mx[domain] = append(dns.mx[domain],
						mx(record.MX.Host, record.MX.Prio))
				}
				for _, s := range record.PTR {
					// domain in this case is of the form:
					//   4.3.2.1.in-addr.arpa
					//   1.0.0.0.0.[...].0.0.E.B.A.B.E.F.A.C.ip6.arpa
					// We need to extract the normal string representation for
					// them, and add the record to dns.addr[ip.String()].
					// Enforce that the record is fully qualified, that's what
					// we expect to see in practice.
					if !strings.HasSuffix(s, ".") {
						s += "."
					}
					ip := reverseDNS(t, domain).String()
					dns.addr[ip] = append(dns.addr[ip], s)
				}
				// TODO: CNAME
			}

			// The test suite is not well done: some tests use SPF instead of
			// TXT because they are old, and others expect the lookup to try
			// TXT first and SPF later, even though that's forbidden by the
			// standard.
			// To try to minimize changes to the suite, we work around this by
			// only adding records from SPF if there is no TXT already.
			// We need to do this in a separate step because order of
			// appearance is not guaranteed.
			if len(dns.txt[domain]) == 0 {
				for _, record := range records {
					if len(record.SPF) > 0 {
						// The test suite expect a single-line SPF record to be
						// concatenated without spaces.
						dns.txt[domain] = append(dns.txt[domain],
							strings.Join(record.SPF, ""))
					}
				}
			}
		}

		// Run each test.
		for name, test := range suite.Tests {
			if *ymlSingle != "" && *ymlSingle != name {
				continue
			}
			if test.Skip != "" && *ymlSkipMarked {
				continue
			}
			t.Logf("  test %s", name)
			ip := net.ParseIP(test.Host)
			t.Logf("    checkhost %v %v", ip, test.MailFrom)
			res, err := CheckHostWithSender(
				net.ParseIP(test.Host), test.Helo, test.MailFrom)
			if !resultIn(res, test.Result) {
				t.Errorf("      failed: expected %v, got %v (%v)  [%v]",
					test.Result, res, err, name)
			} else {
				t.Logf("      success: %v, %v  [%v]", res, err, name)
			}
		}
	}
}

func resultIn(got Result, exp []string) bool {
	for _, e := range exp {
		if e == string(got) {
			return true
		}
	}
	return false
}

// Take a reverse-dns host name of the form:
//   4.3.2.1.in-addr.arpa
//   1.0.0.0.0.[...].0.0.E.B.A.B.E.F.A.C.ip6.arpa
// and returns the corresponding ip.
func reverseDNS(t *testing.T, r string) net.IP {
	s := ""
	if strings.HasSuffix(r, ".in-addr.arpa") {
		// Strip suffix.
		r := r[:len(r)-len(".in-addr.arpa")]

		// Break down in pieces, and construct the ipv4 string backwards.
		pieces := strings.Split(r, ".")
		for i := 0; i < len(pieces); i++ {
			s += pieces[len(pieces)-1-i] + "."
		}
		s = s[:len(s)-1]
	} else if strings.HasSuffix(r, ".ip6.arpa") {
		// Strip suffix.
		r := r[:len(r)-len(".ip6.arpa")]

		// Break down in pieces, and construct the ipv6 string backwards.
		pieces := strings.Split(r, ".")
		for i := 0; i < len(pieces); i++ {
			s += pieces[len(pieces)-1-i]
			if i%4 == 3 {
				s += ":"
			}
		}
		s = s[:len(s)-1]
	} else {
		t.Fatalf("invalid reverse dns %q: invalid suffix", r)
	}

	ip := net.ParseIP(s)
	if ip == nil {
		t.Fatalf("invalid reverse dns %q: bad ip %q", r, s)
	}
	return ip
}

func TestSimple(t *testing.T) {
	testRFC(t, "testdata/simple-tests.yml")
}

func TestRFC4408(t *testing.T) {
	testRFC(t, "testdata/rfc4408-tests.yml")
}

func TestRFC7208(t *testing.T) {
	testRFC(t, "testdata/rfc7208-tests.yml")
}

func TestPySPF(t *testing.T) {
	testRFC(t, "testdata/pyspf-tests.yml")
}
