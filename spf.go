// Package spf implements SPF (Sender Policy Framework) lookup and validation.
//
// Sender Policy Framework (SPF) is a simple email-validation system designed
// to detect email spoofing by providing a mechanism to allow receiving mail
// exchangers to check that incoming mail from a domain comes from a host
// authorized by that domain's administrators [Wikipedia].
//
// This is a Go implementation of it, which is used by the chasquid SMTP
// server (https://blitiri.com.ar/p/chasquid/).
//
// Supported mechanisms and modifiers:
//   all
//   include
//   a
//   mx
//   ip4
//   ip6
//   redirect
//   exists
//   exp (ignored)
//   Macros
//
// References:
//   https://tools.ietf.org/html/rfc7208
//   https://en.wikipedia.org/wiki/Sender_Policy_Framework
package spf // import "blitiri.com.ar/go/spf"

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// Functions that we can override for testing purposes.
var (
	lookupTXT  = net.LookupTXT
	lookupMX   = net.LookupMX
	lookupIP   = net.LookupIP
	lookupAddr = net.LookupAddr
	trace      = func(f string, a ...interface{}) {}
)

// The Result of an SPF check. Note the values have meaning, we use them in
// headers.  https://tools.ietf.org/html/rfc7208#section-8
type Result string

// Valid results.
var (
	// https://tools.ietf.org/html/rfc7208#section-8.1
	// Not able to reach any conclusion.
	None = Result("none")

	// https://tools.ietf.org/html/rfc7208#section-8.2
	// No definite assertion (positive or negative).
	Neutral = Result("neutral")

	// https://tools.ietf.org/html/rfc7208#section-8.3
	// Client is authorized to inject mail.
	Pass = Result("pass")

	// https://tools.ietf.org/html/rfc7208#section-8.4
	// Client is *not* authorized to use the domain
	Fail = Result("fail")

	// https://tools.ietf.org/html/rfc7208#section-8.5
	// Not authorized, but unwilling to make a strong policy statement/
	SoftFail = Result("softfail")

	// https://tools.ietf.org/html/rfc7208#section-8.6
	// Transient error while performing the check.
	TempError = Result("temperror")

	// https://tools.ietf.org/html/rfc7208#section-8.7
	// Records could not be correctly interpreted.
	PermError = Result("permerror")
)

var qualToResult = map[byte]Result{
	'+': Pass,
	'-': Fail,
	'~': SoftFail,
	'?': Neutral,
}

var (
	errLookupLimitReached = fmt.Errorf("lookup limit reached")
	errUnknownField       = fmt.Errorf("unknown field")
	errInvalidIP          = fmt.Errorf("invalid ipX value")
	errInvalidMask        = fmt.Errorf("invalid mask")
	errInvalidMacro       = fmt.Errorf("invalid macro")
	errInvalidDomain      = fmt.Errorf("invalid domain")
	errNoResult           = fmt.Errorf("lookup yielded no result")
	errMultipleRecords    = fmt.Errorf("multiple matching DNS records")
	errTooManyMXRecords   = fmt.Errorf("too many MX records")

	errMatchedAll    = fmt.Errorf("matched 'all'")
	errMatchedA      = fmt.Errorf("matched 'a'")
	errMatchedIP     = fmt.Errorf("matched 'ip'")
	errMatchedMX     = fmt.Errorf("matched 'mx'")
	errMatchedPTR    = fmt.Errorf("matched 'ptr'")
	errMatchedExists = fmt.Errorf("matched 'exists'")
)

// CheckHost fetches SPF records for `domain`, parses them, and evaluates them
// to determine if `ip` is permitted to send mail for it.
// Because it doesn't receive enough information to handle macros well, its
// usage is not recommended, but remains supported for backwards
// compatibility.
// Reference: https://tools.ietf.org/html/rfc7208#section-4
func CheckHost(ip net.IP, domain string) (Result, error) {
	trace("check host %q %q", ip, domain)
	r := &resolution{ip, 0, "@" + domain, nil}
	return r.Check(domain)
}

// CheckHostWithSender fetches SPF records for `sender`'s domain, parses them,
// and evaluates them to determine if `ip` is permitted to send mail for it.
// The `helo` domain is used if the sender has no domain part.
// Reference: https://tools.ietf.org/html/rfc7208#section-4
func CheckHostWithSender(ip net.IP, helo, sender string) (Result, error) {
	_, domain := split(sender)
	if domain == "" {
		domain = helo
	}

	trace("check host with sender %q %q %q (%q)", ip, helo, sender, domain)
	r := &resolution{ip, 0, sender, nil}
	return r.Check(domain)
}

// split an user@domain address into user and domain.
func split(addr string) (string, string) {
	ps := strings.SplitN(addr, "@", 2)
	if len(ps) != 2 {
		return addr, ""
	}

	return ps[0], ps[1]
}

type resolution struct {
	ip    net.IP
	count uint

	sender string

	// Result of doing a reverse lookup for ip (so we only do it once).
	ipNames []string
}

var aField = regexp.MustCompile(`^a$|a:|a/`)
var mxField = regexp.MustCompile(`^mx$|mx:|mx/`)
var ptrField = regexp.MustCompile(`^ptr$|ptr:`)

func (r *resolution) Check(domain string) (Result, error) {
	r.count++
	trace("check %s %d", domain, r.count)
	txt, err := getDNSRecord(domain)
	if err != nil {
		if isTemporary(err) {
			trace("dns temp error: %v", err)
			return TempError, err
		}
		if err == errMultipleRecords {
			trace("multiple dns records")
			return PermError, err
		}
		// Could not resolve the name, it may be missing the record.
		// https://tools.ietf.org/html/rfc7208#section-2.6.1
		trace("dns perm error: %v", err)
		return None, err
	}
	trace("dns record %q", txt)

	if txt == "" {
		// No record => None.
		// https://tools.ietf.org/html/rfc7208#section-4.6
		return None, nil
	}

	fields := strings.Split(txt, " ")

	// redirects must be handled after the rest; instead of having two loops,
	// we just move them to the end.
	var newfields, redirects []string
	for _, field := range fields {
		if strings.HasPrefix(field, "redirect=") {
			redirects = append(redirects, field)
		} else {
			newfields = append(newfields, field)
		}
	}
	if len(redirects) > 1 {
		// At most a single redirect is allowed.
		// https://tools.ietf.org/html/rfc7208#section-6
		return PermError, errInvalidDomain
	}
	fields = append(newfields, redirects...)

	for _, field := range fields {
		if field == "" {
			continue
		}

		// The version check should be case-insensitive (it's a
		// case-insensitive constant in the standard).
		// https://tools.ietf.org/html/rfc7208#section-12
		if strings.HasPrefix(field, "v=") || strings.HasPrefix(field, "V=") {
			continue
		}

		// Limit the number of resolutions to 10
		// https://tools.ietf.org/html/rfc7208#section-4.6.4
		if r.count > 10 {
			trace("lookup limit reached")
			return PermError, errLookupLimitReached
		}

		// See if we have a qualifier, defaulting to + (pass).
		// https://tools.ietf.org/html/rfc7208#section-4.6.2
		result, ok := qualToResult[field[0]]
		if ok {
			field = field[1:]
		} else {
			result = Pass
		}

		// Mechanism and modifier names are case-insensitive.
		// https://tools.ietf.org/html/rfc7208#section-4.6.1
		lfield := strings.ToLower(field)

		if lfield == "all" {
			// https://tools.ietf.org/html/rfc7208#section-5.1
			trace("%v matched all", result)
			return result, errMatchedAll
		} else if strings.HasPrefix(lfield, "include:") {
			if ok, res, err := r.includeField(result, field, domain); ok {
				trace("include ok, %v %v", res, err)
				return res, err
			}
		} else if aField.MatchString(lfield) {
			if ok, res, err := r.aField(result, field, domain); ok {
				trace("a ok, %v %v", res, err)
				return res, err
			}
		} else if mxField.MatchString(lfield) {
			if ok, res, err := r.mxField(result, field, domain); ok {
				trace("mx ok, %v %v", res, err)
				return res, err
			}
		} else if strings.HasPrefix(lfield, "ip4:") || strings.HasPrefix(lfield, "ip6:") {
			if ok, res, err := r.ipField(result, field); ok {
				trace("ip ok, %v %v", res, err)
				return res, err
			}
		} else if ptrField.MatchString(lfield) {
			if ok, res, err := r.ptrField(result, field, domain); ok {
				trace("ptr ok, %v %v", res, err)
				return res, err
			}
		} else if strings.HasPrefix(lfield, "exists:") {
			if ok, res, err := r.existsField(result, field, domain); ok {
				trace("exists ok, %v %v", res, err)
				return res, err
			}
		} else if strings.HasPrefix(lfield, "exp=") {
			trace("exp= not used, skipping")
			continue
		} else if strings.HasPrefix(lfield, "redirect=") {
			trace("redirect, %q", field)
			return r.redirectField(field, domain)
		} else {
			// http://www.openspf.org/SPF_Record_Syntax
			trace("permerror, unknown field")
			return PermError, errUnknownField
		}
	}

	// Got to the end of the evaluation without a result => Neutral.
	// https://tools.ietf.org/html/rfc7208#section-4.7
	trace("fallback to neutral")
	return Neutral, nil
}

// getDNSRecord gets TXT records from the given domain, and returns the SPF
// (if any).  Note that at most one SPF is allowed per a given domain:
// https://tools.ietf.org/html/rfc7208#section-3
// https://tools.ietf.org/html/rfc7208#section-3.2
// https://tools.ietf.org/html/rfc7208#section-4.5
func getDNSRecord(domain string) (string, error) {
	txts, err := lookupTXT(domain)
	if err != nil {
		return "", err
	}

	records := []string{}
	for _, txt := range txts {
		// The version check should be case-insensitive (it's a
		// case-insensitive constant in the standard).
		// https://tools.ietf.org/html/rfc7208#section-12
		if strings.HasPrefix(strings.ToLower(txt), "v=spf1 ") {
			records = append(records, txt)
		}

		// An empty record is explicitly allowed:
		// https://tools.ietf.org/html/rfc7208#section-4.5
		if strings.ToLower(txt) == "v=spf1" {
			records = append(records, txt)
		}
	}

	// 0 records is ok, handled by the parent.
	// 1 record is what we expect, return the record.
	// More than that, it's a permanent error:
	// https://tools.ietf.org/html/rfc7208#section-4.5
	l := len(records)
	if l == 0 {
		return "", nil
	} else if l == 1 {
		return records[0], nil
	}
	return "", errMultipleRecords
}

func isTemporary(err error) bool {
	derr, ok := err.(*net.DNSError)
	return ok && derr.Temporary()
}

// ipField processes an "ip" field.
func (r *resolution) ipField(res Result, field string) (bool, Result, error) {
	fip := field[4:]
	if strings.Contains(fip, "/") {
		_, ipnet, err := net.ParseCIDR(fip)
		if err != nil {
			return true, PermError, errInvalidMask
		}
		if ipnet.Contains(r.ip) {
			return true, res, errMatchedIP
		}
	} else {
		ip := net.ParseIP(fip)
		if ip == nil {
			return true, PermError, errInvalidIP
		}
		if ip.Equal(r.ip) {
			return true, res, errMatchedIP
		}
	}

	return false, "", nil
}

// ptrField processes a "ptr" field.
func (r *resolution) ptrField(res Result, field, domain string) (bool, Result, error) {
	// Extract the domain if the field is in the form "ptr:domain".
	ptrDomain := domain
	if len(field) >= 4 {
		ptrDomain = field[4:]

	}
	ptrDomain, err := r.expandMacros(ptrDomain, domain)
	if err != nil {
		return true, PermError, errInvalidMacro
	}

	if ptrDomain == "" {
		return true, PermError, errInvalidDomain
	}

	if r.ipNames == nil {
		r.ipNames = []string{}
		r.count++
		ns, err := lookupAddr(r.ip.String())
		if err != nil {
			// https://tools.ietf.org/html/rfc7208#section-5
			if isTemporary(err) {
				return true, TempError, err
			}
			return false, "", err
		}
		for _, n := range ns {
			// Validate the record by doing a forward resolution: it has to
			// have some A/AAAA.
			// https://tools.ietf.org/html/rfc7208#section-5.5
			if r.count > 10 {
				return false, "", errLookupLimitReached
			}
			r.count++
			addrs, err := lookupIP(n)
			if err != nil {
				// RFC explicitly says to skip domains which error here.
				continue
			}
			trace("ptr forward resolution %q -> %q", n, addrs)
			if len(addrs) > 0 {
				// Append the lower-case variants so we do a case-insensitive
				// lookup below.
				r.ipNames = append(r.ipNames, strings.ToLower(n))
			}
		}
	}

	trace("ptr evaluating %q in %q", ptrDomain, r.ipNames)
	ptrDomain = strings.ToLower(ptrDomain)
	for _, n := range r.ipNames {
		if strings.HasSuffix(n, ptrDomain+".") {
			return true, res, errMatchedPTR
		}
	}

	return false, "", nil
}

// existsField processes a "exists" field.
// https://tools.ietf.org/html/rfc7208#section-5.7
func (r *resolution) existsField(res Result, field, domain string) (bool, Result, error) {
	// The field is in the form "exists:<domain>".
	eDomain := field[7:]
	eDomain, err := r.expandMacros(eDomain, domain)
	if err != nil {
		return true, PermError, errInvalidMacro
	}

	if eDomain == "" {
		return true, PermError, errInvalidDomain
	}

	r.count++
	ips, err := lookupIP(eDomain)
	if err != nil {
		// https://tools.ietf.org/html/rfc7208#section-5
		if isTemporary(err) {
			return true, TempError, err
		}
		return false, "", err
	}

	// Exists only counts if there are IPv4 matches.
	for _, ip := range ips {
		if ip.To4() != nil {
			return true, res, errMatchedExists
		}
	}
	return false, "", nil
}

// includeField processes an "include" field.
func (r *resolution) includeField(res Result, field, domain string) (bool, Result, error) {
	// https://tools.ietf.org/html/rfc7208#section-5.2
	incdomain := field[len("include:"):]
	incdomain, err := r.expandMacros(incdomain, domain)
	if err != nil {
		return true, PermError, errInvalidMacro
	}
	ir, err := r.Check(incdomain)
	switch ir {
	case Pass:
		return true, res, err
	case Fail, SoftFail, Neutral:
		return false, ir, err
	case TempError:
		return true, TempError, err
	case PermError:
		return true, PermError, err
	case None:
		return true, PermError, errNoResult
	}

	return false, "", fmt.Errorf("This should never be reached")
}

type dualMasks struct {
	v4 int
	v6 int
}

func ipMatch(ip, tomatch net.IP, masks dualMasks) (bool, error) {
	mask := -1
	if tomatch.To4() != nil && masks.v4 >= 0 {
		mask = masks.v4
	} else if tomatch.To4() == nil && masks.v6 >= 0 {
		mask = masks.v6
	}

	if mask >= 0 {
		_, ipnet, err := net.ParseCIDR(
			fmt.Sprintf("%s/%d", tomatch.String(), mask))
		if err != nil {
			return false, errInvalidMask
		}
		return ipnet.Contains(ip), nil
	}

	return ip.Equal(tomatch), nil
}

var aRegexp = regexp.MustCompile(`^[aA](:([^/]+))?(/(\w+))?(//(\w+))?$`)
var mxRegexp = regexp.MustCompile(`^[mM][xX](:([^/]+))?(/(\w+))?(//(\w+))?$`)

func domainAndMask(re *regexp.Regexp, field, domain string) (string, dualMasks, error) {
	masks := dualMasks{-1, -1}
	groups := re.FindStringSubmatch(field)
	if groups != nil {
		if groups[2] != "" {
			domain = groups[2]
		}
		if groups[4] != "" {
			mask4, err := strconv.Atoi(groups[4])
			if err != nil || mask4 < 0 || mask4 > 32 {
				return "", masks, errInvalidMask
			}
			masks.v4 = mask4
		}
		if groups[6] != "" {
			mask6, err := strconv.Atoi(groups[6])
			if err != nil || mask6 < 0 || mask6 > 128 {
				return "", masks, errInvalidMask
			}
			masks.v6 = mask6
		}
	}
	trace("masks on %q: %q %q %v", field, groups, domain, masks)

	// Test to catch malformed entries: if there's a /, there must be at least
	// one mask.
	if strings.Contains(field, "/") && masks.v4 == -1 && masks.v6 == -1 {
		return "", masks, errInvalidMask
	}

	return domain, masks, nil
}

// aField processes an "a" field.
func (r *resolution) aField(res Result, field, domain string) (bool, Result, error) {
	// https://tools.ietf.org/html/rfc7208#section-5.3
	aDomain, masks, err := domainAndMask(aRegexp, field, domain)
	if err != nil {
		return true, PermError, err
	}
	aDomain, err = r.expandMacros(aDomain, domain)
	if err != nil {
		return true, PermError, errInvalidMacro
	}

	r.count++
	ips, err := lookupIP(aDomain)
	if err != nil {
		// https://tools.ietf.org/html/rfc7208#section-5
		if isTemporary(err) {
			return true, TempError, err
		}
		return false, "", err
	}
	for _, ip := range ips {
		ok, err := ipMatch(r.ip, ip, masks)
		if ok {
			trace("mx matched %v, %v, %v", r.ip, ip, masks)
			return true, res, errMatchedA
		} else if err != nil {
			return true, PermError, err
		}
	}

	return false, "", nil
}

// mxField processes an "mx" field.
func (r *resolution) mxField(res Result, field, domain string) (bool, Result, error) {
	// https://tools.ietf.org/html/rfc7208#section-5.4
	mxDomain, masks, err := domainAndMask(mxRegexp, field, domain)
	if err != nil {
		return true, PermError, err
	}
	mxDomain, err = r.expandMacros(mxDomain, domain)
	if err != nil {
		return true, PermError, errInvalidMacro
	}

	r.count++
	mxs, err := lookupMX(mxDomain)
	if err != nil {
		// https://tools.ietf.org/html/rfc7208#section-5
		if isTemporary(err) {
			return true, TempError, err
		}
		return false, "", err
	}

	// There's an explicit maximum of 10 MX records per match.
	// https://tools.ietf.org/html/rfc7208#section-4.6.4
	if len(mxs) > 10 {
		return true, PermError, errTooManyMXRecords
	}

	mxips := []net.IP{}
	for _, mx := range mxs {
		r.count++
		ips, err := lookupIP(mx.Host)
		if err != nil {
			// https://tools.ietf.org/html/rfc7208#section-5
			if isTemporary(err) {
				return true, TempError, err
			}
			return false, "", err
		}
		mxips = append(mxips, ips...)
	}
	for _, ip := range mxips {
		ok, err := ipMatch(r.ip, ip, masks)
		if ok {
			trace("mx matched %v, %v, %v", r.ip, ip, masks)
			return true, res, errMatchedMX
		} else if err != nil {
			return true, PermError, err
		}
	}

	return false, "", nil
}

// redirectField proces a "redirect=" field.
func (r *resolution) redirectField(field, domain string) (Result, error) {
	rDomain := field[len("redirect="):]
	rDomain, err := r.expandMacros(rDomain, domain)
	if err != nil {
		return PermError, errInvalidMacro
	}

	if rDomain == "" {
		return PermError, errInvalidDomain
	}

	// https://tools.ietf.org/html/rfc7208#section-6.1
	result, err := r.Check(rDomain)
	if result == None {
		result = PermError
	}
	return result, err
}

// Group extraction of macro-string from the formal specification.
// https://tools.ietf.org/html/rfc7208#section-7.1
var macroRegexp = regexp.MustCompile(
	`([slodiphcrtvSLODIPHCRTV])([0-9]+)?([rR])?([-.+,/_=]+)?`)

// Expand macros, return the expanded string.
// This expects to be passed the domain-spec within a field, not an entire
// field or larger (that has problematic security implications).
// https://tools.ietf.org/html/rfc7208#section-7
func (r *resolution) expandMacros(s, domain string) (string, error) {
	// Macros/domains shouldn't contain CIDR. Our parsing should prevent it
	// from happening in case where it matters (a, mx), but for the ones which
	// doesn't, prevent them from sneaking through.
	if strings.Contains(s, "/") {
		trace("macro contains /")
		return "", errInvalidDomain
	}

	// Bypass the complex logic if there are no macros present.
	if !strings.Contains(s, "%") {
		return s, nil
	}

	// Are we processing the character right after "%"?
	afterPercent := false

	// Are we inside a macro definition (%{...}) ?
	inMacroDefinition := false

	// Macro string, where we accumulate the values inside the definition.
	macroS := ""

	var err error
	n := ""
	for _, c := range s {
		if afterPercent {
			afterPercent = false
			switch c {
			case '%':
				n += "%"
				continue
			case '_':
				n += " "
				continue
			case '-':
				n += "%20"
				continue
			case '{':
				inMacroDefinition = true
				continue
			}
			return "", errInvalidMacro
		}
		if inMacroDefinition {
			if c != '}' {
				macroS += string(c)
				continue
			}
			inMacroDefinition = false

			// Extract letter, digit transformer, reverse transformer, and
			// delimiters.
			groups := macroRegexp.FindStringSubmatch(macroS)
			trace("macro %q: %q", macroS, groups)
			macroS = ""
			if groups == nil {
				return "", errInvalidMacro
			}
			letter := groups[1]

			digits := 0
			if groups[2] != "" {
				// Use 0 as "no digits given"; an explicit value of 0 is not
				// valid.
				digits, err = strconv.Atoi(groups[2])
				if err != nil || digits <= 0 {
					return "", errInvalidMacro
				}
			}
			reverse := groups[3] == "r" || groups[3] == "R"
			delimiters := groups[4]
			if delimiters == "" {
				// By default, split strings by ".".
				delimiters = "."
			}

			// Uppercase letters indicate URL escaping of the results.
			urlEscape := letter == strings.ToUpper(letter)
			letter = strings.ToLower(letter)

			str := ""
			switch letter {
			case "s":
				str = r.sender
			case "l":
				str, _ = split(r.sender)
			case "o":
				_, str = split(r.sender)
			case "d":
				str = domain
			case "i":
				str = r.ip.String()
			case "p":
				// This shouldn't be used, we don't want to support it, it's
				// risky. "unknown" is a safe value.
				// https://tools.ietf.org/html/rfc7208#section-7.3
				str = "unknown"
			case "v":
				if r.ip.To4() != nil {
					str = "in-addr"
				} else {
					str = "ip6"
				}
			case "h":
				str = domain
			default:
				// c, r, t are allowed in exp only, and we don't expand macros
				// in exp so they are just as invalid as the rest.
				return "", errInvalidMacro
			}

			// Split str using the given separators.
			splitFunc := func(r rune) bool {
				return strings.ContainsRune(delimiters, r)
			}
			split := strings.FieldsFunc(str, splitFunc)

			// Reverse if requested.
			if reverse {
				reverseStrings(split)
			}

			// Leave the last $digits fields, if given.
			if digits > 0 {
				if digits > len(split) {
					digits = len(split)
				}
				split = split[len(split)-digits : len(split)]
			}

			// Join back, always with "."
			str = strings.Join(split, ".")

			// Escape if requested. Note this doesn't strictly escape ALL
			// unreserved characters, it's the closest we can get without
			// reimplmenting it ourselves.
			if urlEscape {
				str = url.QueryEscape(str)
			}

			n += str
			continue
		}
		if c == '%' {
			afterPercent = true
			continue
		}
		n += string(c)
	}

	trace("macro expanded %q to %q", s, n)
	return n, nil
}

func reverseStrings(a []string) {
	for left, right := 0, len(a)-1; left < right; left, right = left+1, right-1 {
		a[left], a[right] = a[right], a[left]
	}
}
