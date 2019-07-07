package goresolver

import (
	"fmt"
	"github.com/miekg/dns"
	"io/ioutil"
	"os"
	"path"
	"strings"
	"testing"
)

var isMockQuery = true
var isMockUpdate = false

func getMockFile(testName string, qname string, qtype uint16) (fileName string, baseDir string) {
	baseDir = path.Join("./testdata", testName)
	fileName = path.Join(baseDir, fmt.Sprintf("%d_%stxt", qtype, qname))
	return fileName, baseDir
}

func mockQueryUpdate(t *testing.T, qname string, qtype uint16) (*dns.Msg, error) {
	r, err := localQuery(qname, qtype)
	if r == nil {
		return nil, err
	}
	mockFile, mockDir := getMockFile(t.Name(), qname, qtype)
	if _, err := os.Stat(mockDir); os.IsNotExist(err) {
		err := os.Mkdir(mockDir, 0755)
		if err != nil {
			t.Error("unable to create directory for mock files")
		}
	}
	f, _ := os.Create(mockFile)
	if f != nil {
		s := make([]string, 0, len(r.Answer))
		for _, rr := range r.Answer {
			s = append(s, rr.String())
		}
		_, _ = f.WriteString(strings.Join(s, "\n"))
		_ = f.Close()
	}
	return r, nil
}

func newResolver(t *testing.T) (res *Resolver) {
	resolver, _ := NewResolver("./testdata/resolv.conf")
	resolver.queryFn = func(qname string, qtype uint16) (*dns.Msg, error) {
		msg := &dns.Msg{}
		if isMockQuery == false {
			return localQuery(qname, qtype)
		}
		if isMockUpdate == true {
			return mockQueryUpdate(t, qname, qtype)
		}
		mockFile, _ := getMockFile(t.Name(), qname, qtype)
		s, err := ioutil.ReadFile(mockFile)
		if err != nil {
			t.Error("mockQuery", err)
		}
		if s == nil {
			t.Log("mockQuery: no result for ", mockFile)
			return &dns.Msg{}, nil
		}
		ss := strings.Split(string(s), "\n")
		rrSet := make([]dns.RR, 0, len(ss))
		for _, rrStr := range ss {
			if rrStr == "" {
				continue
			}
			rr, err := dns.NewRR(rrStr)
			if err != nil {
				t.Error("mockQuery", err)
			}
			rrSet = append(rrSet, rr)
		}
		if len(rrSet) > 0 {
			msg.Answer = rrSet
		}
		return msg, nil
	}
	return resolver
}

func TestInitializeErr(t *testing.T) {
	resolver, err := NewResolver("./testdata/nonexistent.conf")
	if resolver != nil || err == nil {
		t.Error("initialize did not fail")
	}
}

func TestInitialize(t *testing.T) {
	resolver, err := NewResolver("./testdata/resolv.conf")
	if resolver == nil || err != nil {
		t.Error("initialize failed")
	}
}

//func TestLookupInvalid1(t *testing.T) {
//	resolver, _ := NewResolver("./testdata/resolv.conf")
//	testName = t.Name()
//	//resolver.queryFn = mockQuery
//	ips, err := resolver.LookupIP("sigfail.verteiltesysteme.net.")
//	if err == nil {
//		t.Errorf("dnssec validation failed: %v", err)
//	}
//	if len(ips) > 0 {
//		t.Error("lookup should return no results")
//	}
//}

func TestLookupMissingResource(t *testing.T) {
	resolver := newResolver(t)
	ips, err := resolver.LookupIP("invalid.stakey.org.")
	if err != ErrNoResult {
		t.Errorf("should return ErrNoResult")
	}
	if len(ips) > 0 {
		t.Error("lookup should return no results")
	}
}

func TestLookupValid1(t *testing.T) {
	resolver := newResolver(t)
	ips, err := resolver.LookupIP("stakey.org.")
	if err != nil {
		t.Error("shouldn't return err: ", err)
	}
	if len(ips) < 1 {
		t.Error("lookup should return results")
	}
}

func TestLookupValid2(t *testing.T) {
	resolver := newResolver(t)
	ips, err := resolver.LookupIP("testnet-seed.stakey.org.")
	if err != nil {
		t.Error("should validate")
	}
	if len(ips) < 1 {
		t.Error("lookup should return results")
	}
}

func TestLookupAAAAOnly(t *testing.T) {
	resolver := newResolver(t)
	ips, err := resolver.LookupIP("stakey.org.")
	if err != nil {
		t.Error("shouldn't return err")
	}
	if len(ips) < 1 {
		t.Error("lookup should return results")
	}
}

func TestLookupResourceNotSigned(t *testing.T) {
	resolver := newResolver(t)
	ips, err := resolver.LookupIPv4("google.com.")
	if err != ErrResourceNotSigned {
		t.Errorf("should return ErrResourceNotSigned")
	}
	if len(ips) < 1 {
		t.Error("lookup should return results")
	}
}

func TestLookupValid4(t *testing.T) {
	resolver := newResolver(t)
	ips, err := resolver.LookupIP("dnssec-deployment.org.")
	if err != nil {
		t.Error("validation should pass")
	}
	if len(ips) < 1 {
		t.Error("lookup returned no results")
	}
}

func TestLookupValid5(t *testing.T) {
	resolver := newResolver(t)
	ips, err := resolver.LookupIP("ada.bortzmeyer.org.")
	if err != nil {
		t.Error("validation should pass")
	}
	if len(ips) < 1 {
		t.Error("lookup returned no results")
	}
}

func TestLookupInvalidDsDigest(t *testing.T) {
	resolver := newResolver(t)
	ips, err := resolver.LookupIPv4("testnet-seed.stakey.org.")
	if err != ErrDsInvalid {
		t.Errorf("should return ErrDsInvalid")
	}
	if len(ips) > 0 {
		t.Error("lookup shouldn't return results")
	}
}

func TestLookupInvalidDsRrsig(t *testing.T) {
	resolver := newResolver(t)
	ips, err := resolver.LookupIPv4("stakey.org.")
	if err != ErrRrsigValidationError {
		t.Error("should return ErrRrsigValidationError")
	}
	if len(ips) > 0 {
		t.Error("lookup returned no results")
	}
}

func TestLookupInvalidARRSIG(t *testing.T) {
	resolver := newResolver(t)
	ips, err := resolver.LookupIPv4("stakey.org.")
	if err != ErrInvalidRRsig {
		t.Error("should return ErrRrsigValidationError")
	}
	if len(ips) > 0 {
		t.Error("lookup returned no results")
	}
}

func TestLookupInvalidAAAARRSIG(t *testing.T) {
	resolver := newResolver(t)
	ips, err := resolver.LookupIPv6("stakey.org.")
	if err != ErrInvalidRRsig {
		t.Error("should return ErrRrsigValidationError")
	}
	if len(ips) > 0 {
		t.Error("lookup returned no results")
	}
}

func TestLookupInvalidDnskeyRrsig(t *testing.T) {
	resolver := newResolver(t)
	ips, err := resolver.LookupIPv4("stakey.org.")
	if err != ErrRrsigValidationError {
		t.Error("should return ErrRrsigValidationError")
	}
	if len(ips) > 0 {
		t.Error("lookup returned no results")
	}
}

func TestLookupMissingDnskey(t *testing.T) {
	resolver := newResolver(t)
	ips, err := resolver.LookupIPv4("stakey.org.")
	if err != ErrDnskeyNotAvailable {
		t.Error("should return ErrDnskeyNotAvailable")
	}
	if len(ips) > 0 {
		t.Error("lookup returned no results")
	}
}

func TestStrictNSQuery(t *testing.T) {
	resolver := newResolver(t)
	rrs, err := resolver.StrictNSQuery("bortzmeyer.org.", dns.TypeTXT)
	if err != nil {
		t.Error("err should be nil")
	}
	if len(rrs) != 2 {
		t.Error("should return RRs")
	}
}

func TestNonexistentName(t *testing.T) {
	resolver := newResolver(t)
	rrs, err := resolver.StrictNSQuery("non-existent-domain-34545345.org.", dns.TypeTXT)
	if err != ErrNoResult {
		t.Error("should return ErrNoResult")
	}
	if len(rrs) > 0 {
		t.Error("should not return results")
	}
}

func TestOnlyZskPresent(t *testing.T) {
	resolver := newResolver(t)
	rrs, err := resolver.StrictNSQuery("froggle.org.", dns.TypeMX)
	if err != nil {
		t.Error("should not return err")
	}
	if len(rrs) < 7 {
		t.Error("should return results")
	}
}

func TestMissingDsRR(t *testing.T) {
	resolver := newResolver(t)
	ips, err := resolver.LookupIPv4("dnssec-deployment.org.")
	if err != ErrDsNotAvailable {
		t.Error("should return ErrDsNotAvailable")
	}
	if len(ips) > 0 {
		t.Error("should return no results")
	}
}

func TestStrictNSQueryEmptyInput(t *testing.T) {
	resolver := newResolver(t)
	rrs, err := resolver.StrictNSQuery("", dns.TypeMX)
	if err == nil {
		t.Error("should return err")
	}
	if len(rrs) > 0 {
		t.Error("shouldn't return results")
	}
}
