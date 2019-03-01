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

var testName = "test1"
var isMockQuery = true
var isMockUpdate = false

func getMockFile(testName string, qname string, qtype uint16) (fileName string, baseDir string) {
	baseDir = path.Join("./testdata", testName)
	fileName = path.Join(baseDir, fmt.Sprintf("%d_%s.txt", qtype, qname))
	return fileName, baseDir
}

func mockQueryUpdate(qname string, qtype uint16) (*dns.Msg, error) {
	r, err := localQuery(qname, qtype)
	if r == nil {
		return nil, err
	}
	mockFile, mockDir := getMockFile(testName, qname, qtype)
	if _, err := os.Stat(mockDir); os.IsNotExist(err) {
		os.Mkdir(mockDir, 0755)
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

func mockQuery(qname string, qtype uint16) (*dns.Msg, error) {
	if isMockQuery == false {
		return localQuery(qname, qtype)
	}
	if isMockUpdate == true {
		return mockQueryUpdate(qname, qtype)
	}
	mockFile, _ := getMockFile(testName, qname, qtype)
	s, err := ioutil.ReadFile(mockFile)
	if s != nil {
		ss := strings.Split(string(s), "\n")
		rrSet := make([]dns.RR, 0, len(ss))
		for _, rrStr := range ss {
			rr, err := dns.NewRR(rrStr)
			if err != nil {
				return nil, err
			}
			rrSet = append(rrSet, rr)
		}
		msg := &dns.Msg{Answer: rrSet}
		return msg, nil
	}
	return nil, err
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
//	//resolver.query = mockQuery
//	ips, err := resolver.LookupIP("sigfail.verteiltesysteme.net.")
//	if err == nil {
//		t.Errorf("dnssec validation failed: %v", err)
//	}
//	if len(ips) > 0 {
//		t.Error("lookup should return no results")
//	}
//}

func TestLookupMissingResource(t *testing.T) {
	resolver, _ := NewResolver("./testdata/resolv.conf")
	testName = t.Name()
	resolver.query = mockQuery
	ips, err := resolver.LookupIP("invalid.stakey.org.")
	if err != ErrRRnotAvailable {
		t.Errorf("should return ErrRRnotAvailable")
	}
	if len(ips) > 0 {
		t.Error("lookup should return no results")
	}
}

func TestLookupValid1(t *testing.T) {
	resolver, _ := NewResolver("./testdata/resolv.conf")
	testName = t.Name()
	resolver.query = mockQuery
	ips, err := resolver.LookupIP("stakey.org.")
	if err != nil {
		t.Error("shouldn't return err: ", err)
	}
	if len(ips) < 1 {
		t.Error("lookup should return results")
	}
}

func TestLookupAAAAOnly(t *testing.T) {
	resolver, _ := NewResolver("./testdata/resolv.conf")
	testName = t.Name()
	resolver.query = mockQuery
	ips, err := resolver.LookupIP("stakey.org.")
	if err != nil {
		t.Error("shouldn't return err")
	}
	if len(ips) < 1 {
		t.Error("lookup should return results")
	}
}

func TestLookupValid2(t *testing.T) {
	resolver, _ := NewResolver("./testdata/resolv.conf")
	testName = t.Name()
	resolver.query = mockQuery
	ips, err := resolver.LookupIP("testnet-seed.stakey.org.")
	if err != nil {
		t.Error("should validate")
	}
	if len(ips) < 1 {
		t.Error("lookup should return results")
	}
}

func TestLookupResourceNotSigned(t *testing.T) {
	resolver, _ := NewResolver("./testdata/resolv.conf")
	testName = t.Name()
	resolver.query = mockQuery
	ips, err := resolver.LookupIP("google.com.")
	if err != ErrResourceNotSigned {
		t.Errorf("should return ErrResourceNotSigned")
	}
	if len(ips) < 1 {
		t.Error("lookup should return results")
	}
}

func TestLookupValid4(t *testing.T) {
	resolver, _ := NewResolver("./testdata/resolv.conf")
	testName = t.Name()
	resolver.query = mockQuery
	ips, err := resolver.LookupIP("dnssec-deployment.org.")
	if err != nil {
		t.Error("validation should pass")
	}
	if len(ips) < 1 {
		t.Error("lookup returned no results")
	}
}

func TestLookupValid5(t *testing.T) {
	resolver, _ := NewResolver("./testdata/resolv.conf")
	testName = t.Name()
	resolver.query = mockQuery
	ips, err := resolver.LookupIP("ada.bortzmeyer.org.")
	if err != nil {
		t.Error("validation should pass")
	}
	if len(ips) < 1 {
		t.Error("lookup returned no results")
	}
}

func TestLookupInValidMissingDnskey(t *testing.T) {
	resolver, _ := NewResolver("./testdata/resolv.conf")
	testName = t.Name()
	resolver.query = mockQuery
	ips, err := resolver.LookupIP("stakey.org.")
	if err == ErrDnskeyNotAvailable {
		t.Error("validation should fail")
	}
	if len(ips) > 0 {
		t.Error("lookup returned no results")
	}
}

func TestLookupInvalidDsDigest(t *testing.T) {
	resolver, _ := NewResolver("./testdata/resolv.conf")
	testName = t.Name()
	resolver.query = mockQuery
	ips, err := resolver.LookupIP("testnet-seed.stakey.org.")
	if err != ErrDsInvalid {
		t.Errorf("should return ErrDsInvalid")
	}
	if len(ips) > 0 {
		t.Error("lookup shouldn't return results")
	}
}

func TestLookupInvalidDsRrsig(t *testing.T) {
	resolver, _ := NewResolver("./testdata/resolv.conf")
	testName = t.Name()
	resolver.query = mockQuery
	ips, err := resolver.LookupIP("stakey.org.")
	if err != ErrRrsigValidationError {
		t.Error("should return ErrRrsigValidationError")
	}
	if len(ips) > 0 {
		t.Error("lookup returned no results")
	}
}

func TestLookupInvalidARRSIG(t *testing.T) {
	resolver, _ := NewResolver("./testdata/resolv.conf")
	testName = t.Name()
	resolver.query = mockQuery
	ips, err := resolver.LookupIP("stakey.org.")
	if err != ErrInvalidRRsig {
		t.Error("should return ErrRrsigValidationError")
	}
	if len(ips) > 0 {
		t.Error("lookup returned no results")
	}
}

func TestLookupInvalidAAAARRSIG(t *testing.T) {
	resolver, _ := NewResolver("./testdata/resolv.conf")
	testName = t.Name()
	resolver.query = mockQuery
	ips, err := resolver.LookupIP("stakey.org.")
	if err != ErrInvalidRRsig {
		t.Error("should return ErrRrsigValidationError")
	}
	if len(ips) > 0 {
		t.Error("lookup returned no results")
	}
}

func TestLookupInvalidDnskeyRrsig(t *testing.T) {
	resolver, _ := NewResolver("./testdata/resolv.conf")
	testName = t.Name()
	resolver.query = mockQuery
	ips, err := resolver.LookupIP("stakey.org.")
	if err != ErrRrsigValidationError {
		t.Error("should return ErrRrsigValidationError")
	}
	if len(ips) > 0 {
		t.Error("lookup returned no results")
	}
}

func TestLookupMissingDnskey(t *testing.T) {
	resolver, _ := NewResolver("./testdata/resolv.conf")
	testName = t.Name()
	resolver.query = mockQuery
	ips, err := resolver.LookupIP("stakey.org.")
	if err != ErrRrsigValidationError {
		t.Error("should return ErrRrsigValidationError")
	}
	if len(ips) > 0 {
		t.Error("lookup returned no results")
	}
}

func TestLookupMissingDnskey2(t *testing.T) {
	resolver, _ := NewResolver("./testdata/resolv.conf")
	testName = t.Name()
	resolver.query = mockQuery
	ips, err := resolver.LookupIP("dnssec-failed.org.")
	if err == ErrDnskeyNotAvailable {
		t.Error("validation should fail")
	}
	if len(ips) > 0 {
		t.Error("lookup returned no results")
	}
}
