package dnssecvalidator

import (
	"github.com/miekg/dns"
	"testing"
)

func TestLookupInvalid1(t *testing.T) {
	dnsClientConfig, err := dns.ClientConfigFromFile("./testdata/resolv.conf")
	SetClientConfig(dnsClientConfig)
	ips, err := LookupIP("sigfail.verteiltesysteme.net.")
	if err == nil {
		t.Errorf("dnssec validation failed: %v", err)
	}
	if len(ips) > 0 {
		t.Error("lookup should return no results")
	}
}

func TestLookupInvalid2(t *testing.T) {
	dnsClientConfig, err := dns.ClientConfigFromFile("./testdata/resolv.conf")
	SetClientConfig(dnsClientConfig)
	ips, err := LookupIP("invalid.stakey.org.")
	if err == nil {
		t.Errorf("dnssec validation failed: %v", err)
	}
	if len(ips) > 0 {
		t.Error("lookup should return no results")
	}
}

func TestLookupValid1(t *testing.T) {
	err := Initialize("./testdata/resolv.conf")
	if err != nil {
		t.Errorf("dnssec initialization failed: %v", err)
	}
	ips, err := LookupIP("stakey.org.")
	if err != nil {
		t.Errorf("dnssec validation failed: %v", err)
	}
	if len(ips) != 0 {
		t.Error("lookup returned unexpected results")
	}
}

func TestLookupValid2(t *testing.T) {
	err := Initialize("./testdata/resolv.conf")
	if err != nil {
		t.Errorf("dnssec initialization failed: %v", err)
	}
	ips, err := LookupIP("testnet-seed.stakey.org.")
	if err != nil {
		t.Errorf("dnssec validation failed: %v", err)
	}
	if len(ips) < 1 {
		t.Error("lookup returned no results")
	}
}

func TestLookupValid3(t *testing.T) {
	err := Initialize("./testdata/resolv.conf")
	if err != nil {
		t.Errorf("dnssec initialization failed: %v", err)
	}
	ips, err := LookupIP("google.com.")
	if err != nil {
		t.Errorf("dnssec validation failed: %v", err)
	}
	if len(ips) < 1 {
		t.Error("lookup returned no results")
	}
}

func TestLookupAddr(t *testing.T) {
	err := Initialize("./testdata/resolv.conf")
	if err != nil {
		t.Errorf("dnssec initialization failed: %v", err)
	}
	names, err := LookupAddr("decred.org.")
	if err != nil {
		t.Errorf("err should be nil %#v", err)
	}
	if len(names) < 1 {
		t.Error("lookup returned no results")
	}
}
