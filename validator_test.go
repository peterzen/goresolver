package dnssecvalidator

import (
	"github.com/miekg/dns"
	"testing"
)

func TestSetClientConfig(t *testing.T) {
	dnsClientConfig, err := dns.ClientConfigFromFile("./test/resolv.conf")

	if dnsClientConfig == nil || err != nil {
		t.Errorf("resolv.conf not found: %v", dnsClientConfig)
	}

	SetClientConfig(dnsClientConfig)
}

func TestDnsMessageInit(t *testing.T) {
	msg := dnsMessageInit()
	opt := msg.IsEdns0()
	if opt.Do() != true {
		t.Logf("DO bit not enabled")
	}
}
