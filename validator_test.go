package goresolver

import (
	"testing"
)

func TestSetClientConfig(t *testing.T) {
	resolver, err := NewResolver("./testdata/resolv.conf")
	if resolver.dnsClientConfig == nil || err != nil {
		t.Errorf("resolv.conf not found: %v", resolver.dnsClientConfig)
	}
}

func TestDnsMessageInit(t *testing.T) {
	msg := dnsMessageInit()
	opt := msg.IsEdns0()
	if opt.Do() != true {
		t.Logf("DO bit not enabled")
	}
}

func TestPopulateChainOfTrust(t *testing.T) {
	//var Config = spew.ConfigState{
	//	Indent:                  " ",
	//	DisablePointerMethods:   false,
	//	DisableCapacities:       true,
	//	DisablePointerAddresses: true,
	//}
	//resolver, err := NewResolver("./testdata/resolv.conf")
	//chainOfTrust, err := resolver.populateChainOfTrust("testnet-seed.decred.org.")
	//
	//if err != nil || chainOfTrust == nil {
	//	t.Error("populateChainOfTrust unexpected return value")
	//}
	//fmt.Printf("%#v", chainOfTrust)
	//m,err:=json.Marshal(chainOfTrust)
	//fmt.Printf("%s\n\n",m)
	//Config.Dump(chainOfTrust)
	//fmt.Printf("%v", chainOfTrust)
}

func TestValidateChainOfTrust(t *testing.T) {

}
