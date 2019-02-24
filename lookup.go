package dnssecvalidator

import (
	"github.com/miekg/dns"
	"log"
	"net"
)

func LookupIP(qname string) (ips []net.IP, err error) {

	if len(qname) < 1 {
		return nil, nil
	}

	chainOfTrust, err := populateChainOfTrust(qname)

	if chainOfTrust == nil {
		return net.LookupIP(qname)
	}

	if err != nil {
		log.Printf("Cannot populate chain of trust: %s\n", err)
		return nil, err
	}

	err = validateChainOfTrust(chainOfTrust)
	if err != nil {
		log.Printf("DNSSEC validation failed: %s\n", err)
		return nil, err
	}

	ips = make([]net.IP, 0, len(chainOfTrust.a.rrSet)+len(chainOfTrust.aaaa.rrSet))
	for _, answer := range chainOfTrust.a.rrSet {
		switch t := answer.(type) {
		case *dns.A:
			ips = append(ips, t.A)
		}
	}
	for _, answer := range chainOfTrust.aaaa.rrSet {
		switch t := answer.(type) {
		case *dns.AAAA:
			ips = append(ips, t.AAAA)
		}
	}
	return ips, nil
}

func LookupAddr(addr string) (names []string, err error) {

	ips, err := LookupIP(addr)
	if err != nil {
		return nil, err
	}
	names = make([]string, 0, len(ips))
	for _, ip := range ips {
		names = append(names, ip.String())
	}
	return names, nil
}
