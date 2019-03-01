package goresolver

import (
	"github.com/miekg/dns"
	"log"
	"net"
)

func (res *Resolver) LookupIP(qname string) (ips []net.IP, err error) {

	if len(qname) < 1 {
		return nil, nil
	}

	chainOfTrust, err := res.populateChainOfTrust(qname)

	if err == ErrRRnotAvailable {
		return make([]net.IP, 0), ErrRRnotAvailable
	}

	if err == ErrResourceNotSigned {
		return formatResultRRs(chainOfTrust), ErrResourceNotSigned
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

	return formatResultRRs(chainOfTrust), nil

}

func formatResultRRs(chainOfTrust *ChainOfTrust) []net.IP {
	ips := make([]net.IP, 0, len(chainOfTrust.a.rrSet)+len(chainOfTrust.aaaa.rrSet))
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
	return ips
}
