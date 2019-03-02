package goresolver

import (
	"github.com/miekg/dns"
	"log"
	"net"
)

const MaxReturnedIPAddressesCount = 64

func (resolver *Resolver) LookupIP(qname string) (ips []net.IP, err error) {

	if len(qname) < 1 {
		return nil, nil
	}

	qtypes := []uint16{dns.TypeA, dns.TypeAAAA}

	answers := make([]*SignedRRSet, 0, len(qtypes))

	for _, qtype := range qtypes {

		answer, err := querySignedRRset(qname, qtype)
		if answer == nil {
			continue
		}
		if err != nil {
			continue
		}
		if answer.IsEmpty() {
			continue
		}
		if !answer.IsSigned() {
			continue
		}

		answers = append(answers, answer)
	}

	if len(answers) < 1 {
		log.Printf("no results")
		return nil, ErrNoResult
	}

	signerName := answers[0].SignerName()
	chainOfTrust := NewChainOfTrust()
	err = chainOfTrust.Populate(signerName)
	if err != nil {
		log.Printf("Cannot populate chain of trust: %s\n", err)
		return nil, err
	}
	resultIPs := make([]net.IP, MaxReturnedIPAddressesCount)
	for _, answer := range answers {
		err = chainOfTrust.Verify(answer)
		if err != nil {
			log.Printf("DNSSEC validation failed: %s\n", err)
			continue
		}
		ips := formatResultRRs(answer)
		resultIPs = append(resultIPs, ips...)
	}

	return resultIPs, nil
}

func (resolver *Resolver) LookupIPv4(qname string) (ips []net.IP, err error) {
	return resolver.LookupIPType(qname, dns.TypeA)
}

func (resolver *Resolver) LookupIPv6(qname string) (ips []net.IP, err error) {
	return resolver.LookupIPType(qname, dns.TypeAAAA)
}

func (resolver *Resolver) LookupIPType(qname string, qtype uint16) (ips []net.IP, err error) {

	if len(qname) < 1 {
		return nil, nil
	}

	answer, err := querySignedRRset(qname, qtype)
	if answer == nil {
		return nil, ErrNoResult
	}

	if err != nil {
		return nil, err
	}

	if !answer.IsSigned() {
		return formatResultRRs(answer), ErrResourceNotSigned
	}

	signerName := answer.SignerName()
	chainOfTrust := NewChainOfTrust()
	err = chainOfTrust.Populate(signerName)
	if err != nil {
		log.Printf("Cannot populate chain of trust: %s\n", err)
		return nil, err
	}

	err = chainOfTrust.Verify(answer)
	if err != nil {
		log.Printf("DNSSEC validation failed: %s\n", err)
		return nil, err
	}

	return formatResultRRs(answer), nil
}

func (resolver *Resolver) StrictNSQuery(qname string, qtype uint16) (rrSet []dns.RR, err error) {

	if len(qname) < 1 {
		return nil, nil
	}

	answer, err := querySignedRRset(qname, qtype)
	if err != nil {
		return nil, err
	}

	if answer == nil {
		return nil, ErrNoResult
	}

	if !answer.IsSigned() {
		return nil, ErrResourceNotSigned
	}

	signerName := answer.SignerName()

	chainOfTrust := NewChainOfTrust()
	err = chainOfTrust.Populate(signerName)

	if err == ErrNoResult {
		return nil, err
	}

	err = chainOfTrust.Verify(answer)
	if err != nil {
		log.Printf("DNSSEC validation failed: %s\n", err)
		return nil, err
	}

	return answer.rrSet, nil
}

func formatResultRRs(signedRrset *SignedRRSet) []net.IP {
	ips := make([]net.IP, 0, len(signedRrset.rrSet))
	for _, rr := range signedRrset.rrSet {
		switch t := rr.(type) {
		case *dns.A:
			ips = append(ips, t.A)
		case *dns.AAAA:
			ips = append(ips, t.AAAA)
		}
	}
	return ips
}
