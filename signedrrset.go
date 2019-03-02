package goresolver

import (
	"github.com/miekg/dns"
	"log"
)

type SignedRRSet struct {
	rrSet []dns.RR
	rrSig *dns.RRSIG
}

func querySignedRRset(qname string, qtype uint16) (*SignedRRSet, error) {

	r, err := resolver.queryFn(qname, qtype)

	if err != nil {
		log.Printf("cannot lookup %v", err)
		return nil, err
	}

	if r.Rcode == dns.RcodeNameError {
		log.Printf("no such domain %s\n", qname)
		return nil, ErrNoResult
	}

	if r.Answer == nil {
		return nil, ErrNoResult
	}

	result := NewSignedRRSet()
	result.rrSet = make([]dns.RR, 0, len(r.Answer))

	for _, rr := range r.Answer {
		switch t := rr.(type) {
		case *dns.RRSIG:
			result.rrSig = t
		default:
			if rr != nil {
				result.rrSet = append(result.rrSet, rr)
			}
		}
	}
	return result, nil
}

func (sRRset *SignedRRSet) IsSigned() bool {
	return sRRset.rrSig != nil
}

func (sRRset *SignedRRSet) IsEmpty() bool {
	return len(sRRset.rrSet) < 1
}

func (sRRset *SignedRRSet) SignerName() string {
	return sRRset.rrSig.SignerName
}

func NewSignedRRSet() *SignedRRSet {
	return &SignedRRSet{
		rrSet: make([]dns.RR, 0),
	}
}
