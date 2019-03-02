package goresolver

import (
	"errors"
	"fmt"
	"github.com/miekg/dns"
	"log"
	"strings"
	"time"
)

const (
	DefaultTimeout = 5 * time.Second
)

type SignedRRSet struct {
	rrSet []dns.RR
	rrSig *dns.RRSIG
}

func (sRRset *SignedRRSet) IsSigned() bool {
	return sRRset.rrSig != nil
}

type ChainOfTrust struct {
	delegationChain []SignedZone
	a               SignedRRSet
	aaaa            SignedRRSet
}

type Resolver struct {
	query           func(string, uint16) (*dns.Msg, error)
	dnsClient       *dns.Client
	dnsClientConfig *dns.ClientConfig
}

var resolver *Resolver

var (
	ErrResourceNotSigned    = errors.New("resource is not signed with RRSIG")
	ErrRRnotAvailable       = errors.New("requested RR not found")
	ErrNsNotAvailable       = errors.New("no name server to answer the question")
	ErrDnskeyNotAvailable   = errors.New("DNSKEY RR does not exist")
	ErrDsNotAvailable       = errors.New("DS RR does not exist")
	ErrInvalidRRsig         = errors.New("invalid RRSIG")
	ErrRrsigValidationError = errors.New("RR doesn't validate against RRSIG")
	ErrRrsigValidityPeriod  = errors.New("invalid RRSIG validity period")
	ErrUnknownDsDigestType  = errors.New("unknown DS digest type")
	ErrDsInvalid            = errors.New("DS RR does not match DNSKEY")
)

func dnsMessageInit() *dns.Msg {
	dnsMessage := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			RecursionDesired: true,
		},
		Question: make([]dns.Question, 1),
	}
	dnsMessage.SetEdns0(4096, true)
	return dnsMessage
}

func localQuery(qname string, qtype uint16) (*dns.Msg, error) {
	dnsMessage := dnsMessageInit()
	dnsMessage.SetQuestion(qname, qtype)

	if resolver.dnsClientConfig == nil {
		return nil, errors.New("dns client not initialized")
	}

	for _, server := range resolver.dnsClientConfig.Servers {
		r, _, err := resolver.dnsClient.Exchange(dnsMessage, server+":"+resolver.dnsClientConfig.Port)
		if err != nil {
			return nil, err
		}
		if r == nil || r.Rcode == dns.RcodeNameError || r.Rcode == dns.RcodeSuccess {
			return r, err
		}
	}
	return nil, ErrNsNotAvailable
}

func queryDelegation(domainName string) (signedZone *SignedZone, err error) {

	signedZone = &SignedZone{
		zone:   domainName,
		ds:     SignedRRSet{},
		dnskey: SignedRRSet{},
	}

	// get DS record
	r, err := resolver.query(domainName, dns.TypeDS)
	if err != nil {
		log.Printf("cannot retrieve DS for %s: %v\n", domainName, err)
		return nil, nil
	}
	if r.Rcode == dns.RcodeNameError {
		log.Printf("no such domain %s\n", domainName)
		return nil, err
	}
	if r.Answer == nil {
		return nil, ErrDsNotAvailable
	}

	signedZone.ds.rrSet = make([]dns.RR, 0, len(r.Answer))

	for _, rr := range r.Answer {
		switch k := rr.(type) {
		case *dns.DS:
			signedZone.ds.rrSet = append(signedZone.ds.rrSet, k)
		case *dns.RRSIG:
			signedZone.ds.rrSig = k
		}
	}

	// get DNSKEY records
	r, err = resolver.query(domainName, dns.TypeDNSKEY)
	if err != nil || r == nil {
		fmt.Printf("Cannot retrieve DNSKEY %s: %s\n", domainName, err)
		return nil, err
	}

	signedZone.dnskey.rrSet = make([]dns.RR, 0, len(r.Answer))
	signedZone.signingKeys = make(map[uint16]*dns.DNSKEY)

	for _, rr := range r.Answer {
		switch k := rr.(type) {
		case *dns.DNSKEY:
			signedZone.dnskey.rrSet = append(signedZone.dnskey.rrSet, rr)
			signedZone.addSigningKey(k)
		case *dns.RRSIG:
			signedZone.dnskey.rrSig = k
		}
	}

	return signedZone, nil
}

func (res *Resolver) populateChainOfTrust(hostname string) (*ChainOfTrust, error) {

	chainOfTrust := &ChainOfTrust{
		a:    SignedRRSet{},
		aaaa: SignedRRSet{},
	}

	// get A records for the seed host
	r, err := resolver.query(hostname, dns.TypeA)

	if err != nil {
		log.Printf("Cannot retrieve A %v", err)
		return nil, err
	}

	if r.Answer != nil {
		chainOfTrust.a.rrSet = make([]dns.RR, 0, len(r.Answer))
		for _, rr := range r.Answer {
			switch t := rr.(type) {
			case *dns.A:
				chainOfTrust.a.rrSet = append(chainOfTrust.a.rrSet, rr)
			case *dns.RRSIG:
				chainOfTrust.a.rrSig = t
			}
		}
	}

	// get AAAA records for the seed host
	r, err = resolver.query(hostname, dns.TypeAAAA)
	if err != nil {
		log.Printf("Cannot retrieve A %v", err)
		return nil, err
	}

	if r.Answer != nil {
		chainOfTrust.aaaa.rrSet = make([]dns.RR, 0, len(r.Answer))
		for _, rr := range r.Answer {
			switch t := rr.(type) {
			case *dns.AAAA:
				chainOfTrust.aaaa.rrSet = append(chainOfTrust.aaaa.rrSet, rr)
			case *dns.RRSIG:
				chainOfTrust.aaaa.rrSig = t
			}
		}
	}

	if len(chainOfTrust.a.rrSet) < 1 && len(chainOfTrust.aaaa.rrSet) < 1 {
		log.Printf("A and AAAA RR not found: %s\n", hostname)
		return chainOfTrust, ErrRRnotAvailable
	}

	// TODO this should be a fatal error if DNSSEC validation
	// is set to strict mode
	if !chainOfTrust.a.IsSigned() && !chainOfTrust.aaaa.IsSigned() {
		return chainOfTrust, ErrResourceNotSigned
	}

	var signerName string

	if chainOfTrust.a.IsSigned() {
		signerName = chainOfTrust.a.rrSig.SignerName
	}

	if chainOfTrust.aaaa.IsSigned() {
		signerName = chainOfTrust.aaaa.rrSig.SignerName
	}

	qnameComponents := strings.Split(signerName, ".")
	// optimization - we're trusting the TLD (i.e. .org) zone and will only
	// verify the zones up to the TLD
	zonesToVerify := len(qnameComponents) - 1
	if zonesToVerify < 0 {
		zonesToVerify = 0
	}

	chainOfTrust.delegationChain = make([]SignedZone, 0, zonesToVerify)

	for i := 0; i < zonesToVerify; i++ {
		zoneName := dns.Fqdn(strings.Join(qnameComponents[i:], "."))
		delegation, err := queryDelegation(zoneName)
		if err != nil || delegation == nil {
			//log.Printf("zone query failed: %v\n", err)
			return nil, err
		}
		if i > 0 {
			chainOfTrust.delegationChain[i-1].parentZone = delegation
		}
		chainOfTrust.delegationChain = append(chainOfTrust.delegationChain, *delegation)
	}

	return chainOfTrust, nil
}

// DNSSEC chain of trust verification
func verifyChainOfTrust(chainOfTrust *ChainOfTrust) (err error) {

	if chainOfTrust.delegationChain == nil {
		return ErrDnskeyNotAvailable
	}

	signedZone := chainOfTrust.delegationChain[0]

	// Verify the RRSIG of the requested RRset with the public ZSK.
	if len(chainOfTrust.a.rrSet) > 0 {
		err := signedZone.verifyRRSIG(chainOfTrust.a.rrSig, chainOfTrust.a.rrSet)
		if err != nil {
			fmt.Printf("validation A: %s\n", err)
			return ErrInvalidRRsig
		}
	}

	if len(chainOfTrust.aaaa.rrSet) > 0 {
		err := signedZone.verifyRRSIG(chainOfTrust.aaaa.rrSig, chainOfTrust.aaaa.rrSet)
		if err != nil {
			fmt.Printf("validation AAAA: %s\n", err)
			return ErrInvalidRRsig
		}
	}

	for _, signedZone := range chainOfTrust.delegationChain {

		if len(signedZone.dnskey.rrSet) == 0 {
			log.Printf("DNSKEY RR does not exist on %s\n", signedZone.zone)
			return ErrDnskeyNotAvailable
		}

		// Verify the RRSIG of the DNSKEY RRset with the public KSK.
		err := signedZone.verifyRRSIG(signedZone.dnskey.rrSig, signedZone.dnskey.rrSet)

		if err != nil {
			log.Printf("validation DNSKEY: %s\n", err)
			return ErrRrsigValidationError
		}

		if len(signedZone.ds.rrSet) < 1 {
			log.Printf("DS RR is not available on zone %s\n", signedZone.zone)
			return ErrDsNotAvailable
		}

		if signedZone.parentZone != nil {
			err := signedZone.parentZone.verifyRRSIG(signedZone.ds.rrSig, signedZone.ds.rrSet)
			if err != nil {
				log.Printf("DS on %s doesn't validate against RRSIG %d\n", signedZone.zone, signedZone.ds.rrSig.KeyTag)
				return ErrRrsigValidationError
			}
		}

		err = signedZone.verifyDS(signedZone.ds.rrSet)
		if err != nil {
			log.Printf("DS does not validate: %s", err)
			return ErrDsInvalid
		}
	}

	return nil
}

func NewResolver(resolvConf string) (res *Resolver, err error) {
	resolver = &Resolver{}
	resolver.dnsClient = &dns.Client{
		ReadTimeout: DefaultTimeout,
	}
	resolver.dnsClientConfig, err = dns.ClientConfigFromFile(resolvConf)
	if err != nil {
		return nil, err
	}
	resolver.query = localQuery
	return resolver, nil
}
