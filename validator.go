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
	DefaultTimeout time.Duration = 5 * time.Second
)

var (
	dnsClient       *dns.Client
	dnsClientConfig *dns.ClientConfig
)

var (
	ErrNsNotAvailable       = errors.New("no name server to answer the question")
	ErrDnskeyNotAvailable   = errors.New("DNSKEY RR does not exist")
	ErrDsNotAvailable       = errors.New("DS RR does not exist")
	ErrRrsigValidationError = errors.New("RR doesn't validate against RRSIG")
	ErrRrsigValidityPeriod  = errors.New("invalid RRSIG validity period")
	ErrUnknownDsDigestType  = errors.New("unknown DS digest type")
	ErrDsInvalid            = errors.New("DS RR does not match DNSKEY")
)

type SignedRRSet struct {
	rrSet []dns.RR
	rrSig *dns.RRSIG
}

type ChainOfTrust struct {
	delegationChain []SignedZone
	a               *SignedRRSet
	aaaa            *SignedRRSet
}

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

func SetClientConfig(config *dns.ClientConfig) {
	dnsClientConfig = config
}

func query(qname string, qtype uint16) (*dns.Msg, error) {
	dnsMessage := dnsMessageInit()
	dnsMessage.SetQuestion(qname, qtype)

	if dnsClientConfig == nil {
		return nil, errors.New("dns client not initialized")
	}

	for _, server := range dnsClientConfig.Servers {
		r, _, err := dnsClient.Exchange(dnsMessage, server+":"+dnsClientConfig.Port)
		if err != nil {
			return nil, err
		}
		if r == nil || r.Rcode == dns.RcodeNameError || r.Rcode == dns.RcodeSuccess {
			return r, err
		}
	}
	return nil, ErrNsNotAvailable
}

func populateChainOfTrust(qname string) (*ChainOfTrust, error) {

	dnsClient = &dns.Client{
		ReadTimeout: DefaultTimeout,
	}

	chainOfTrust := &ChainOfTrust{}

	queryDelegation := func(qname string) (signedZone *SignedZone, err error) {

		signedZone = &SignedZone{
			zone:   qname,
			ds:     SignedRRSet{},
			dnskey: SignedRRSet{},
		}

		// get DS record
		r, err := query(qname, dns.TypeDS)
		if err != nil || r.Answer == nil {
			log.Printf("Cannot retrieve DS for %s: %v\n", qname, err)
			return nil, nil
		}
		if r.Rcode == dns.RcodeNameError {
			fmt.Printf("No such domain %s\n", qname)
			return nil, err
		}

		signedZone.ds.rrSet = make([]dns.RR, 0, len(r.Answer))

		for _, rr := range r.Answer {
			switch k := rr.(type) {
			case *dns.RRSIG:
				signedZone.ds.rrSig = k
			case *dns.DS:
				signedZone.ds.rrSet = append(signedZone.ds.rrSet, k)
			}
		}

		// get DNSKEY records
		r, err = query(qname, dns.TypeDNSKEY)
		if err != nil || r == nil {
			fmt.Printf("Cannot retrieve DNSKEY %s: %s\n", qname, err)
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

	qnameComponents := strings.Split(qname, ".")
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

	// get A records for the seed host
	r, err := query(qname, dns.TypeA)
	if err != nil || r == nil {
		fmt.Printf("Cannot retrieve A %s: %s\n", qname, err)
		return nil, err
	}

	chainOfTrust.a = &SignedRRSet{}
	chainOfTrust.a.rrSet = make([]dns.RR, 0, len(r.Answer))

	for _, rr := range r.Answer {
		switch t := rr.(type) {
		case *dns.A:
			chainOfTrust.a.rrSet = append(chainOfTrust.a.rrSet, rr)
		case *dns.RRSIG:
			chainOfTrust.a.rrSig = t
		}
	}

	// get AAAA records for the seed host
	r, err = query(qname, dns.TypeAAAA)
	if err != nil || r == nil {
		fmt.Printf("Cannot retrieve AAAA %s: %s\n", qname, err)
		return chainOfTrust, err
	}

	chainOfTrust.aaaa = &SignedRRSet{}
	chainOfTrust.aaaa.rrSet = make([]dns.RR, 0, len(r.Answer))

	for _, rr := range r.Answer {
		switch t := rr.(type) {
		case *dns.AAAA:
			chainOfTrust.aaaa.rrSet = append(chainOfTrust.aaaa.rrSet, rr)
		case *dns.RRSIG:
			chainOfTrust.aaaa.rrSig = t
		}
	}
	return chainOfTrust, nil
}

// DNSSEC chain of trust validation
func validateChainOfTrust(chainOfTrust *ChainOfTrust) (err error) {

	signedZone := chainOfTrust.delegationChain[0]

	// Verify the RRSIG of the requested RRset with the public ZSK.
	if len(chainOfTrust.a.rrSet) > 0 {
		err := signedZone.validateRRSIG(chainOfTrust.a.rrSig, chainOfTrust.a.rrSet)
		if err != nil {
			fmt.Printf("validation A: %s\n", err)
			return err
		}
	}

	if len(chainOfTrust.aaaa.rrSet) > 0 {
		err := signedZone.validateRRSIG(chainOfTrust.aaaa.rrSig, chainOfTrust.aaaa.rrSet)
		if err != nil {
			fmt.Printf("validation AAAA: %s\n", err)
			return err
		}
	}

	for _, signedZone := range chainOfTrust.delegationChain {

		if len(signedZone.dnskey.rrSet) == 0 {
			log.Printf("DNSKEY RR does not exist on %s\n", signedZone.zone)
			return ErrDnskeyNotAvailable
		}

		// Verify the RRSIG of the DNSKEY RRset with the public KSK.
		err := signedZone.validateRRSIG(signedZone.dnskey.rrSig, signedZone.dnskey.rrSet)

		if err != nil {
			log.Printf("validation DNSKEY: %s\n", err)
			return ErrRrsigValidationError
		}

		if len(signedZone.ds.rrSet) < 1 {
			log.Printf("DS RR is not available on zone %s\n", signedZone.zone)
			return ErrDsNotAvailable
		}

		if signedZone.parentZone != nil {
			err := signedZone.parentZone.validateRRSIG(signedZone.ds.rrSig, signedZone.ds.rrSet)
			if err != nil {
				log.Printf("DS on %s doesn't validate against RRSIG %d\n", signedZone.zone, signedZone.ds.rrSig.KeyTag)
				return ErrDsInvalid
			}
		}

		err = signedZone.validateDS(signedZone.ds.rrSet)
		if err != nil {
			log.Printf("DS does not validate: %s", err)
			return ErrDsInvalid
		}
	}

	return nil
}

func Initialize(resolvConf string) (err error) {
	dnsClientConfig, err = dns.ClientConfigFromFile(resolvConf)
	return err
}
