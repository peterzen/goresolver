package goresolver

import (
	"github.com/miekg/dns"
	"log"
	"strings"
)

type AuthenticationChain struct {
	zone            string
	delegationChain []SignedZone
}

func (authChain *AuthenticationChain) Populate(domainName string) error {

	qnameComponents := strings.Split(domainName, ".")
	// TODO make this verify all the way up to the root zone
	zonesToVerify := len(qnameComponents) - 1

	if zonesToVerify < 0 {
		zonesToVerify = 0
	}

	authChain.delegationChain = make([]SignedZone, 0, zonesToVerify)

	for i := 0; i < zonesToVerify; i++ {
		zoneName := dns.Fqdn(strings.Join(qnameComponents[i:], "."))
		delegation, err := queryDelegation(zoneName)
		if err != nil {
			//log.Printf("zone queryFn failed: %v\n", err)
			return err
		}
		if i > 0 {
			authChain.delegationChain[i-1].parentZone = delegation
		}
		authChain.delegationChain = append(authChain.delegationChain, *delegation)
	}
	return nil
}

// DNSSEC chain of trust verification
func (authChain *AuthenticationChain) Verify(answerRRset *SignedRRSet) error {

	if authChain.delegationChain == nil {
		return ErrDnskeyNotAvailable
	}

	signedZone := authChain.delegationChain[0]
	if !signedZone.checkHasDnskeys() {
		return ErrDnskeyNotAvailable
	}

	err := signedZone.verifyRRSIG(answerRRset)
	if err != nil {
		log.Println("RRSIG didn't verify", err)
		return ErrInvalidRRsig
	}

	for _, signedZone := range authChain.delegationChain {

		if signedZone.dnskey.IsEmpty() {
			log.Printf("DNSKEY RR does not exist on %s\n", signedZone.zone)
			return ErrDnskeyNotAvailable
		}

		// Verify the RRSIG of the DNSKEY RRset with the public KSK.
		err := signedZone.verifyRRSIG(signedZone.dnskey)
		if err != nil {
			log.Printf("validation DNSKEY: %s\n", err)
			return ErrRrsigValidationError
		}

		if signedZone.ds.IsEmpty() {
			log.Printf("DS RR is not available on zone %s\n", signedZone.zone)
			return ErrDsNotAvailable
		}

		if signedZone.parentZone != nil {
			err := signedZone.parentZone.verifyRRSIG(signedZone.ds)
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

func NewChainOfTrust() *AuthenticationChain {
	return &AuthenticationChain{}
}
