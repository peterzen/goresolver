package goresolver

import (
	"github.com/miekg/dns"
	"log"
	"strings"
)

// AuthenticationChain represents the DNSSEC chain of trust from the
// queried zone to the root (.) zone.  In order for a zone to validate,
// it is required that each zone in the chain validate against its
// parent using the DS record.
//
// https://www.ietf.org/rfc/rfc4033.txt
type AuthenticationChain struct {
	delegationChain []SignedZone
}

// Populate queries the RRs required for the zone validation
// It begins the queries at the *domainName* zone and then walks
// up the delegation tree all the way up to the root zone, thus
// populating a linked list of SignedZone objects.
func (authChain *AuthenticationChain) Populate(domainName string) error {

	qnameComponents := strings.Split(domainName, ".")
	zonesToVerify := len(qnameComponents)
	// TODO add test case
	if zonesToVerify < 0 {
		zonesToVerify = 0
	}

	authChain.delegationChain = make([]SignedZone, 0, zonesToVerify)
	for i := 0; i < zonesToVerify; i++ {
		zoneName := dns.Fqdn(strings.Join(qnameComponents[i:], "."))
		delegation, err := queryDelegation(zoneName)
		if err != nil {
			return err
		}
		if i > 0 {
			authChain.delegationChain[i-1].parentZone = delegation
		}
		authChain.delegationChain = append(authChain.delegationChain, *delegation)
	}
	return nil
}

// Verify uses the zone data in delegationChain to validate the DNSSEC
// chain of trust.
// It starts the verification in the RRSet supplied as parameter (verifies
// the RRSIG on the answer RRs), and, assuming a signature is correct and
// valid, it walks through the delegationChain checking the RRSIGs on
// the DNSKEY and DS resource record sets, as well as correctness of each
// delegation using the lower level methods in SignedZone.
func (authChain *AuthenticationChain) Verify(answerRRset *RRSet) error {

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

		if signedZone.parentZone != nil {

			if signedZone.ds.IsEmpty() {
				log.Printf("DS RR is not available on zoneName %s\n", signedZone.zone)
				return ErrDsNotAvailable
			}

			err := signedZone.parentZone.verifyRRSIG(signedZone.ds)
			if err != nil {
				log.Printf("DS on %s doesn't validate against RRSIG %d\n", signedZone.zone, signedZone.ds.rrSig.KeyTag)
				return ErrRrsigValidationError
			}
			err = signedZone.verifyDS(signedZone.ds.rrSet)
			if err != nil {
				log.Printf("DS does not validate: %s", err)
				return ErrDsInvalid
			}
		}
	}
	return nil
}

// NewAuthenticationChain initializes an AuthenticationChain object and
// returns a reference to it.
func NewAuthenticationChain() *AuthenticationChain {
	return &AuthenticationChain{}
}
