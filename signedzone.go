package goresolver

import (
	"github.com/miekg/dns"
	"log"
	"strings"
	"time"
)

// SignedZone represents a DNSSEC-enabled zone, its DNSKEY and DS records
type SignedZone struct {
	zone         string
	dnskey       *RRSet
	ds           *RRSet
	parentZone   *SignedZone
	pubKeyLookup map[uint16]*dns.DNSKEY
}

// lookupPubkey returns a DNSKEY by its keytag
func (z SignedZone) lookupPubKey(keyTag uint16) *dns.DNSKEY {
	return z.pubKeyLookup[keyTag]
}

// addPubkey stores a DNSKEY in the keytag lookup table.
func (z SignedZone) addPubKey(k *dns.DNSKEY) {
	z.pubKeyLookup[k.KeyTag()] = k
}

// verifyRRSIG verifies the signature on a signed
// RRSET, and checks the validity period on the RRSIG.
// It returns nil if the RRSIG verifies and the signature
// is valid, and the appropriate error value in case
// of validation failure.
func (z SignedZone) verifyRRSIG(signedRRset *RRSet) (err error) {

	if !signedRRset.IsSigned() {
		return ErrInvalidRRsig
	}

	// Verify the RRSIG of the DNSKEY RRset
	key := z.lookupPubKey(signedRRset.rrSig.KeyTag)
	if key == nil {
		log.Printf("DNSKEY keytag %d not found", signedRRset.rrSig.KeyTag)
		return ErrDnskeyNotAvailable
	}

	err = signedRRset.rrSig.Verify(key, signedRRset.rrSet)
	if err != nil {
		log.Println("DNSKEY verification", err)
		return err
	}

	if !signedRRset.rrSig.ValidityPeriod(time.Now()) {
		log.Println("invalid validity period", err)
		return ErrRrsigValidityPeriod
	}
	return nil
}

// verifyDS validates the DS record against the KSK
// (key signing key) of the zone.
// Return nil if the DS record matches the digest of
// the KSK.
func (z SignedZone) verifyDS(dsRrset []dns.RR) (err error) {

	for _, rr := range dsRrset {

		ds := rr.(*dns.DS)

		if ds.DigestType != dns.SHA256 {
			log.Printf("Unknown digest type (%d) on DS RR", ds.DigestType)
			continue
		}

		parentDsDigest := strings.ToUpper(ds.Digest)
		key := z.lookupPubKey(ds.KeyTag)
		if key == nil {
			log.Printf("DNSKEY keytag %d not found", ds.KeyTag)
			return ErrDnskeyNotAvailable
		}
		dsDigest := strings.ToUpper(key.ToDS(ds.DigestType).Digest)
		if parentDsDigest == dsDigest {
			return nil
		}

		log.Printf("DS does not match DNSKEY\n")
		return ErrDsInvalid
	}
	return ErrUnknownDsDigestType
}

// checkHasDnskeys returns true if the SignedZone has a DNSKEY
// record, false otherwise.
func (z *SignedZone) checkHasDnskeys() bool {
	return len(z.dnskey.rrSet) > 0
}

// NewSignedZone initializes a new SignedZone and returns it.
func NewSignedZone(domainName string) *SignedZone {
	return &SignedZone{
		zone:   domainName,
		ds:     &RRSet{},
		dnskey: &RRSet{},
	}
}
