package goresolver

import (
	"github.com/miekg/dns"
	"log"
	"strings"
	"time"
)

type SignedZone struct {
	zone         string
	dnskey       *RRSet
	ds           *RRSet
	parentZone   *SignedZone
	pubKeyLookup map[uint16]*dns.DNSKEY
}

func (z SignedZone) lookupPubKey(keyTag uint16) *dns.DNSKEY {
	return z.pubKeyLookup[keyTag]
}

func (z SignedZone) addPubKey(k *dns.DNSKEY) {
	z.pubKeyLookup[k.KeyTag()] = k
}

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

func (z *SignedZone) checkHasDnskeys() bool {
	return len(z.dnskey.rrSet) > 0
}

func NewSignedZone(domainName string) *SignedZone {
	return &SignedZone{
		zone:   domainName,
		ds:     &RRSet{},
		dnskey: &RRSet{},
	}
}
