package goresolver

import (
	"github.com/miekg/dns"
	"log"
	"strings"
	"time"
)

type SignedZone struct {
	zone        string
	dnskey      *SignedRRSet
	ds          *SignedRRSet
	parentZone  *SignedZone
	signingKeys map[uint16]*dns.DNSKEY
}

func (z SignedZone) getKeyByTag(keyTag uint16) *dns.DNSKEY {
	return z.signingKeys[keyTag]
}

func (z SignedZone) addSigningKey(k *dns.DNSKEY) {
	z.signingKeys[k.KeyTag()] = k
}

func (z SignedZone) verifyRRSIG(sig *dns.RRSIG, rrSet []dns.RR) (err error) {
	if sig == nil {
		return ErrInvalidRRsig
	}
	// Verify the RRSIG of the DNSKEY RRset
	key := z.getKeyByTag(sig.KeyTag)
	if key == nil {
		log.Printf("DNSKEY keytag %d not found", sig.KeyTag)
		return ErrDnskeyNotAvailable
	}
	err = sig.Verify(key, rrSet)

	if err != nil {
		log.Println("DNSKEY verification", err)
		return err
	}

	if !sig.ValidityPeriod(time.Now()) {
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
		key := z.getKeyByTag(ds.KeyTag)
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

func (z *SignedZone) checkDnskeys() (bool, error) {
	if len(z.dnskey.rrSet) < 2 {
		return false, ErrDnskeyNotAvailable
	}
	return true, nil
}
