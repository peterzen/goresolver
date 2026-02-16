package goresolver

import (
	"errors"

	"github.com/miekg/dns"
)

// ErrRootZoneNotTrusted is returned when the root zone DNSKEY does not
// match any configured trust anchor
var ErrRootZoneNotTrusted = errors.New("root zone DNSKEY does not match trust anchor")

// TrustAnchor represents a DNSSEC trust anchor for the root zone
type TrustAnchor struct {
	dnskeys []*dns.DNSKEY
}

// defaultRootTrustAnchors contains the official IANA root zone trust anchors
// These are the KSK (Key Signing Key) records for the root zone
//
// KSK-2017 (Key Tag 20326) - Currently active
// Reference: https://www.iana.org/dnssec/files
var defaultRootTrustAnchors = []string{
	// KSK-2017 (Key Tag 20326)
	". IN DNSKEY 257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=",
}

// NewTrustAnchor creates a new TrustAnchor with the default root zone
// trust anchors
func NewTrustAnchor() (*TrustAnchor, error) {
	ta := &TrustAnchor{
		dnskeys: make([]*dns.DNSKEY, 0, len(defaultRootTrustAnchors)),
	}

	for _, anchor := range defaultRootTrustAnchors {
		rr, err := dns.NewRR(anchor)
		if err != nil {
			return nil, err
		}
		dnskey, ok := rr.(*dns.DNSKEY)
		if !ok {
			return nil, errors.New("trust anchor is not a DNSKEY record")
		}
		ta.dnskeys = append(ta.dnskeys, dnskey)
	}

	return ta, nil
}

// VerifyRootZone validates that the root zone DNSKEY matches one of the
// configured trust anchors. It returns nil if validation succeeds.
func (ta *TrustAnchor) VerifyRootZone(rootZone SignedZone) error {
	if rootZone.zone != "." {
		return errors.New("not a root zone")
	}

	// Check that at least one of the KSKs in the root zone matches
	// a trust anchor
	for _, trustAnchor := range ta.dnskeys {
		trustAnchorKeyTag := trustAnchor.KeyTag()
		
		// Look up the key in the root zone by key tag
		rootKey := rootZone.lookupPubKey(trustAnchorKeyTag)
		if rootKey == nil {
			continue
		}

		// Compare the DNSKEY records
		if keysMatch(trustAnchor, rootKey) {
			return nil
		}
	}

	return ErrRootZoneNotTrusted
}

// keysMatch compares two DNSKEY records for equality
func keysMatch(a, b *dns.DNSKEY) bool {
	return a.Flags == b.Flags &&
		a.Protocol == b.Protocol &&
		a.Algorithm == b.Algorithm &&
		a.PublicKey == b.PublicKey
}
