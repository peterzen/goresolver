package goresolver

import (
	"testing"

	"github.com/miekg/dns"
)

func TestNewTrustAnchor(t *testing.T) {
	ta, err := NewTrustAnchor()
	if err != nil {
		t.Fatalf("NewTrustAnchor failed: %v", err)
	}
	if ta == nil {
		t.Fatal("NewTrustAnchor returned nil")
	}
	if len(ta.dnskeys) == 0 {
		t.Fatal("NewTrustAnchor should have at least one trust anchor")
	}

	// Verify that KSK-2017 (key tag 20326) is present
	foundKSK := false
	for _, key := range ta.dnskeys {
		if key.KeyTag() == 20326 {
			foundKSK = true
			// Verify it's a KSK (Key Signing Key)
			if key.Flags != 257 {
				t.Errorf("Expected KSK flag 257, got %d", key.Flags)
			}
			// Verify algorithm is RSA/SHA-256 (8)
			if key.Algorithm != 8 {
				t.Errorf("Expected algorithm 8, got %d", key.Algorithm)
			}
		}
	}
	if !foundKSK {
		t.Error("KSK-2017 (key tag 20326) not found in trust anchors")
	}
}

func TestVerifyRootZone_Valid(t *testing.T) {
	ta, err := NewTrustAnchor()
	if err != nil {
		t.Fatalf("NewTrustAnchor failed: %v", err)
	}

	// Create a mock root zone with the correct KSK
	rootZone := NewSignedZone(".")
	rootZone.pubKeyLookup = make(map[uint16]*dns.DNSKEY)
	
	// Add the trust anchor key to the root zone
	for _, key := range ta.dnskeys {
		rootZone.addPubKey(key)
	}
	
	rootZone.dnskey = &RRSet{
		rrSet: []dns.RR{ta.dnskeys[0]},
	}

	err = ta.VerifyRootZone(rootZone)
	if err != nil {
		t.Errorf("VerifyRootZone should succeed with matching trust anchor, got: %v", err)
	}
}

func TestVerifyRootZone_Invalid(t *testing.T) {
	ta, err := NewTrustAnchor()
	if err != nil {
		t.Fatalf("NewTrustAnchor failed: %v", err)
	}

	// Create a mock root zone with a different (wrong) key
	rootZone := NewSignedZone(".")
	rootZone.pubKeyLookup = make(map[uint16]*dns.DNSKEY)
	
	// Create a fake DNSKEY
	fakeKey := &dns.DNSKEY{
		Hdr: dns.RR_Header{
			Name:   ".",
			Rrtype: dns.TypeDNSKEY,
			Class:  dns.ClassINET,
		},
		Flags:     257,
		Protocol:  3,
		Algorithm: 8,
		PublicKey: "FakeKeyDataThatDoesNotMatchTrustAnchor==",
	}
	rootZone.addPubKey(fakeKey)
	rootZone.dnskey = &RRSet{
		rrSet: []dns.RR{fakeKey},
	}

	err = ta.VerifyRootZone(rootZone)
	if err != ErrRootZoneNotTrusted {
		t.Errorf("VerifyRootZone should fail with wrong key, expected ErrRootZoneNotTrusted, got: %v", err)
	}
}

func TestVerifyRootZone_NotRootZone(t *testing.T) {
	ta, err := NewTrustAnchor()
	if err != nil {
		t.Fatalf("NewTrustAnchor failed: %v", err)
	}

	// Try to verify a non-root zone
	zone := NewSignedZone("example.com.")
	
	err = ta.VerifyRootZone(zone)
	if err == nil || err.Error() != "not a root zone" {
		t.Errorf("VerifyRootZone should fail for non-root zone, got: %v", err)
	}
}

func TestKeysMatch(t *testing.T) {
	key1 := &dns.DNSKEY{
		Flags:     257,
		Protocol:  3,
		Algorithm: 8,
		PublicKey: "TestKeyData",
	}
	
	key2 := &dns.DNSKEY{
		Flags:     257,
		Protocol:  3,
		Algorithm: 8,
		PublicKey: "TestKeyData",
	}
	
	key3 := &dns.DNSKEY{
		Flags:     257,
		Protocol:  3,
		Algorithm: 8,
		PublicKey: "DifferentKeyData",
	}

	if !keysMatch(key1, key2) {
		t.Error("keysMatch should return true for identical keys")
	}
	
	if keysMatch(key1, key3) {
		t.Error("keysMatch should return false for different keys")
	}
}
