package goresolver

import (
	"errors"
	"github.com/miekg/dns"
	"time"
)

const (
	DefaultTimeout = 5 * time.Second
)

type Resolver struct {
	queryFn         func(string, uint16) (*dns.Msg, error)
	dnsClient       *dns.Client
	dnsClientConfig *dns.ClientConfig
}

var (
	ErrResourceNotSigned    = errors.New("resource is not signed with RRSIG")
	ErrNoResult             = errors.New("requested RR not found")
	ErrNsNotAvailable       = errors.New("no name server to answer the question")
	ErrDnskeyNotAvailable   = errors.New("DNSKEY RR does not exist")
	ErrDsNotAvailable       = errors.New("DS RR does not exist")
	ErrInvalidRRsig         = errors.New("invalid RRSIG")
	ErrRrsigValidationError = errors.New("RR doesn't validate against RRSIG")
	ErrRrsigValidityPeriod  = errors.New("invalid RRSIG validity period")
	ErrUnknownDsDigestType  = errors.New("unknown DS digest type")
	ErrDsInvalid            = errors.New("DS RR does not match DNSKEY")
)

var resolver *Resolver

func NewDNSMessage() *dns.Msg {
	dnsMessage := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			RecursionDesired: true,
		},
	}
	dnsMessage.SetEdns0(4096, true)
	return dnsMessage
}

func localQuery(qname string, qtype uint16) (*dns.Msg, error) {
	dnsMessage := NewDNSMessage()
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

	signedZone = NewSignedZone(domainName)

	signedZone.ds, err = queryRRset(domainName, dns.TypeDS)
	if err == ErrNoResult {
		return nil, ErrDsNotAvailable
	}

	signedZone.dnskey, err = queryRRset(domainName, dns.TypeDNSKEY)
	if err != nil {
		return nil, err
	}
	signedZone.pubKeyLookup = make(map[uint16]*dns.DNSKEY)
	for _, rr := range signedZone.dnskey.rrSet {
		signedZone.addPubKey(rr.(*dns.DNSKEY))
	}

	return signedZone, nil
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
	resolver.queryFn = localQuery
	return resolver, nil
}
