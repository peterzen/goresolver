go-resolver
===============

[![Build Status](https://travis-ci.org/peterzen/goresolver.svg?branch=master)](https://travis-ci.org/peterzen/goresolver)
[![ISC License](http://img.shields.io/badge/license-ISC-blue.svg)](http://copyfree.org)
[![codecov](https://codecov.io/gh/peterzen/goresolver/branch/master/graph/badge.svg)](https://codecov.io/gh/peterzen/goresolver)

A Golang DNSSEC validating resolver library implemented on top of [miekg/dns](https://github.com/miekg/dns).


This package implements DNS lookup functions that perform DNSSEC validation.  

When querying DNSSEC enabled zones, it performs a full verification of the resource records (RRs) included in the response and validates the chain of trust:

* Requests the desired RRset (along with the corresponding `RRSIG` record)
* Requests the `DNSKEY` records containing the public ZSK and public KSK (along with the `RRSIG` for the `DNSKEY` RRset)
* Performs the cryptographic verification of the `RRSIG` of the requested RRset with the public ZSK
* Performs the cryptographic verification of the `RRSIG` of the `DNSKEY` RRset with the public KSK
* Checks the validity period of the `RRSIG` records

Following these cryptographic verifications, the package then verifies the chain of trust by walking up the delegation chain and checking the public `DNSKEY` RRs against the `DS` records in the parent zones, up to the TLD zone.  (For a more in-depth description of how DNSSEC works, see [this guide](https://www.cloudflare.com/dns/dnssec/how-dnssec-works/).)

In case of any validation errors, the method return a non-nil `err` value, and an empty result set.  

 
## Documentation

```Go
import "github.com/peterzen/goresolver"

result, err := resolver.StrictNSQuery("example.com.", dns.TypeMX)

if err != nil {
	// handle validation errors
}
```
`goresolver.LookupIP` can be used as drop-in replacement to [net.LookupIP](https://golang.org/pkg/net/#LookupIP):

```Go
import "github.com/peterzen/goresolver"

ips, err := goresolver.LookupIP("www.example.com")

if err != nil {
	// handle validation errors
}
```

## Installation

```bash
$ go get -u github.com/peterzen/goresolver
```

PRs for additional test cases covering less common DNSSEC setups are welcome and much appreciated.
