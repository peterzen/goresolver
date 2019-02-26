dnssecvalidator
===============

A DNSSEC validating resolver library implemented on top of [miekg/dns](https://github.com/miekg/dns).


This package implements DNS lookup functions compatible with `net.LookupIP` and `net.LookupAddr`.  When querying DNSSEC enabled zones, it performs a full validation of the resource records (RRs) included in the response:

* Requests the desired RRset (along with the corresponding RRSIG record)
* Requests the DNSKEY records containing the public ZSK and public KSK (along with the RRSIG for the DNSKEY RRset)
* Performs the cryptographic validation of the RRSIG of the requested RRset with the public ZSK
* Performs the cryptographic validation of the RRSIG of the DNSKEY RRset with the public KSK
* Checks the validity period of the RRSIGs

Following successful cryptographic validations, it will then verify the chain of trust by walking up the delegation chain and checking the public DNSKEYs against the DS records in the parent zones, up to the TLD zone.  (For a more in-depth description of how DNSSEC works, see [this guide](https://www.cloudflare.com/dns/dnssec/how-dnssec-works/).)

In case of any validation errors, the methods return a non-nil `err` value, and an empty result set.  

In case the queried zone is not DNSSEC-enabled (i.e. does not have a DS record in the parent zone), the library will defer the query to `net.LookupIP`/`net.LookupAddr`.
 
## Documentation


```Go
import "github.com/peterzen/dnssecvalidator"

ips, err := dnssecvalidator.LookupIP("www.example.com")

if err != nil {
	// handle validation errors
}
```

```Go
import "github.com/peterzen/dnssecvalidator"

ipStrings, err := dnssecvalidator.LookupAddr("www.example.com")

if err != nil {
	// handle validation errors
}
```


## Installation

```bash
$ go get -u github.com/peterzen/dnssecvalidator
```
