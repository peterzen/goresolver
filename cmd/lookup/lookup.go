package main

import (
	"fmt"
	"github.com/miekg/dns"
	"github.com/peterzen/dnssecvalidator"
	"os"
	"strings"
)

func main() {

	if len(os.Args) < 2 {
		fmt.Printf("Usage: validator <hostname>\n")
		os.Exit(0)
	}
	hostname := os.Args[1]

	//conf = &dns.ClientConfig{
	//	Ndots:   1,
	//	Servers: []string{"localhost"},
	//	Port:    "5354",
	//}

	err := dnssecvalidator.Initialize("./testdata/resolv.conf")

	if err != nil {
		fmt.Printf("Cannot initialize the local resolver: %s\n", err)
		os.Exit(1)
	}

	ips, err := dnssecvalidator.LookupAddr(dns.Fqdn(hostname))

	if err != nil {
		fmt.Printf("Validation failed: %s\n", err)
		os.Exit(1)
	}

	fmt.Println("validation successful")
	fmt.Printf("IPs %s\n", strings.Join(ips, "\n"))
}
