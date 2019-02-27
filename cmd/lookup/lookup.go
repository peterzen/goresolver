package main

import (
	"fmt"
	"github.com/miekg/dns"
	"github.com/peterzen/goresolver"
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
	resolver, err := goresolver.NewResolver("./testdata/resolv.conf")

	if err != nil {
		fmt.Printf("Cannot initialize the local resolver: %s\n", err)
		os.Exit(1)
	}

	ips, err := resolver.LookupIP(dns.Fqdn(hostname))

	if err != nil {
		fmt.Printf("Validation failed: %s\n", err)
		os.Exit(1)
	}

	ipStr := make([]string, 0, len(ips))

	for _, ip := range ips {
		ipStr = append(ipStr, ip.String())
	}

	fmt.Println("validation successful")
	fmt.Printf("IPs %s\n", strings.Join(ipStr, "\n"))
}
