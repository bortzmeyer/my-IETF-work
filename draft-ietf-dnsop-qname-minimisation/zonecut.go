// [DNS] Implementation of the zone cut finding algorithm in
// <https://tools.ietf.org/html/draft-ietf-dnsop-qname-minimisation#appendix-A>

// If you are not used to the Go programming language, fast compile
// instructions:

// 1) Install Go

// 2) go get github.com/miekg/dns

// 3) go build zonecut.go

// Limitations: only uses one name server per zone. So, it is very
// brittle: if this name server happens to be broken, resolution will
// fail.

// We cheat a bit by relying on the local resolver to find IP addresses
// of name servers from their zones. So, we do not process glue
// records.

// Stephane Bortzmeyer <bortzmeyer@nic.fr>

package main

import (
	"flag"
	"fmt"
	"github.com/miekg/dns"
	"net"
	"os"
	"time"
)

const (
	ROOT_NS string = "k.root-servers.net" // In the future, we
	// will have the full array and the ability
	// to switch away from a broken name server.
	TIMEOUT   float64 = float64(1.5)
	MAXTRIALS uint    = 3
	QTYPE     uint16  = dns.TypeA
)

type Reply struct {
	retrieved     bool
	rcode         int
	authoritative bool
	dnsdata       []dns.RR
	msg           string
}

var ( // Global vars
	nameservers map[string]string
	timeout     time.Duration
	maxTrials   *int
	qtypeI      *int
	qtype       uint16
	verbose     *bool
)

func nsQuery(qname string, server string, qtype uint16, acceptReferrals bool) Reply {
	var (
		trials uint
		result Reply
	)
	result.retrieved = false
	result.msg = "UNKNOWN"
	m := new(dns.Msg)
	m.Id = dns.Id()
	m.RecursionDesired = false
	m.Question = make([]dns.Question, 1)
	c := new(dns.Client)
	c.ReadTimeout = timeout
	m.Question[0] = dns.Question{qname, qtype, dns.ClassINET}
	nsAddressPort := ""
	nsAddressPort = net.JoinHostPort(server, "53")
	if *verbose {
		fmt.Fprintf(os.Stdout, "Querying type %d for name %s at server %s\n", qtype, qname, server)
	}
	for trials = 0; trials < uint(*maxTrials); trials++ {
		answer, _, err := c.Exchange(m, nsAddressPort)
		if answer == nil {
			if *verbose {
				fmt.Fprintf(os.Stderr, "Error when querying %s: \"%s\"\n", server, err)
			}
			result.msg = fmt.Sprintf("%s", err)
			break
		} else {
			result.rcode = answer.Rcode
			result.authoritative = answer.Authoritative
			if answer.Rcode != dns.RcodeSuccess {
				result.msg = dns.RcodeToString[answer.Rcode]
				break
			} else {
				result.retrieved = true
				if len(answer.Answer) == 0 { // May happen if the server is a recursor,
					// not authoritative, since we query with RD=0 or:
					if acceptReferrals {
						if len(answer.Ns) == 0 {
							result.msg = "0 answer and 0 referral"
							result.dnsdata = answer.Answer
						} else {
							result.msg = "Referral(s)"
							result.dnsdata = answer.Ns
						}
					} else {
						result.msg = "0 answer"
						result.dnsdata = answer.Answer
					}
					break
				} else {
					result.msg = "Answer(s)"
					result.dnsdata = answer.Answer
					break
				}
			}
		}
	}
	return result
}

func main() {
	nameservers = make(map[string]string)
	nameservers["."] = ROOT_NS
	timeout = time.Duration(TIMEOUT * 1.0e9)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "%s [options] DOMAIN-NAME\n", os.Args[0])
		flag.PrintDefaults()
	}
	help := flag.Bool("h", false, "Print help")
	verbose = flag.Bool("v", false, "Be verbose")
	qtypeI = flag.Int("q", int(QTYPE), "Query type (numeric value only, sorry, A is 1, SOA is 6, etc")
	maxTrials = flag.Int("n", int(MAXTRIALS), "Number of trials before giving in")
	timeoutI := flag.Float64("t", float64(TIMEOUT), "Timeout in seconds")
	flag.Parse()
	if *help {
		flag.Usage()
		os.Exit(0)
	}
	if *timeoutI <= 0 {
		fmt.Fprintf(os.Stderr, "Timeout must be positive, not %d\n", *timeoutI)
		flag.Usage()
		os.Exit(1)
	}
	timeout = time.Duration(*timeoutI * float64(time.Second))
	if *maxTrials <= 0 {
		fmt.Fprintf(os.Stderr, "Number of trials must be positive, not %d\n", *maxTrials)
		flag.Usage()
		os.Exit(1)
	}
	if *qtypeI <= 0 {
		fmt.Fprintf(os.Stderr, "Qtype must be positive, not %d\n", *qtypeI)
		flag.Usage()
		os.Exit(1)
	}
	qtype = uint16(*qtypeI)
	if flag.NArg() != 1 {
		fmt.Fprintf(os.Stderr, "Only one argument expected, %d arguments received\n", flag.NArg())
		flag.Usage()
		os.Exit(1)
	}
	domain := dns.Fqdn(flag.Arg(0))
	if *verbose {
		fmt.Fprintf(os.Stdout, "Searching %d for %s\n", qtype, domain)
	}
	remainingLabels := dns.SplitDomainName(domain)

	// Step numbers in the program are from
	// draft-ietf-dnsop-qname-minimisation-01. Other versions may
	// be different.

	// Start resolving the domain name. If we were a real
	// resolver, we would start with the cache (step 0).

	// Find closest enclosing NS RRset in your cache. Since we are
	// always cold (no caching at all), this is always the
	// root when we start. Step 1.
	parent := "."
	leaf := false
	for !leaf {
		if *verbose {
			fmt.Fprintf(os.Stdout, "\nZone cut at \"%s\"\n", parent)
		}

		// Step 2
		child := parent

		zonecut := false
		for !zonecut {
			// Step 3
			if child == domain {
				result := nsQuery(domain, nameservers[parent], qtype, false)
				if !result.retrieved {
					fmt.Fprintf(os.Stderr, "Error in retrieving the final result: \"%s\"\n", result.msg)
					os.Exit(1)
				}
				// TODO: check we have data of the requested type?
				fmt.Fprintf(os.Stdout, "Final result: %s\n", result.dnsdata)
				leaf = true
				zonecut = true
			} else {
				// Step 4
				if child == "." {
					child = dns.Fqdn(remainingLabels[len(remainingLabels)-1])
				} else {
					child = remainingLabels[len(remainingLabels)-1] + "." + child
				}
				remainingLabels = remainingLabels[0 : len(remainingLabels)-1]
				// Step 5 skipped since we don't have a cache
				// Step 6
				result := nsQuery(child, nameservers[parent], dns.TypeNS, true)
				if !result.retrieved {
					fmt.Fprintf(os.Stderr, "Error in retrieving the intermediate result: \"%s\"\n", result.msg)
					os.Exit(1)
				}
				if *verbose {
					fmt.Fprintf(os.Stdout, "Result for \"%s\": %s\n", child, result.msg)
				}
				// 6c
				if result.rcode == dns.RcodeNameError { // NXDOMAIN
					fmt.Fprintf(os.Stderr, "Name \"%s\" does not exist\n", child)
					os.Exit(1)
				}
				if result.rcode != dns.RcodeSuccess { //
					fmt.Fprintf(os.Stderr, "Fatal error %s\n", result.msg)
					os.Exit(1)
				}
				referralFound := false
				for i := range result.dnsdata {
					ans := result.dnsdata[i]
					name := ""
					switch ans.(type) {
					case *dns.NS:
						record := ans.(*dns.NS)
						if record.Header().Name == child { // Some middleboxes add NS records of the parent...
							name = record.Ns
							referralFound = true
							break
						}
					}
					if referralFound {
						nameservers[child] = name
						// Step 6a or 6b (merged here because of the work done in function nsQuery)
						parent = child
						zonecut = true
					} else { // 6d
						zonecut = false
					}
				}
			}
		}
	}
	os.Exit(0)
}
