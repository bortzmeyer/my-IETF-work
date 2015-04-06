/* [DNS] Implementation of the zone cut finding algorithm in
<https://tools.ietf.org/html/draft-ietf-dnsop-qname-minimisation#appendix-A>

If you are not used to the Go programming language, fast compile
instructions:

1) Install Go

2) export GOPATH=$(pwd)

3) go get github.com/miekg/dns

4) go build zonecut.go

5) ./zonecut

6) TODO the client

Limitations: only uses one name server per zone. So, it is very
brittle: if this name server happens to be broken, resolution will
fail.

We cheat a bit by relying on the local resolver to find IP addresses
of name servers from their zones. So, we do not process glue
records.

Stephane Bortzmeyer <bortzmeyer@nic.fr>
*/

package main

import (
	// Standard libraries
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
	// External libraries
	"github.com/miekg/dns"
	// Local libraries
	"dnscache"
)

const (
	TIMEOUT     float64 = float64(1.5)
	MAXTRIALS   uint    = 3
	QTYPE       uint16  = dns.TypeA
	SOCKET_NAME string  = "/tmp/zonecut.sock"
)

type Reply struct {
	retrieved     bool
	rcode         int
	authoritative bool
	dnsdata       []dns.RR
	msg           string
}

var ( // Global vars
	timeout   time.Duration
	maxTrials *int
	qtypeI    int
	qtype     uint16
	verbose   *bool
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
	nameservers := make(map[string]string)
	timeout = time.Duration(TIMEOUT * 1.0e9)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "%s [options]\n", os.Args[0])
		flag.PrintDefaults()
	}
	help := flag.Bool("h", false, "Print help")
	verbose = flag.Bool("v", false, "Be verbose")
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
	if flag.NArg() != 0 {
		fmt.Fprintf(os.Stderr, "No argument expected, %d arguments received\n", flag.NArg())
		flag.Usage()
		os.Exit(1)
	}
	sock, err := net.Listen("unix", "@"+SOCKET_NAME)
	if err != nil {
		panic(err)
	}
	defer sock.Close()
	// ReadingLoop:
	for {
		fd, err := sock.Accept()
		if err != nil {
			panic(err)
		}
		buf := make([]byte, 512)
		// TODO loop the read in case we need several i/o operations?
		nr, err := fd.Read(buf)
		if err != nil {
			if err != io.EOF {
				panic(err)
			}
		}
		data := string(buf[0:nr])
		result := strings.SplitN(data, "\000", 2)
		domain_raw := result[0]
		qtypeI, err := strconv.ParseInt(result[1], 10, 8)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid request\n")
			os.Exit(1)
		}
		domain := dns.Fqdn(domain_raw)
		if qtypeI <= 0 {
			fmt.Fprintf(os.Stderr, "Qtype must be positive, not %d\n", qtypeI)
			flag.Usage()
			os.Exit(1)
		}
		qtype = uint16(qtypeI)
		if *verbose {
			fmt.Fprintf(os.Stdout, "Searching %d for %s\n", qtype, domain)
		}
		remainingLabels := dns.SplitDomainName(domain)

		// Step numbers in the program are from
		// draft-ietf-dnsop-qname-minimisation-02. Other versions may
		// be different.

		// Start resolving the domain name. Start with the cache (step 0).
		finalResult := "UNINITIALIZED"
		_, rnameservers, _ := dnscache.Get("", 0)
		nameservers["."] = rnameservers[0]
		ok, _, rdata := dnscache.Get(domain, qtype)
		if ok.Exists == nil { // Not in the cache

			// Find closest enclosing NS RRset in your cache. Step 1.
			parent := dns.Fqdn(ok.Closest)

			leaf := false
		NodeLoop:
			for !leaf {
				if *verbose {
					fmt.Fprintf(os.Stdout, "\nZone cut at \"%s\"\n", parent)
				}

				// Step 2
				child := parent

				zonecut := false
				// InTheZoneLoop:
				for !zonecut {
					// Step 3
					if child == domain {
						result := nsQuery(domain, nameservers[parent], qtype, false)
						if !result.retrieved {
							fmt.Fprintf(os.Stderr, "Error in retrieving the final result: \"%s\"\n", result.msg)
							break NodeLoop
						}
						finalResult = fmt.Sprintf("%s", result.dnsdata)
						leaf = true
						zonecut = true
						break NodeLoop
					} else {
						// Step 4
						if child == "." {
							child = dns.Fqdn(remainingLabels[len(remainingLabels)-1])
						} else {
							child = remainingLabels[len(remainingLabels)-1] + "." + child
						}
						remainingLabels = remainingLabels[0 : len(remainingLabels)-1]
						// Step 5
						// TODO If you have a negative cache entry for the NS RRset at CHILD,  go back to step 3.
						// Step 6
						result := nsQuery(child, nameservers[parent], dns.TypeNS, true)
						if !result.retrieved {
							fmt.Fprintf(os.Stderr, "Error in retrieving the intermediate result: \"%s\"\n", result.msg)
						}
						if *verbose {
							fmt.Fprintf(os.Stdout, "Result for \"%s\": %s\n", child, result.msg)
						}
						// 6c
						if result.rcode == dns.RcodeNameError { // NXDOMAIN
							fmt.Fprintf(os.Stderr, "Name \"%s\" does not exist\n", child)
							finalResult = "No such domain"
							dnscache.PutNx(domain)
							break NodeLoop
						}
						if result.rcode != dns.RcodeSuccess { //
							fmt.Fprintf(os.Stderr, "Fatal error %s\n", result.msg)
							finalResult = fmt.Sprintf("Fatal error %s", result.msg)
							break NodeLoop
						}
						// TODO put the positive results in the cache
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
		} else {
			// TODO separate NXDOMAIn and actual data
			finalResult = fmt.Sprintf("Data in cache \"%s\"", rdata)
		}
		// TODO: check we have data of the requested type?
		fd.Write([]byte(fmt.Sprintf("Final result: %s", finalResult)))
		fd.Close()
	}
	os.Exit(0)
}
