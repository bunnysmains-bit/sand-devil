/*
 * Sand Devil
 * coded by @sam_phisher
 *
 * Automates the process of running a whois against a known IP, identifying the address
 * space of the AS the target IP belongs to, then performing reverse DNS against each IP in
 * the address space, checking for the provided keywords. If it finds a match, it'll output it.
 *
 * Usage:
 *
 *	./sand-devil -target <ip_address> -keywords <comma-separated_keywords>
 *
 * E.g.
 *    microsoft.com resolves to 20.236.44.162, so...
 *	  $ ./sand-devil -target 20.236.44.162 -keywords "microsoft,ms,office,azure"
 *     2025/01/24 14:45:05 Route CIDR found:       20.192.0.0/10
 *     2025/01/24 14:45:05 Number of IPs to scan:  4194304
 *     20.192.2.19     => mailforcepoint1new.centralindia.cloudapp.azure.com.
 *     20.192.12.109   => imap.centralindia.cloudapp.azure.com.
 *     20.193.49.212   => mmtspipauevpnprod2.australiaeast.cloudapp.azure.com.
 *     20.193.147.19   => exide-smg.centralindia.cloudapp.azure.com.
 *     20.193.148.235  => smtp.hourlyrooms.co.in.
 *     20.194.27.43    => mscreen.cariflex.com.
 *     20.194.151.159  => pip-stage-365a-001.japaneast.cloudapp.azure.com.
 *     20.194.163.73   => vpn-tak-karte-prod-001.japaneast.cloudapp.azure.com.
 *     20.194.171.107  => host3digifax.japaneast.cloudapp.azure.com.
 *     20.194.171.166  => dmsmtpap.dmh-global.com.
 *     20.194.173.33   => wkyoken-mta-vm01.japaneast.cloudapp.azure.com.
 *     20.194.182.93   => mitsubishi-shokuhin-mail2.japaneast.cloudapp.azure.com.
 *     20.194.182.103  => mitsubishi-shokuhin-mail1.japaneast.cloudapp.azure.com.
 *     20.194.193.167  => az-20-194-193-167.japaneast.cloudapp.azure.com.
 *     20.194.193.229  => az-20-194-193-229.japaneast.cloudapp.azure.com.
 *     20.194.194.97   => az-20-194-194-97.japaneast.cloudapp.azure.com.
 *     20.194.212.242  => azure-ptr-test.nic.nec.co.jp.
 *     20.194.225.118  => sasdb001.japaneast.cloudapp.azure.com.
 *     20.194.227.138  => web-azure-shared01.cts-cloud.net.
 *     20.194.228.126  => sasdb002.japaneast.cloudapp.azure.com.
 *     20.195.9.169    => az-20-195-9-169.southeastasia.cloudapp.azure.com.
 *     20.195.24.178   => az-20-195-24-178.southeastasia.cloudapp.azure.com.
 *     20.195.59.140   => sea-mgmtscs-dx-csdxa-prd-pip.southeastasia.cloudapp.azure.com.
 *     20.195.63.47    => sea-mgmtscs-dx-morf-prd-pip.southeastasia.cloudapp.azure.com.
 *     20.195.85.186   => mail-sgp-cu01-sg.southeastasia.cloudapp.azure.com.
 *     20.195.85.187   => mail-apc-cu01-sg.southeastasia.cloudapp.azure.com.
 */
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/likexian/whois"
)

type empty struct{}

type result struct {
	ip     string
	domain string
}

var (
	r       = &net.Resolver{}
	version = "0.1.0"
	author  = "@sam_phisher"
)

func banner() {
	fmt.Printf("Sand-Devil v%s\n", version)
	fmt.Printf("by %s\n\n", author)
}

func main() {
	banner()
	ipAddress := flag.String("target", "", "Target IP address or domain to query for whois information.")
	keywords := flag.String("keywords", "", "Comma-separated list of keywords to search for")
	dnsServer := flag.String("resolver", "1.1.1.1", "DNS server to use for lookups")
	threads := flag.Int("threads", 100, "Number of threads to create")
	outputFile := flag.String("output", "", "Output file to write results (optional)")
	urlFlag := flag.String("url", "", "URL to scrape for keywords (optional)")
	flag.Parse()

	r.PreferGo = true
	r.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		d := net.Dialer{
			Timeout: time.Millisecond * time.Duration(10000),
		}
		return d.DialContext(ctx, network, fmt.Sprintf("%s:53", *dnsServer))
	}

       if *urlFlag != "" && *keywords != "" {
	       // Scrape the URL for keywords
	       resp, err := http.Get(*urlFlag)
	       if err != nil {
		       log.Fatalf("Failed to fetch URL: %v", err)
	       }
	       defer resp.Body.Close()
	       body, err := io.ReadAll(resp.Body)
	       if err != nil {
		       log.Fatalf("Failed to read URL body: %v", err)
	       }
	       found := false
	       for _, word := range strings.Split(*keywords, ",") {
		       if strings.Contains(string(body), word) {
			       fmt.Printf("Keyword '%s' found in %s\n", word, *urlFlag)
			       found = true
		       }
	       }
	       if !found {
		       fmt.Printf("No keywords found in %s\n", *urlFlag)
	       }
	       return
       } else if *ipAddress == "" || *keywords == "" {
	       flag.Usage()
	       os.Exit(1)
       }


       var targets []string
       if net.ParseIP(*ipAddress) == nil {
	       ips, err := net.LookupIP(*ipAddress)
	       if err != nil || len(ips) == 0 {
		       log.Fatalf("Could not resolve domain %s: %v", *ipAddress, err)
	       }
	       for _, ip := range ips {
		       targets = append(targets, ip.String())
	       }
	       log.Printf("Resolved %s to: %v", *ipAddress, targets)
       } else {
	       targets = append(targets, *ipAddress)
       }

       keywordsParsed := strings.Split(*keywords, ",")
       ipChan := make(chan string, len(targets))
       for _, ip := range targets {
	       ipChan <- ip
       }
       close(ipChan)

       var allTargetSubnets []string
       var allTargetAS []string
       for ip := range ipChan {
	       whoisResult, err := whois.Whois(ip)
	       if err != nil {
		       log.Printf("Whois failed for %s: %v", ip, err)
		       continue
	       }
	       tempCidrs, err := getCIDRsFromString(whoisResult)
	       if err == nil {
		       for _, subnet := range tempCidrs {
			       if !slices.Contains(allTargetSubnets, subnet) {
				       allTargetSubnets = append(allTargetSubnets, subnet)
			       }
		       }
	       }
	       targetAS, _ := extractStringsWithRegex(whoisResult, `(AS\\d+)`)
	       if targetAS != nil {
		       for _, asn := range targetAS {
			       if !slices.Contains(allTargetAS, asn) {
				       allTargetAS = append(allTargetAS, asn)
			       }
		       }
	       }
	       log.Printf("Whois for %s: CIDRs: %v, ASNs: %v", ip, tempCidrs, targetAS)
       }
       log.Println("All Route CIDRs found:      ", allTargetSubnets)
       log.Println("All AS numbers found:       ", allTargetAS)

       var targetSubnets []string

       // this is an ugly work around because I couldn't get regexes working
       // to extract IPv6 CIDRs.
       tempCidrs, err := getCIDRsFromString(whoisResult)
       if err != nil {
	       log.Fatal(err)
       }
       // this could be a one-liner, but we want to de-duplicate
       for _, subnet := range tempCidrs {
	       if !slices.Contains(targetSubnets, subnet) {
		       targetSubnets = append(targetSubnets, subnet)
	       }
       }

       targetAS, _ := extractStringsWithRegex(whoisResult, `(AS\d+)`)
       log.Println("Route CIDR found:      ", targetSubnets)
       if targetAS != nil {
	       log.Println("AS number found:       ", targetAS[0])
       }

       var ips []string
       for _, subnet := range targetSubnets {
	       ipAddr, err := getIPsFromCIDR(subnet)
	       if err != nil {
		       log.Fatal(err)
	       }
	       ips = append(ips, ipAddr...)
       }

       log.Println("Number of IPs to scan: ", len(ips))

       ipChan := make(chan string)
       gather := make(chan result)
       tracker := make(chan empty)

       for i := 0; i < *threads; i++ {
	       go worker(tracker, ipChan, gather, keywordsParsed)
       }

       var output *os.File
       var errOutput error
       if *outputFile != "" {
	       output, errOutput = os.Create(*outputFile)
	       if errOutput != nil {
		       log.Fatalf("Failed to open output file: %v", errOutput)
	       }
	       defer output.Close()
       }

       go func() {
	       for r := range gather {
		       line := fmt.Sprintf("%-15s => %s\n", r.ip, r.domain)
		       if output != nil {
			       output.WriteString(line)
		       } else {
			       fmt.Print(line)
		       }
	       }
	       var e empty
	       tracker <- e
       }()

       for _, v := range ips {
	       ipChan <- v
       }

       close(ipChan)
       for i := 0; i < *threads; i++ {
	       <-tracker
       }
       close(gather)
       <-tracker
}

func worker(tracker chan empty, ips chan string, gather chan result, keywords []string) {
	for ip := range ips {
		names, err := r.LookupAddr(context.Background(), ip)
		if err != nil {
			continue
		}
		for _, v := range names {
			if containsAny(v, keywords) {
				res := result{
					ip:     ip,
					domain: v,
				}
				gather <- res
			}
		}
	}
	var e empty
	tracker <- e
}

func extractStringsWithRegex(s, regex string) ([]string, error) {
	re := regexp.MustCompile(regex)
	result := re.FindAllStringSubmatch(s, -1)

	var ret []string
	if len(result) > 1 {
		for i := 1; i < len(result); i++ {
			if result[i][0] != "" {
				ret = append(ret, result[i][0])
			}
		}
		return ret, nil
	}

	return nil, fmt.Errorf("no match found")
}

func getIPsFromCIDR(cidr string) ([]string, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR: %v", err)
	}

	var ips []string
	for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); incrementIP(ip) {
		ips = append(ips, ip.String())
	}

	return ips, nil
}

// this monstrosity is built from pure malice towards regexes and extracting
// IPv6 CIDRs with them.
func getCIDRsFromString(s string) ([]string, error) {
	var ret []string
	// I'll update the following patterns as and when I identify new ones.
	typicalValues := []string{
		"route", // RIPE
		"CIDR",  // ARIN
	}
	for _, line := range strings.Split(s, "\n") {
		for _, v := range typicalValues {
			if strings.HasPrefix(line, v) {
				cidrs := strings.Split(line[strings.Index(line, ":"):], ", ")
				for _, vv := range cidrs {
					ret = append(ret, strings.Trim(vv, ":\t "))
				}
			}
		}
	}
	if len(ret) > 0 {
		return ret, nil
	}
	return nil, fmt.Errorf("no CIDR notation subnets found. Sanity check the raw whois output - may be the pattern hasn't been implemented.")
}

func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] != 0 {
			break
		}
	}
}

func containsAny(domain string, keywords []string) bool {
	for _, word := range keywords {
		if strings.Contains(domain, word) {
			return true
		}
	}
	return false
}