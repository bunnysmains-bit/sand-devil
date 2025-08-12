## Sand Devil


<p align="center">
      <a href="https://github.com/redskal/sand-devil"><img alt="Logo containing a sea demon" src="assets/logo.png" width="50%" /></a>
</p>

<p align="center">
      <a href="https://imgur.com/eMEc0R0" target="_blank">
            <img src="https://imgur.com/eMEc0R0" alt="Sand Devil Demo Video" width="60%"/>
      </a>
</p>

#### Overview

Automates the process of running a whois query against a known IP, identifying the address space of the AS the target IP belongs to, then performing reverse DNS against each IP in the address space, checking for the provided keywords. If it finds a match, it'll output it.

***Note: it supports IPv6, but you'll need to download a lot more RAM to use it due to the exponentially larger address space it has to generate individual IPs for. See screenshot below***

<p align="center"><img alt="More RAM, vicar?" src="assets/more-ram-needed-for-ipv6.png" /></p>

#### Usage

```bash
Usage of sand-devil:
  -target string
        Target IP address or domain to query for whois information.
  -keywords string
        Comma-separated list of keywords to search for
  -resolver string
        DNS server to use for lookups (default "1.1.1.1")
  -threads int
        Number of threads to create (default 100)
  -output string
        Output file to write results (optional)
  -url string
        URL to scrape for keywords (optional)
  -zone string
        Country code IP Blocks (e.g., 'vn', 'uk', 'es') Can be Zmapped (optional)
```


#### Examples

**1. Scrape a zone and save the IP blocks:**

```bash
$ ./sand-devil -zone vn
Sand-Devil v0.1.0
by @sam_phisher

[success]: Zone file saved as vn.zone
```

**2. Scrape a URL for keywords:**

```bash
$ ./sand-devil -url https://example.com -keywords "test,example"
Sand-Devil v0.1.0
by @sam_phisher

Keyword 'test' found in https://example.com
```

**3. Save output to a file:**

```bash
$ ./sand-devil -target 20.70.246.20 -keywords "microsoft,office,azure" -output results.txt
Sand-Devil v0.1.0
by @sam_phisher

2025/01/25 03:38:36 Route CIDR found:       [20.33.0.0/16 20.34.0.0/15 20.36.0.0/14 20.40.0.0/13 20.48.0.0/12 20.64.0.0/10]
2025/01/25 03:38:37 Number of IPs to scan:  6225920
20.33.36.48     => ns-mx-megla.westeurope.cloudapp.azure.com.
20.33.39.3      => bcmx1.westeurope.cloudapp.azure.com.
20.33.40.70     => smtpapp4.northeurope.cloudapp.azure.com.
20.33.40.71     => smtpapp3.northeurope.cloudapp.azure.com.
20.33.40.135    => mail03.northeurope.cloudapp.azure.com.
20.33.49.53     => bcmx3.westeurope.cloudapp.azure.com.
20.33.66.101    => mailout3.westeurope.cloudapp.azure.com.
...SNIP...
[success]: Results saved to results.txt
```