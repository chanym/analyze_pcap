# analyze_pcap
using tshark to get url from pcap and check against Virustotal

Need to insert own virustotal API key to make it work

Please take note that non premium API key only allows 4 queries per minute

Usage - ./analyze_pcap.rb [pcap]

Example - ./analyze_pcap.rb <pcap file>

Sample output will be as shown below

Total url to be query against virustotal : 185
Estimate time will be 46 minutes as I am using non premium API key...
*******

1) IP: XX.XX.XX.XX
http://ZZZZ/ZZZ/

2) IP: XXX.XXX.XXX.XXX
http://YYY/YYY/YYY/YYY?a=sc&r=1&err=1:

            Webutation: malicious site
             

