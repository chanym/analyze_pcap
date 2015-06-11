#!/usr/bin/ruby

puts "\n** using tshark to get url from pcap and check against Virustotal **\n\n"

if ARGV.length != 1 
	puts "Usage - ./analyze_pcap.rb [pcap]"
	puts "\nExample - ./analyze_pcap.rb <pcap file>"
	exit
end

require 'rubygems'
require 'uirusu'

APT_KEY = "" #Enter your virustotal API key here

def url_query(url)
	results = Uirusu::VTUrl.query_report(APT_KEY, url)
  result = Uirusu::VTResult.new(url, results)
  result_array = result.to_stdout.split("\n")
	return result_array
end

result = `tshark -Y 'tcp.port==80  && \
				(http.request.method == "GET" || http.request.method=="HEAD" || http.request.method=="POST" )'\
				 -r "#{ARGV[0]}" \
				 -Tfields \
				 -e ip.dst \
				 -e http.request.full_uri 2>/dev/null`

url = Hash.new

result.split("\n").uniq!.sort!.each {|x| url["#{x.split[1]}"] = x.split[0]}

puts "Total url to be query against virustotal : #{url.length}"
puts "Estimate time will be #{url.length / 4} minutes as I am using non premium API key..."
print "*******\n"

count = 0
total = 0
url.each do |key, value|
	result_array = []
	ip = nil
 	if count < 4
		result_array = url_query(key)
		print "\n"
		puts "#{total += 1}) IP: #{value}"
		puts "#{result_array[0]}"
 		result_array.each {|a| puts a if a =~ /mal(ware|icious) site/}
 		count += 1
 	else
 		sleep 60
 		count = 0
 		redo
 	end
end
