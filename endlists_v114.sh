#! /bin/sh
####################################################################################
#                        HEADER AND INSTRUCTIONS
####################################################################################
# Program: endlists.sh
# Type: Bourne shell script
# Current Version: 1.15  Apr 16 2016
# Stable Version:  1.13, Feb 28 2016
# Author: Endwall Development Team
#
# Description:  Traditional iptables list based blacklisting 
#
# Changes:  - Updated EULA
#           - Added EULA
#           - Removed Linux Security Booleans section.
#           - Fixed some style issues
#           - Fixed the logging bug (reversed the order of drop and log)
#           - Use && to execute log and drop rules in parallel (multiprocess)
#           - changed echo to Endlists Loaded
#
#
# Instructions: make directory,copy the file and change name to endlists.sh
#               make whitelists,blacklist text files, edit the endlists.sh file
#               change permisions to make endlists.sh executable, run the file.  
#                 
#
# Notes:    -  This script is slow to run with more than 1000 blacklist entries.
#           -  Use endsets.sh if your blacklists run over 1000 entries.
#
# $ mkdir ~/endwall
# $ cp vdyvuh.sh ~/endwall/endlists.sh
# $ cd ~/endwall
# $ echo " " >> smtp_whitelist.txt  # whitelist (hotmail,gmail,etc)
# $ echo " " >> http_whitelist.txt  # users of your website  
# $ echo " " >> http_blacklist.txt  # ipv4 addresses to restrict http/https
# $ echo " " >> smtp_blacklist.txt  # ipv4 addresses to restrict smtp access
# $ echo " " >> dns_blacklist.txt   # ipv4 addresses to restrict dns access/ bad dns actors
# $ echo " " >> attackers.txt       # ipv4 blacklist for hack attackers / all ports protocols to your ip 
# $ echo " " >> blacklist.txt       # ipv4 blacklist of DOD subnets and others/ all ports protocols period
# $ echo " " >> email_blacklist.txt # strings of email addresses and keywords to block from smtp
# $ echo " " >> html_blacklist.txt  # strings of attack html calls (cgi,php) to block from http 
# $ echo " " >> ipv6_blacklist.txt  # ipv6 addresses to blacklist all ports and protocols
# $ ls                              # list the files you just made
# $ nano endlists.sh   # go to the section below labeled SAVE RULES (line 336)
#                      # comment out save rules for distributions you don't use line 336
# $ chmod u+rwx endlists.sh         # change permisions to allow script execution 
# $ su                              # become root
# # ./endwall.sh                    # execute script/install the basic firewall rules
# # ./endlists.sh                   # execute script / install blacklists
# # ./endsets.sh                    # execute script / install ipsets based blacklists 
##############################################################################################
#                       ADDING TO BAN LIST EXAMPLES
##############################################################################################
# Next add ip addresses to the whitelists and blacklists
# Example: adding an ip to attackers.txt
# $ echo "116.58.45.115" >> attackers.txt
# Example: banning a subnet from accessing smtp
# $ echo "116.58.0.0/16" >> smtp_blacklist.txt
# Example: banning a larger subnet from accessing http
# $ echo "117.0.0.0/8" >> http_blacklist.txt
# Example: banning a large subnet from accessing anything on your server
# $ echo "118.0.0.0/8" >> blacklist.txt
# Example: banning a spammer 
# $ echo "retard_lamer@website.com" >> email_blacklist.txt (read the postfix log for examples)
# Example: banning a hacker diving for files on your webserver (read your httpd log for examples)
# $ echo "/configuration.php" >> html_blacklist.txt
# $ echo "/wordpress/xmlrpc.php" >> html_blacklist.txt
# Example: Whitelisting 
# $ echo "198.252.153.0/24" >> http_whitelist.txt
# $ echo "198.252.153.0/24" >> smtp_whitelist.txt
# $ chmod u+wrx endwall.sh
# $ chmod u+wrx endlists.sh
# $ su                     
# # ./endwall.sh   # run the endwall firewall script 
# # ./endlists.sh  # run the blacklist/whitelist script endlists.sh
###############################################################################################
#                Enable iptables and ip6tables if using systemd
################################################################################################
# systemctl enable iptables
# systemctl enable ip6tables
# systemctl enable iptables.service
# systemctl enable ip6tables.service
# systemctl restart iptables
# systemctl restart ip6tables
#
#######################################################################
#                 ACKNOWLEDGEMENTS
#######################################################################
#  The Endwall development team would like to acknowledge the work and efforts
#  of Odilitime, who graciously hosted and promoted this firewall project.
#  Without his efforts and his wonderful website www.endchan.xyz , endwall.sh would not
#  exist in the public domain at all in any form. So thanks to Odilitime for inspiring this work
#  and for hosting and promoting it. 
#  
#  Endwall,Endsets,Endlists, and Endtools are named in honor of Endchan.
#
#  Thank you also to early beta testers including a@a, and to other contributors 
#  as well as to the detractors who helped to critique this work and to ultimately improve it.  
#  
#  We also acknowledge paste.debian.net and gitweb for their hosting services, 
#  without which distribution would be limited / impossible, so thank you.
#
#  https://www.endchan.xyz, http://paste.debian.net, http://gitweb2zl5eh7tp3.onion  
#
#  We salute you! 
#  
#  In the end, may it all end well.
#
#  Endwall Development Team
#
###############################################################################################################################################
#                               LICENSE AGREEMENT  
###############################################################################################################################################
#  TITLE:  THE ENDWALL END USER LICENSE AGREEMENT (EULA) 
#  VERSION: 1.01 
#  VERSION DATE: April 10, 2016
#   
#  DEFINITION: WHAT CONSTITUES "USE"?
#  0) a) Use of this program means the ability to study, posses, run, copy, modify, and distribute the code as included above and below the LISCENSE AGREMENT. 
#        in text format or as a binary file consituting this particular program or its compiled binary machine code form, and the performance of these actions or activities. 
#  WHO MAY "USE" THIS PROGRAM AND WHERE MAY THEY USE IT?
#  1) a) A user of this program is any individual who has been granted use as defined in 0) a) by the LICENSE AGREEMENT, and granted by section 1.
#  1) b) This program may be used  by any living human being, or by any person, or by any sentient individual with the ability to do so.
#  1) c) This program may be used by any citizen of any country.
#  1) d) This program may be used by any civilian, military officer, government agent, private citizen, public official, soveriegn, monarch, head of state,
#        dignitary, ambassdor, nobleman, commoner, clergy, layman, and generally all classes and ranks of people, persons, or human beings mentioned and those not mentioned.
#  1) e) This program may be used by any human being of any gender, including men, women, and any other gender not mentioned.       
#  1) f) This program may be used in any country, in any geographic location, on any planet, at any distance to the surface of the Earth, in orbit, and anywhere in the solar system.  
#  1) g) This program may be used by anyone of any afiliation, political viewpoint, political affiliation, religious belief, religious affiliation, and by those non-belief and non #        affiliation.
#  1) h) This program may be used by any person of any physical apperance, race, ethnicity, identity, genetic makeup, mental ability, and any other physical or non physical
#        characteristics of differentiation.
#  1) i) Sections 1) a) and 1) b) are sufficient for use; however section 1) c) through 1) h) are presented to clarify 1 b) and to enforce non-discrimination and non-exlusion of use.  
#  WHAT MAY A "USER" DO WITH THIS PROGRAM ?
#  2) Any user of this program is granted the freedom to study the code.
#  3) a) Any user of this program is granted the freedom to distribute and share the code with any neighbor of their choice electronically or by any other method of transmission. 
#  3  b) The LICENCSE AGREEMENT, ACKNOWLEDGEMENTS, Header and Instructions must remain attached to the code when re-distributed.
#  4) a) Any user of this program is granted the freedom to modify and improve the code for personal use.
#  4) b) When modified or improved, any user of this program is granted the freedom of re-distribution of their modified code if and only if the user attatchs the LICENSE AGREEMENT
#        in its entirety to their modified code before re-distribution.   
#  5) a) Any user of this program is granted the freedom to run this code on any computer of their choice.
#  5) b) Any user of this program is granted the freedom to run as many simultaneous instances of this code, on as many computers as they are able, for as long as they can,
#        with any degree of simultaneity in use. 
#  6)  This program may be used by any person, human being or sentient individual for any purpose and in any context and in any setting including for personal use, academic use,   #      business use, commercial use, governmental agency use, non-governmental organization use, non-profit organization use, military use, civilian use, and generally any other use 
#      not specifically mentioned.
#  7)  This software is distributed without any warranty and without any guaranty and the creators do not imply anything about its usefulness or efficacy.
#  8)  If you sustain financial loss, informational loss, material loss, physical loss or data loss as a result of using, running, or modifying this script 
#      you agree that you will hold the creators of this script, the "Endwall Development Team" and the programers involved in its creation, free from prosecution, 
#      free from indemnity, and free from liability.
#  9)  If you find a significant flaw or make a significant improvement feel free to notify the original developers so that we may also
#      include your improvement in the next release; you are not obligated to do this but we would enjoy this courtesy tremendously.   
##################################################################################################

#################################################################################################################
#                           GLOBAL VARIABLES
################################################################################################
iptables=/sbin/iptables
ip6tables=/sbin/ip6tables

# Grab interface name from ip link and parse 
int_if=$(ip link | grep -a "2: " | awk -F: '{ print $2}')
int_if2=$(ip link | grep -a "3: " | awk -F: '{ print $2}')

# Grab Gateway Information
gateway_ip=$(ip route | awk '/via/ {print $3}')
#gateway_mac=$( arp | awk '/gateway/ {print $3}')
gateway_mac=$( nmap -sS $gateway_ip -p 53| grep -a "MAC Address:" | awk '{print $3}')

# grab host mac addresses from ip link  
host_mac=$(ip link | grep -a "ether" | awk ' {if (FNR==1) print $2}')
host_mac2=$(ip link | grep -a "ether" | awk ' {if (FNR==2) print $2}')

# grab the ip addresses from the interfaces
host_ip=$(ip addr | grep -a "scope global"|awk 'BEGIN  {FS="/"} {if (FNR==1) print $1}'| awk '{print $2}')
host_ip2=$(ip addr | grep -a "scope global"|awk 'BEGIN  {FS="/"} {if (FNR==2) print $1}'| awk '{print $2}')

host_ip1v6=$(ip addr | grep -a "scope link"|awk 'BEGIN  {FS="/"} {if (FNR==1) print $1}'| awk '{print $2}')
host_ip2v6=$(ip addr | grep -a "scope link"|awk 'BEGIN  {FS="/"} {if (FNR==2) print $1}'| awk '{print $2}')

########################### INTERNAL VARIABLES ################################## 
int_mac="$host_mac"         # internal mac address of interface 1
int_mac2="$host_mac2"       # internal mac address of interface 2 
int_ip1="$host_ip"          # internal ipv4 address of interface 1  
int_ip1v6="$host_ip1v6"     # internal ipv6 address of interface 1  
int_ip2="$host_ip2"         # internal ipv4 address of interface 2
int_ip2v6="$host_ip2v6"     # internal ipv6 address of interface 2

####################################################################################
#                    IP FILTER BLACK LISTS
####################################################################################
#

echo HTTP/HTTPS BLACKLIST LOADING
for blackout in $(cat http_blacklist.txt);
do 

iptables -I OUTPUT  -p tcp -s "$int_ip1" -d "$blackout" -m multiport --dports 80,443 -j DROP && iptables -I OUTPUT -p tcp -s "$int_ip1" -d "$blackout" -m multiport --sports 80,443 -j DROP;
iptables -I INPUT 31  -p tcp -d "$int_ip1" -s "$blackout" -m multiport --dports 80,443 -j DROP && iptables -I INPUT 31 -p tcp -d "$int_ip1" -s "$blackout" -m 
multiport --sports 80,443 -j DROP;

iptables -I OUTPUT  -p tcp -s "$int_ip1" -d "$blackout" -m multiport --dports 80,443 -j LOG --log-prefix "[HTTP-BL OUT] " --log-level=info && iptables -I OUTPUT -p tcp -s "$int_ip1" -d "$blackout" -m multiport  --sports 80,443 -j LOG --log-prefix "[HTTP-BL OUT] "  --log-level=info 
iptables -I INPUT 31 -p tcp -d "$int_ip1" -s "$blackout" -m multiport --dports 80,443 -j LOG --log-prefix "[HTTP-BL IN] " --log-level=info && iptables -I INPUT 31 -p tcp -d "$int_ip1" -s "$blackout" -m multiport --sports 80,443 -j LOG --log-prefix "[HTTP-BL IN] " --log-level=info 

#iptables -I FORWARD  -p tcp -d "$int_ip1" -s "$blackout" -m multiport --dports 80,443 -j DROP;
#iptables -I FORWARD  -p tcp -s "$int_ip1" -d "$blackout" -m multiport --dports 80,443 -j DROP;
#iptables -I FORWARD  -p tcp -d "$int_ip1" -s "$blackout" -m multiport --dports 80,443 -j LOG --log-prefix "[HTTP-BL FORWARD IN] "  --log-level=info;
#iptables -I FORWARD  -p tcp -s "$int_ip1" -d "$blackout" -m multiport --dports 80,443 -j LOG --log-prefix "[HTTP-BL FORWARD OUT] " --log-level=info;
)
echo "$blackout" ; 
done 
echo HTTP BLACKLIST LOADED

#smtp_blacklist.txt
echo SMTP BLACKLIST LOADING
for blackout in $(cat smtp_blacklist.txt);
do 
(

iptables -I OUTPUT  -p tcp -s "$int_ip1" -d "$blackout" -m multiport --dports 25,587 -j DROP && iptables -I OUTPUT  -p tcp -s "$int_ip1" -d $"blackout" -m multiport --sports 25,587 -j DROP;
iptables -I INPUT 31  -p tcp -d "$int_ip1" -s "$blackout" -m multiport --dports 25,587 -j DROP && iptables -I INPUT 31  -p tcp -d "$int_ip1" -s "$blackout" -m multiport --sports 25,587 -j DROP;

iptables -I OUTPUT  -p tcp -s "$int_ip1" -d "$blackout" -m multiport --dports 25,587 -j LOG --log-prefix "[SMTP-BL SPAM OUT] " --log-level=info && iptables -I OUTPUT -p tcp -s "$int_ip1" -d "$blackout" -m multiport --sports 25,587 -j LOG --log-prefix "[SMTP-BL SPAM OUT] " --log-level=info; 
iptables -I INPUT 31  -p tcp -d "$int_ip1" -s "$blackout" -m multiport --dports 25,587 -j LOG --log-prefix "[SMTP-BL SPAM IN] " --log-level=info && iptables -I INPUT 31  -p tcp -d "$int_ip1" -s "$blackout" -m multiport --sports 25,587 -j LOG --log-prefix "[SMTP-BL SPAM IN] " --log-level=info ;

#iptables -I FORWARD -p tcp -d "$int_ip1" -s "$blackout" -m multiport --dports 25,587 -j DROP;
#iptables -I FORWARD -p tcp -s "$int_ip1" -d "$blackout" -m multiport --dports 25,587 -j DROP;
#iptables -I FORWARD -p tcp -d "$int_ip1" -s "$blackout" -m multiport --dports 25,587 -j LOG --log-prefix "[SMTP-BL FORWARD IN] " --log-level=info;
#iptables -I FORWARD -p tcp -s "$int_ip1" -d "$blackout" -m multiport --dports 25,587 -j LOG --log-prefix "[SMTP-BL FORWARD OUT] " --log-level=info;
)
echo "$blackout" ; 
done 
echo SMTP BLACKLIST LOADED

echo DNS BLACKLIST LOADING
for blackout in $(cat dns_blacklist.txt);
do 
(
iptables  -I OUTPUT  -p udp -s "$int_ip1" -d "$blackout" --dport 53 -j DROP && iptables  -I OUTPUT  -p udp -s "$int_ip1" -d "$blackout" --sport 53 -j DROP;
iptables  -I INPUT 31  -p udp -d "$int_ip1" -s "$blackout" --dport 53 -j DROP && iptables  -I INPUT 31  -p udp -d "$int_ip1" -s "$blackout" --sport 53 -j DROP;

iptables  -I OUTPUT  -p udp -s "$int_ip1" -d "$blackout" --dport 53 -j LOG --log-prefix "[DNS-BL UDP OUT] " --log-level=info && iptables -I OUTPUT -p udp -s "$int_ip1" -d "$blackout" --sport 53 -j LOG --log-prefix "[DNS-BL UDP OUT] " --log-level=info 
iptables  -I INPUT 31  -p udp -d "$int_ip1" -s "$blackout" --dport 53 -j LOG --log-prefix "[DNS-BL UDP IN] " --log-level=info && iptables  -I INPUT 31  -p udp -d "$int_ip1" -s "$blackout" --sport 53 -j LOG --log-prefix "[DNS-BL UDP IN] " --log-level=info 

#iptables  -I FORWARD -p udp -d "$int_ip1" -s "$blackout" --dport 53 -j DROP;
#iptables  -I FORWARD -p udp -s "$int_ip1" -d "$blackout" --dport 53 -j DROP;
#iptables  -I FORWARD -p udp -d "$int_ip1" -s "$blackout" --sport 53 -j DROP;
#iptables  -I FORWARD -p udp -s "$int_ip1" -d "$blackout" --sport 53 -j DROP;

#iptables  -I FORWARD -p udp -d "$int_ip1" -s "$blackout" --dport 53 -j LOG --log-prefix "[DNS-BL UDP FORWARD IN] " --log-level=info;
#iptables  -I FORWARD -p udp -s "$int_ip1" -d "$blackout" --dport 53 -j LOG --log-prefix "[DNS-BL UDP FORWARD OUT] " --log-level=info;
#iptables  -I FORWARD -p udp -d "$int_ip1" -s "$blackout" --sport 53 -j LOG --log-prefix "[DNS-BL UDP FORWARD IN] " --log-level=info;
#iptables  -I FORWARD -p udp -s "$int_ip1" -d "$blackout" --sport 53 -j LOG --log-prefix "[DNS-BL UDP FORWARD OUT] " --log-level=info;

iptables -I OUTPUT  -p tcp -s "$int_ip1" -d "$blackout" --dport 53 -j DROP && iptables -I OUTPUT  -p tcp -s "$int_ip1" -d "$blackout" --sport 53 -j DROP;
iptables -I INPUT 31  -p tcp -d "$int_ip1" -s "$blackout" --dport 53 -j DROP && iptables -I INPUT 31  -p tcp -d "$int_ip1" -s "$blackout" --sport 53 -j DROP;

iptables -I OUTPUT  -p tcp -s "$int_ip1" -d "$blackout" --sport 53 -j LOG --log-prefix "[DNS-BL TCP OUT] " --log-level=info && iptables -I OUTPUT  -p tcp -s "$int_ip1" -d "$blackout" --dport 53 -j LOG --log-prefix "[DNS-BL TCP OUT] " --log-level=info;
iptables -I INPUT 31  -p tcp -d "$int_ip1" -s "$blackout" --dport 53 -j LOG --log-prefix "[DNS-BL TCP IN] " --log-level=info && iptables -I INPUT 31  -p tcp -d "$int_ip1" -s "$blackout" --sport 53 -j LOG --log-prefix "[DNS-BL TCP IN] " --log-level=info;

#iptables -I FORWARD -p tcp -d "$int_ip1" -s "$blackout" --dport 53 -j DROP;
#iptables -I FORWARD -p tcp -s "$int_ip1" -d "$blackout" --dport 53 -j DROP;
#iptables -I FORWARD -p tcp -d "$int_ip1" -s "$blackout" --sport 53 -j DROP;
#iptables -I FORWARD -p tcp -s "$int_ip1" -d "$blackout" --sport 53 -j DROP;

#iptables -I FORWARD -p tcp -d "$int_ip1" -s "$blackout" --dport 53 -j LOG --log-prefix "[DNS-BL TCP FORWARD IN] " --log-level=info;
#iptables -I FORWARD -p tcp -s "$int_ip1" -d "$blackout" --dport 53 -j LOG --log-prefix "[DNS-BL TCP FORWARD OUT] " --log-level=info;
#iptables -I FORWARD -p tcp -d "$int_ip1" -s "$blackout" --sport 53 -j LOG --log-prefix "[DNS-BL TCP FORWARD IN] " --log-level=info;
#iptables -I FORWARD -p tcp -s "$int_ip1" -d "$blackout" --sport 53 -j LOG --log-prefix "[DNS-BL TCP FORWARD OUT] " --log-level=info;

)
echo "$blackout" ; 
done 
echo DNS BLACKLIST LOADED

echo EMAIL BLACKLIST LOADING
for blackout in $(cat email_blacklist.txt);
do 
(

iptables -I INPUT 31  -p tcp --dport 25 -m string --string "$blackout" --algo bm -j DROP && iptables -I OUTPUT  -p tcp --dport 25 -m string --string "$blackout" --algo bm -j DROP ;
iptables -I INPUT 31  -p tcp --dport 25 -m string --string "$blackout" --algo bm -j LOG --log-prefix "[EMAIL SPAM] " --log-level=info && iptables -I OUTPUT  -p tcp --dport 25 -m string --string "$blackout" --algo bm -j LOG --log-prefix "[EMAIL SPAM] " --log-level=info ;

#iptables -I FORWARD -p tcp --dport 25 -m string --string "$blackout" --algo bm -j DROP 
#iptables -I FORWARD -p tcp --dport 25 -m string --string "$blackout" --algo bm -j LOG --log-prefix "[EMAIL SPAM] " --log-level=info
)
echo $blackout ; 
done 
echo EMAIL BLACKLIST LOADED

echo HTML BLACKLIST LOADING
for blackout in $(cat html_blacklist.txt);
do 
(

iptables -I INPUT 31  -p tcp -m multiport --dports 80,443 -m string --string "$blackout" --algo bm -j DROP && iptables -I OUTPUT  -p tcp -m multiport --dports 80,443 -m string --string "$blackout" --algo bm -j DROP;
iptables -I INPUT 31  -p tcp -m multiport --dports 80,443 -m string --string "$blackout" --algo bm -j LOG --log-prefix "[HTTP SPAM] " --log-level=info && iptables -I OUTPUT  -p tcp -m multiport --dports 80,443 -m string --string "$blackout" --algo bm -j LOG --log-prefix "[HTTP SPAM] " --log-level=info;

#iptables -I FORWARD -p tcp -m multiport --dports 80,443 -m string --string "$blackout" --algo bm -j DROP 
#iptables -I FORWARD -p tcp -m multiport --dports 80,443 -m string --string "$blackout" --algo bm -j LOG --log-prefix "[HTTP SPAM] " --log-level=info;
)
echo "$blackout" ; 
done 
echo HTML BLACKLIST LOADED

echo ATTACKER BLACKLIST LOADING
for blackout in $(cat attackers.txt);
do 
(

iptables -I OUTPUT  -p all -s "$int_ip1" -d "$blackout" -j DROP && iptables -I INPUT 31  -p all -d "$int_ip1" -s "$blackout" -j DROP;
iptables -I OUTPUT  -p all -s "$int_ip1" -d "$blackout" -j LOG --log-prefix "[ATTACKER OUT] "  --log-level=info && iptables -I INPUT 31  -p all -d "$int_ip1" -s "$blackout" -j LOG --log-prefix "[ATTACKER IN] "  --log-level=info;

#iptables -I FORWARD -p all -d "$int_ip1" -s "$blackout" -j DROP;
#iptables -I FORWARD -p all -s "$int_ip1" -d "$blackout" -j DROP;

#iptables -I FORWARD -p all -d "$int_ip1" -s "$blackout" -j LOG --log-prefix "[ATTACKER FORWARD IN] "  --log-level=info;
#iptables -I FORWARD -p all -s "$int_ip1" -d "$blackout" -j LOG --log-prefix "[ATTACKER FORWARD OUT] "  --log-level=info;
)
echo "$blackout" ; 
done
echo ATTACKER BLACKLIST LOADED

echo LOADING BLACKLIST 
for blackout in $(cat blacklist.txt);
do 
(

iptables -I OUTPUT  -p all -d "$blackout" -j DROP && iptables -I INPUT 31  -p all -s "$blackout" -j DROP;
iptables -I OUTPUT  -p all -d "$blackout" -j LOG --log-prefix "[BLACKLIST OUT] " --log-level=info && "iptables" -I INPUT 31  -p all -s "$blackout" -j LOG --log-prefix "[BLACKLIST IN] "  --log-level=info;

#iptables -I FORWARD -p all -s "$blackout" -j DROP;
#iptables -I FORWARD -p all -d "$blackout" -j DROP;

#iptables -I FORWARD -p all -s "$blackout" -j LOG --log-prefix "[BLACKLIST FORWARD IN] "  --log-level=info;
#iptables -I FORWARD -p all -d "$blackout" -j LOG --log-prefix "[BLACKLIST FORWARD OUT] "  --log-level=info;
)
echo "$blackout" ; 
done
echo BLACKLIST LOADED

echo LOADING IPv6 BLACKLIST 
for blackout in $(cat ipv6_blacklist.txt);
do 
(

ip6tables -I OUTPUT  -p all -d "$blackout" -j DROP && ip6tables -I INPUT 31  -p all -s "$blackout" -j DROP;
ip6tables -I OUTPUT  -p all -d "$blackout" -j LOG --log-prefix "[IPv6 BLACKLIST OUT] " --log-level=info && ip6tables -I INPUT 31  -p all -s "$blackout" -j LOG --log-prefix "[IPv6 BLACKLIST IN] "  --log-level=info ;

#ip6tables -I FORWARD -p all  -s "$blackout" -j DROP;
#ip6tables -I FORWARD -p all  -d "$blackout" -j DROP;
#ip6tables -I FORWARD -p all  -s "$blackout" -j LOG --log-prefix "[IPv6 BLACKLIST FORWARD IN] "  --log-level=info;
#ip6tables -I FORWARD -p all  -d "$blackout" -j LOG --log-prefix "[IPv6 BLACKLIST FORWARD OUT] "  --log-level=info;
)
echo "$blackout" ; 
done
echo IPv6 BLACKLIST LOADED

####################################################################################
#                    IP FILTER WHITE LISTS
####################################################################################
# smtp_whitelist.txt
#echo SMTP WHITELIST LOADING
#for whiteout in $(cat smtp_whitelist.txt);
#do 
#(

#iptables -I OUTPUT  -p tcp -s "$int_ip1" -d "$whiteout" -m multiport --dports 25,587 -j ACCEPT && iptables -I INPUT 31  -p tcp -d "$int_ip1" -s "$whiteout" -m multiport --dports 25,587 -j ACCEPT;
#iptables -I OUTPUT  -p tcp -s "$int_ip1" -d "$whiteout" -m multiport --dports 25,587 -j LOG --log-prefix "[SMTP-WL OUT] " --log-level=info && iptables -I INPUT 31  -p tcp -d "$int_ip1" -s "$whiteout" -m multiport --dports 25,587 -j LOG --log-prefix "[SMTP-WL IN] " --log-level=info;

#iptables -I FORWARD -p tcp -d "$int_ip1" -s "$whiteout" -m multiport --dports 25,587 -j ACCEPT;
#iptables -I FORWARD -p tcp -s "$int_ip1" -d "$whiteout" -m multiport --dports 25,587 -j ACCEPT;

#iptables -I FORWARD -p tcp -d "$int_ip1" -s "$whiteout" -m multiport --dports 25,587 -j LOG --log-prefix "[SMTP-WL FORWARD IN] " --log-level=info;
#iptables -I FORWARD -p tcp -s "$int_ip1" -d "$whiteout" -m multiport --dports 25,587 -j LOG --log-prefix "[SMTP-WL FORWARD OUT] " --log-level=info;
#)
#echo "$whiteout" ; 
#done 
#echo SMTP WHITELIST LOADED

# http_whitelist.txt
#echo HTTP/HTTPS WHITELIST LOADING
#for whiteout in $(cat http_whitelist.txt);
#do 
#(

#iptables -I OUTPUT  -p tcp -s "$int_ip1" -d "$whiteout" -m multiport --dports 80,443 -j ACCEPT && iptables -I INPUT 31  -p tcp -d "$int_ip1" -s "$whiteout" -m multiport --dports 80,443 -j ACCEPT;
#iptables -I OUTPUT  -p tcp -s "$int_ip1" -d "$whiteout" -m multiport --dports 80,443 -j LOG --log-prefix "[HTTPS-WL OUT] " --log-level=info && iptables -I INPUT 31 -p tcp -d "$int_ip1" -s "$whiteout" -m multiport --dports 80,443 -j LOG --log-prefix "[HTTPS-WL IN] " --log-level=info 

#iptables -I FORWARD -p tcp -d "$int_ip1" -s "$whiteout" -m multiport --dports 80,443 -j ACCEPT;
#iptables -I FORWARD -p tcp -s "$int_ip1" -d "$whiteout" -m multiport --dports 80,443 -j ACCEPT;

#iptables -I FORWARD -p tcp -d "$int_ip1" -s "$whiteout" -m multiport --dports 80,443 -j LOG --log-prefix "[HTTPS-WL FORWARD IN] " --log-level=info;
#iptables -I FORWARD -p tcp -s "$int_ip1" -d "$whiteout" -m multiport --dports 80,443 -j LOG --log-prefix "[HTTPS-WL FORWARD OUT] " --log-level=info;
#)
#echo "$whiteout" ; 
#done 
#echo HTTP/HTTPS WHITELIST LOADED

##########################################################################################################################
#                                 SAVE RULES
#####################################################################################################################
#ARCH/PARABOLA
iptables-save  > /etc/iptables/iptables.rules
ip6tables-save > /etc/iptables/ip6tables.rules

#DEBIAN/UBUNTU
iptables-save  > /etc/iptables/rules.v4
ip6tables-save > /etc/iptables/rules.v6

# RHEL/CENTOS/FEDORA
iptables-save  > /etc/iptables/iptables
ip6tables-save > /etc/iptables/ip6tables

############ RHEL/CENTOS/FEDORA
#iptables-save  > /etc/iptables/iptables
#ip6tables-save > /etc/iptables/ip6tables
#########  DEBIAN/UBUNTU
# iptables-save >  /etc/iptables/rules.v4
# ip6tables-save > /etc/iptables/rules.v6 
######### ARCH/PARABOLA/ARCHBANG/ANTERGOS/MANJARO
# iptables-save >  /etc/iptables/iptables.rules 
# ip6tables-save > /etc/iptables/ip6tables.rules 

echo "ENDLISTS LOADED"
################################  PRINT RULES   ###############################################################
#list the rules
#iptables -L -v
#ip6tables -L -v

#############################   PRINT ADDRESSES  ############################################################
echo GATEWAY  :          MAC:$gateway_mac  IP:$gateway_ip  
echo INTERFACE_1: "$int_if"  MAC:"$int_mac"  IPv4:"$int_ip1" IPv6:"$int_ip1v6" 
echo INTERFACE_2: "$int_if2" MAC:"$int_mac2" IPv4:"$int_ip2" IPv6:"$int_ip2v6"
# print the time the script finishes
date
