#! /bin/bash
####################################################################################
#                        HEADER AND INSTRUCTIONS
####################################################################################
# Program: endlists.sh
# Type: bash shell script
# Current Version: 1.10  Feb 14 2016
# Stable Version:  1.02, Feb 13 2016
# Author: Endwall Development Team
#
# Description:  Traditional iptables list based blacklisting 
#
# Changes:  - Fixed the logging bug (reversed the order of drop and log)
#           - Use && to execute log and drop rules in parallel (multiprocess)
#           - changed echo to Endlists Loaded
#           - Fixed a typo in the smtp blacklist section
#           - Changed order of blacklists and whitelists
#           - Changed some blacklist settings for http and smtp
#           - Moved blacklists out of endwall.sh and into endlists.sh
#           - Made save rules non distribution specific
#           
#
#
# Instructions: make directory,copy the file and change name to endlists.sh
#               make whitelists,blacklist text files, edit the endlists.sh file
#               change permisions to make endlists.sh executable, run the file.    
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
# $ nano endlists.sh   # go to the section below labeled GLOBAL VARIABLES
#                       edit the variables client1_ip,client1_mac,client1_ip,client2_mac 
#                       so that they match your needs and save. ^X  
#                       uncomment the macchanger lines to use machanger
# $ chmod u+rwx endlists.sh          # change permisions to allow script execution 
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
################################################################################################
#                           GLOBAL VARIABLES
################################################################################################
iptables=/sbin/iptables
ip6tables=/sbin/ip6tables

#systemctl enable iptables
#systemctl enable ip6tables
#systemctl enable iptables.service
#systemctl enable ip6tables.service
#systemctl restart iptables
#systemctl restart ip6tables

# Grab interface name from ip link and parse 
int_if=$(ip link | grep -a "2: " | gawk -F: '{ print $2}')
int_if2=$(ip link | grep -a "3: " | gawk -F: '{ print $2}')

# Grab Gateway Information
gateway_ip=$(ip route | gawk '/via/ {print $3}')
#gateway_mac=$( arp | gawk '/gateway/ {print $3}')
gateway_mac=$( nmap -sS $gateway_ip -p 53| grep -a "MAC Address:" | gawk '{print $3}')


# RUN MAC CHANGER on INTERFACES
#macchanger -A $int_if
#macchanger -A $int_if2

# grab host mac addresses from ip link  
host_mac=$(ip link | grep -a "ether" | gawk ' {if (FNR==1) print $2}')
host_mac2=$(ip link | grep -a "ether" | gawk ' {if (FNR==2) print $2}')

# grab the ip addresses from the interfaces
host_ip=$(ip addr | grep -a "scope global"|gawk 'BEGIN  {FS="/"} {if (FNR==1) print $1}'| gawk '{print $2}')
host_ip2=$(ip addr | grep -a "scope global"|gawk 'BEGIN  {FS="/"} {if (FNR==2) print $1}'| gawk '{print $2}')

host_ip1v6=$(ip addr | grep -a "scope link"|gawk 'BEGIN  {FS="/"} {if (FNR==1) print $1}'| gawk '{print $2}')
host_ip2v6=$(ip addr | grep -a "scope link"|gawk 'BEGIN  {FS="/"} {if (FNR==2) print $1}'| gawk '{print $2}')

############################  CLIENTS  ################################################
# change these values but dont leave them blank
# add more clients as you need them use $ arp or $ nmap -sS client_ip to determine values 

#client1_mac=00:00:00:00:00:00  # change to be the mac address of client 1
#client2_mac=00:00:00:00:00:00  # change to be the mac address of client 2

#client1_ip=192.168.0.161   # change to be the static ip of your first internal client
#client2_ip=192.168.0.162   # change to be the static ip of your second internal client

########################### INTERNAL VARIABLES ################################## 
int_mac=$host_mac         # internal mac address of interface 1
int_mac2=$host_mac2       # internal mac address of interface 2 
int_ip1=$host_ip          # internal ipv4 address of interface 1  
int_ip1v6=$host_ip1v6     # internal ipv6 address of interface 1  
int_ip2=$host_ip2         # internal ipv4 address of interface 2
int_ip2v6=$host_ip2v6     # internal ipv6 address of interface 2


# int_if2,int_ip2 and int_mac2 are not currently used in this script, you may safely comment these lines out. 

###################################################################################################################################
#                              LINUX SECURITY BOOLEANS
###################################################################################################################################
# Disable Source Routed Packets
for f in /proc/sys/net/ipv4/conf/*/accept_source_route; do
       echo 0 > $f
done

# Disable ICMP Redirect Acceptance
for f in /proc/sys/net/ipv4/conf/*/accept_redirects; do
      echo 0 > $f
done

# Don't send Redirect Messages
for f in /proc/sys/net/ipv4/conf/*/send_redirects; do
     echo 0 > $f
done

# Drop Spoofed Packets coming in on an interface, which if replied to,
# would result in the reply going out a different interface.
for f in /proc/sys/net/ipv4/conf/*/rp_filter; do
     echo 1 > $f
done

# Log packets with impossible addresses.
for f in /proc/sys/net/ipv4/conf/*/log_martians; do
     echo 1 > $f
done

echo 1 > /proc/sys/net/ipv4/tcp_syncookies                              # enable tcp syn cookies (prevent against the common 'syn flood attack')
echo 0 > /proc/sys/net/ipv4/ip_forward                                  # disable Packet forwarning between interfaces
echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts                 # ignore all ICMP ECHO and TIMESTAMP requests sent to it via broadcast/multicast
echo 1 > /proc/sys/net/ipv4/icmp_ignore_bogus_error_responses           # disable logging of bogus responses to broadcast frames
echo 1 > /proc/sys/net/ipv4/conf/all/log_martians                       # log packets with impossible addresses to kernel log
echo 1 > /proc/sys/net/ipv4/conf/all/rp_filter                          # do source validation by reversed path (Recommended option for single homed hosts)
echo 0 > /proc/sys/net/ipv4/conf/all/accept_source_route                # Disable source routed packets redirects
echo 0 > /proc/sys/net/ipv4/conf/all/accept_redirects                   # don't accept redirects
echo 0 > /proc/sys/net/ipv4/conf/all/send_redirects                     # don't send redirects
echo 0 > /proc/sys/net/ipv4/conf/all/accept_source_route                # don't accept packets with SRR option

echo 0 > /proc/sys/net/ipv6/conf/all/accept_redirects                   # don't accept redirects
echo 0 > /proc/sys/net/ipv6/conf/all/accept_source_route                # don't accept packets with SRR option

#echo 1 > /proc/sys/net/ipv4/conf/all/disable_ipv6                      # disable ipv6
#setsebool httpd_can_network_connect on   #needed for squirelmail if you are on selinux
#setsebool httpd_can_sendmail on          #needed for squirelmail send if you are selinux

####################################################################################
#                    IP FILTER BLACK LISTS
####################################################################################
#

echo HTTP/HTTPS BLACKLIST LOADING
for blackout in $(cat http_blacklist.txt);
do 
(

iptables -I OUTPUT   -p tcp -s $int_ip1 -d $blackout -m multiport --dports 80,443 -j DROP && iptables -I OUTPUT   -p tcp -s $int_ip1 -d $blackout -m multiport --sports 80,443 -j DROP;
iptables -I INPUT 27   -p tcp -d $int_ip1 -s $blackout -m multiport --dports 80,443 -j DROP && iptables -I INPUT 27   -p tcp -d $int_ip1 -s $blackout -m multiport --sports 80,443 -j DROP;

iptables -I OUTPUT  -p tcp -s $int_ip1 -d $blackout -m multiport  --dports 80,443 -j LOG --log-prefix "[HTTP-BL OUT] "  --log-level=info && iptables -I OUTPUT  -p tcp -s $int_ip1 -d $blackout -m multiport  --sports 80,443 -j LOG --log-prefix "[HTTP-BL OUT] "  --log-level=info 
iptables -I INPUT 27   -p tcp -d $int_ip1 -s $blackout -m multiport --dports 80,443 -j LOG --log-prefix "[HTTP-BL IN] " --log-level=info && iptables -I INPUT 27   -p tcp -d $int_ip1 -s $blackout -m multiport --sports 80,443 -j LOG --log-prefix "[HTTP-BL IN] " --log-level=info 

#iptables -I FORWARD  -p tcp -d $int_ip1 -s $blackout -m multiport --dports 80,443 -j DROP;
#iptables -I FORWARD  -p tcp -s $int_ip1 -d $blackout -m multiport --dports 80,443 -j DROP;
#iptables -I FORWARD  -p tcp -d $int_ip1 -s $blackout -m multiport --dports 80,443 -j LOG --log-prefix "[HTTP-BL FORWARD IN] "  --log-level=info;
#iptables -I FORWARD  -p tcp -s $int_ip1 -d $blackout -m multiport --dports 80,443 -j LOG --log-prefix "[HTTP-BL FORWARD OUT] " --log-level=info;
)
echo $blackout ; 
done 
echo HTTP BLACKLIST LOADED

#smtp_blacklist.txt
echo SMTP BLACKLIST LOADING
for blackout in $(cat smtp_blacklist.txt);
do 
(

iptables -I OUTPUT  -p tcp -s $int_ip1 -d $blackout -m multiport --dports 25,587 -j DROP && iptables -I OUTPUT  -p tcp -s $int_ip1 -d $blackout -m multiport --sports 25,587 -j DROP;
iptables -I INPUT 27  -p tcp -d $int_ip1 -s $blackout -m multiport --dports 25,587 -j DROP && iptables -I INPUT 27  -p tcp -d $int_ip1 -s $blackout -m multiport --sports 25,587 -j DROP;

iptables -I OUTPUT  -p tcp -s $int_ip1 -d $blackout -m multiport --dports 25,587 -j LOG --log-prefix "[SMTP-BL SPAM OUT] " --log-level=info &&iptables -I OUTPUT  -p tcp -s $int_ip1 -d $blackout -m multiport --sports 25,587 -j LOG --log-prefix "[SMTP-BL SPAM OUT] " --log-level=info; 
iptables -I INPUT 27  -p tcp -d $int_ip1 -s $blackout -m multiport --dports 25,587 -j LOG --log-prefix "[SMTP-BL SPAM IN] " --log-level=info && iptables -I INPUT 27  -p tcp -d $int_ip1 -s $blackout -m multiport --sports 25,587 -j LOG --log-prefix "[SMTP-BL SPAM IN] " --log-level=info ;

#iptables -I FORWARD -p tcp -d $int_ip1 -s $blackout -m multiport --dports 25,587 -j DROP;
#iptables -I FORWARD -p tcp -s $int_ip1 -d $blackout -m multiport --dports 25,587 -j DROP;
#iptables -I FORWARD -p tcp -d $int_ip1 -s $blackout -m multiport --dports 25,587 -j LOG --log-prefix "[SMTP-BL FORWARD IN] " --log-level=info;
#iptables -I FORWARD -p tcp -s $int_ip1 -d $blackout -m multiport --dports 25,587 -j LOG --log-prefix "[SMTP-BL FORWARD OUT] " --log-level=info;
)
echo $blackout ; 
done 
echo SMTP BLACKLIST LOADED

echo DNS BLACKLIST LOADING
for blackout in $(cat dns_blacklist.txt);
do 
(
iptables  -I OUTPUT  -p udp -s $int_ip1 -d $blackout --dport 53 -j DROP && iptables  -I OUTPUT  -p udp -s $int_ip1 -d $blackout --sport 53 -j DROP;
iptables  -I INPUT 27  -p udp -d $int_ip1 -s $blackout --dport 53 -j DROP && iptables  -I INPUT 27  -p udp -d $int_ip1 -s $blackout --sport 53 -j DROP;


iptables  -I OUTPUT  -p udp -s $int_ip1 -d $blackout --dport 53 -j LOG --log-prefix "[DNS-BL UDP OUT] " --log-level=info && iptables  -I OUTPUT  -p udp -s $int_ip1 -d $blackout --sport 53 -j LOG --log-prefix "[DNS-BL UDP OUT] " --log-level=info 
iptables  -I INPUT 27  -p udp -d $int_ip1 -s $blackout --dport 53 -j LOG --log-prefix "[DNS-BL UDP IN] " --log-level=info && iptables  -I INPUT 27  -p udp -d $int_ip1 -s $blackout --sport 53 -j LOG --log-prefix "[DNS-BL UDP IN] " --log-level=info 

#iptables  -I FORWARD -p udp -d $int_ip1 -s $blackout --dport 53 -j DROP;
#iptables  -I FORWARD -p udp -s $int_ip1 -d $blackout --dport 53 -j DROP;
#iptables  -I FORWARD -p udp -d $int_ip1 -s $blackout --sport 53 -j DROP;
#iptables  -I FORWARD -p udp -s $int_ip1 -d $blackout --sport 53 -j DROP;

#iptables  -I FORWARD -p udp -d $int_ip1 -s $blackout --dport 53 -j LOG --log-prefix "[DNS-BL UDP FORWARD IN] " --log-level=info;
#iptables  -I FORWARD -p udp -s $int_ip1 -d $blackout --dport 53 -j LOG --log-prefix "[DNS-BL UDP FORWARD OUT] " --log-level=info;
#iptables  -I FORWARD -p udp -d $int_ip1 -s $blackout --sport 53 -j LOG --log-prefix "[DNS-BL UDP FORWARD IN] " --log-level=info;
#iptables  -I FORWARD -p udp -s $int_ip1 -d $blackout --sport 53 -j LOG --log-prefix "[DNS-BL UDP FORWARD OUT] " --log-level=info;

iptables -I OUTPUT  -p tcp -s $int_ip1 -d $blackout --dport 53 -j DROP && iptables -I OUTPUT  -p tcp -s $int_ip1 -d $blackout --sport 53 -j DROP;
iptables -I INPUT 27  -p tcp -d $int_ip1 -s $blackout --dport 53 -j DROP && iptables -I INPUT 27  -p tcp -d $int_ip1 -s $blackout --sport 53 -j DROP;

iptables -I OUTPUT  -p tcp -s $int_ip1 -d $blackout --sport 53 -j LOG --log-prefix "[DNS-BL TCP OUT] " --log-level=info && iptables -I OUTPUT  -p tcp -s $int_ip1 -d $blackout --dport 53 -j LOG --log-prefix "[DNS-BL TCP OUT] " --log-level=info;
iptables -I INPUT 27  -p tcp -d $int_ip1 -s $blackout --dport 53 -j LOG --log-prefix "[DNS-BL TCP IN] " --log-level=info && iptables -I INPUT 27  -p tcp -d $int_ip1 -s $blackout --sport 53 -j LOG --log-prefix "[DNS-BL TCP IN] " --log-level=info;

#iptables -I FORWARD -p tcp -d $int_ip1 -s $blackout --dport 53 -j DROP;
#iptables -I FORWARD -p tcp -s $int_ip1 -d $blackout --dport 53 -j DROP;
#iptables -I FORWARD -p tcp -d $int_ip1 -s $blackout --sport 53 -j DROP;
#iptables -I FORWARD -p tcp -s $int_ip1 -d $blackout --sport 53 -j DROP;

#iptables -I FORWARD -p tcp -d $int_ip1 -s $blackout --dport 53 -j LOG --log-prefix "[DNS-BL TCP FORWARD IN] " --log-level=info;
#iptables -I FORWARD -p tcp -s $int_ip1 -d $blackout --dport 53 -j LOG --log-prefix "[DNS-BL TCP FORWARD OUT] " --log-level=info;
#iptables -I FORWARD -p tcp -d $int_ip1 -s $blackout --sport 53 -j LOG --log-prefix "[DNS-BL TCP FORWARD IN] " --log-level=info;
#iptables -I FORWARD -p tcp -s $int_ip1 -d $blackout --sport 53 -j LOG --log-prefix "[DNS-BL TCP FORWARD OUT] " --log-level=info;

)
echo $blackout ; 
done 
echo DNS BLACKLIST LOADED

echo EMAIL BLACKLIST LOADING
for blackout in $(cat email_blacklist.txt);
do 
(

iptables -I INPUT 27  -p tcp --dport 25 -m string --string "$blackout" --algo bm -j DROP && iptables -I OUTPUT  -p tcp --dport 25 -m string --string "$blackout" --algo bm -j DROP ;
iptables -I INPUT 27  -p tcp --dport 25 -m string --string "$blackout" --algo bm -j LOG --log-prefix "[EMAIL SPAM] " --log-level=info && iptables -I OUTPUT  -p tcp --dport 25 -m string --string "$blackout" --algo bm -j LOG --log-prefix "[EMAIL SPAM] " --log-level=info ;

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

iptables -I INPUT 27  -p tcp -m multiport --dports 80,443 -m string --string "$blackout" --algo bm -j DROP && iptables -I OUTPUT  -p tcp -m multiport --dports 80,443 -m string --string "$blackout" --algo bm -j DROP;
iptables -I INPUT 27  -p tcp -m multiport --dports 80,443 -m string --string "$blackout" --algo bm -j LOG --log-prefix "[HTTP SPAM] " --log-level=info && iptables -I OUTPUT  -p tcp -m multiport --dports 80,443 -m string --string "$blackout" --algo bm -j LOG --log-prefix "[HTTP SPAM] " --log-level=info;

#iptables -I FORWARD -p tcp -m multiport --dports 80,443 -m string --string "$blackout" --algo bm -j DROP 
#iptables -I FORWARD -p tcp -m multiport --dports 80,443 -m string --string "$blackout" --algo bm -j LOG --log-prefix "[HTTP SPAM] " --log-level=info;
)
echo $blackout ; 
done 
echo HTML BLACKLIST LOADED

echo ATTACKER BLACKLIST LOADING
for blackout in $(cat attackers.txt);
do 
(

iptables -I OUTPUT  -p all -s $int_ip1 -d $blackout -j DROP && iptables -I INPUT 27  -p all -d $int_ip1 -s $blackout -j DROP;
iptables -I OUTPUT  -p all -s $int_ip1 -d $blackout -j LOG --log-prefix "[ATTACKER OUT] "  --log-level=info && iptables -I INPUT 27  -p all -d $int_ip1 -s $blackout -j LOG --log-prefix "[ATTACKER IN] "  --log-level=info;

#iptables -I FORWARD -p all -d $int_ip1 -s $blackout -j DROP;
#iptables -I FORWARD -p all -s $int_ip1 -d $blackout -j DROP;

#iptables -I FORWARD -p all -d $int_ip1 -s $blackout -j LOG --log-prefix "[ATTACKER FORWARD IN] "  --log-level=info;
#iptables -I FORWARD -p all -s $int_ip1 -d $blackout -j LOG --log-prefix "[ATTACKER FORWARD OUT] "  --log-level=info;
)
echo $blackout ; 
done
echo ATTACKER BLACKLIST LOADED

echo LOADING BLACKLIST 
for blackout in $(cat blacklist.txt);
do 
(

iptables -I OUTPUT  -p all -d $blackout -j DROP && iptables -I INPUT 27  -p all -s $blackout -j DROP;
iptables -I OUTPUT  -p all -d $blackout -j LOG --log-prefix "[BLACKLIST OUT] " --log-level=info && iptables -I INPUT 27  -p all -s $blackout -j LOG --log-prefix "[BLACKLIST IN] "  --log-level=info;

#iptables -I FORWARD -p all -s $blackout -j DROP;
#iptables -I FORWARD -p all -d $blackout -j DROP;

#iptables -I FORWARD -p all -s $blackout -j LOG --log-prefix "[BLACKLIST FORWARD IN] "  --log-level=info;
#iptables -I FORWARD -p all -d $blackout -j LOG --log-prefix "[BLACKLIST FORWARD OUT] "  --log-level=info;
)
echo $blackout ; 
done
echo BLACKLIST LOADED

echo LOADING IPv6 BLACKLIST 
for blackout in $(cat ipv6_blacklist.txt);
do 
(

ip6tables -I OUTPUT  -p all -d $blackout -j DROP && ip6tables -I INPUT 27  -p all -s $blackout -j DROP;
ip6tables -I OUTPUT  -p all -d $blackout -j LOG --log-prefix "[IPv6 BLACKLIST OUT] " --log-level=info && ip6tables -I INPUT 27  -p all -s $blackout -j LOG --log-prefix "[IPv6 BLACKLIST IN] "  --log-level=info ;

#ip6tables -I FORWARD -p all  -s $blackout -j DROP;
#ip6tables -I FORWARD -p all  -d $blackout -j DROP;
#ip6tables -I FORWARD -p all  -s $blackout -j LOG --log-prefix "[IPv6 BLACKLIST FORWARD IN] "  --log-level=info;
#ip6tables -I FORWARD -p all  -d $blackout -j LOG --log-prefix "[IPv6 BLACKLIST FORWARD OUT] "  --log-level=info;
)
echo $blackout ; 
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

iptables -I OUTPUT  -p tcp -s $int_ip1 -d $whiteout -m multiport --dports 25,587 -j ACCEPT && iptables -I INPUT 27  -p tcp -d $int_ip1 -s $whiteout -m multiport --dports 25,587 -j ACCEPT;
iptables -I OUTPUT  -p tcp -s $int_ip1 -d $whiteout -m multiport --dports 25,587 -j LOG --log-prefix "[SMTP-WL OUT] " --log-level=info && iptables -I INPUT 27  -p tcp -d $int_ip1 -s $whiteout -m multiport --dports 25,587 -j LOG --log-prefix "[SMTP-WL IN] " --log-level=info;

#iptables -I FORWARD -p tcp -d $int_ip1 -s $whiteout -m multiport --dports 25,587 -j ACCEPT;
#iptables -I FORWARD -p tcp -s $int_ip1 -d $whiteout -m multiport --dports 25,587 -j ACCEPT;

#iptables -I FORWARD -p tcp -d $int_ip1 -s $whiteout -m multiport --dports 25,587 -j LOG --log-prefix "[SMTP-WL FORWARD IN] " --log-level=info;
#iptables -I FORWARD -p tcp -s $int_ip1 -d $whiteout -m multiport --dports 25,587 -j LOG --log-prefix "[SMTP-WL FORWARD OUT] " --log-level=info;
#)
#echo $whiteout ; 
#done 
#echo SMTP WHITELIST LOADED

# http_whitelist.txt
#echo HTTP/HTTPS WHITELIST LOADING
#for whiteout in $(cat http_whitelist.txt);
#do 
#(

iptables -I OUTPUT  -p tcp -s $int_ip1 -d $whiteout -m multiport --dports 80,443 -j ACCEPT && iptables -I INPUT 27  -p tcp -d $int_ip1 -s $whiteout -m multiport --dports 80,443 -j ACCEPT;
iptables -I OUTPUT  -p tcp -s $int_ip1 -d $whiteout -m multiport --dports 80,443 -j LOG --log-prefix "[HTTPS-WL OUT] " --log-level=info && iptables -I INPUT 27  -p tcp -d $int_ip1 -s $whiteout -m multiport --dports 80,443 -j LOG --log-prefix "[HTTPS-WL IN] " --log-level=info 

#iptables -I FORWARD -p tcp -d $int_ip1 -s $whiteout -m multiport --dports 80,443 -j ACCEPT;
#iptables -I FORWARD -p tcp -s $int_ip1 -d $whiteout -m multiport --dports 80,443 -j ACCEPT;

#iptables -I FORWARD -p tcp -d $int_ip1 -s $whiteout -m multiport --dports 80,443 -j LOG --log-prefix "[HTTPS-WL FORWARD IN] " --log-level=info;
#iptables -I FORWARD -p tcp -s $int_ip1 -d $whiteout -m multiport --dports 80,443 -j LOG --log-prefix "[HTTPS-WL FORWARD OUT] " --log-level=info;
#)
#echo $whiteout ; 
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
echo INTERFACE_1: $int_if  MAC:$int_mac  IPv4:$int_ip1 IPv6:$int_ip1v6 
echo INTERFACE_2: $int_if2 MAC:$int_mac2 IPv4:$int_ip2 IPv6:$int_ip2v6
# print the time the script finishes
date
