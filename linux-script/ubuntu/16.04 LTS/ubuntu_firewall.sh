#!/bin/bash
################################################
# 
# Script Firewall for INPUT and OUTPUT rules
#
# https://help.ubuntu.com/community/UFW
# https://www.digitalocean.com/community/tutorials/iptables-essentials-common-firewall-rules-and-commands
# https://www.cyberciti.biz/tips/linux-unix-bsd-nginx-webserver-security.html
# 
################################################
version_num=20181010
RED="\033[0;31m"
GREEN="\033[0;32m"
NO_COLOR="\033[0m"

# define interfaces IP
MY_ETH0_IP=$(ifconfig eth0 | grep inet | awk '{print $2}' | awk -F ":" '{print $2}')
MY_ETH0_IP_SEG="${MY_ETH0_IP%.*}.0/24"

### Interfaces ###
PUB_IF=$MY_ETH0_IP   # public interface
LO_IF="lo"           # loopback
VPN_IF="eth1"        # vpn / private net

backup_rules() {
  echo "Saving iptables rules: "
  mkdir -p /etc/iptables_history
  IPT_BACKUP_FILE=/etc/iptables_history/iptables.$(date +%y%m%d_%H%M%S)
  iptables-save > $IPT_BACKUP_FILE
  echo -e "$GREEN Iptables rules saved in $IPT_BACKUP_FILE $NO_COLOR"
}

clean_iptables() {
  echo "Cleaning rules - setting policies - flush rules - delete chains: "
  iptables -P INPUT ACCEPT
  iptables -P OUTPUT ACCEPT
  iptables -P FORWARD DROP

  iptables --flush        # Flush all rules, but keep policies
  iptables -t nat --flush	# Flush NAT table as well
  iptables --delete-chain
  iptables -t mangle -F
  echo -e "$GREEN Cleaning done. $NO_COLOR"
}

input_rules() {
  echo -en "Creating rules for allowed INPUT traffic: $RED\n"
  # Unlimited lo access
  iptables -A INPUT -i lo -j ACCEPT
  # Unlimited vpn / pnet access
  if ifconfig eth1 &> /dev/null;then
	  iptables -A INPUT -i eth0 -j ACCEPT
  else
    # Local traffic - allow all on intranet interface. <<<Apply to VPC environment>>>
    iptables -A INPUT -p tcp -m state --state NEW -m tcp -s $MY_ETH0_IP_SEG -j ACCEPT
  fi
  iptables -A INPUT -p tcp -m state --state NEW -m tcp -s localhost -j ACCEPT

  iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
  iptables -A INPUT -p icmp -m icmp --icmp-type echo-request -m limit --limit 10/second -j ACCEPT
  iptables -A INPUT -p icmp -m icmp --icmp-type echo-reply -m limit --limit 10/second -j ACCEPT
  iptables -A INPUT -p icmp -m icmp --icmp-type time-exceeded -m limit --limit 10/second -j ACCEPT
  iptables -A INPUT -p icmp -m icmp --icmp-type destination-unreachable -m limit --limit 10/second -j ACCEPT
  iptables -A INPUT -p icmp -j DROP
  
  ###### Add the input rules here:
  # iptables -A INPUT -p tcp -m state --state NEW -m tcp -s <source_address> --dport <destnation_port> -j ACCEPT
  ###### Add an end
  
  # ssh 端口只对跳板机开放
  iptables -A INPUT -p tcp -m state --state NEW -m tcp -s xxx.xxx.xxx.xxx --dport 22 -j ACCEPT
  
  # 80、443 端口只对 SLB 开放
  iptables -A INPUT -p tcp -m state --state NEW -m tcp -s xxx.xxx.xxx.xxx --dport 80 -j ACCEPT
  iptables -A INPUT -p tcp -m state --state NEW -m tcp -s xxx.xxx.xxx.xxx --dport 443 -j ACCEPT
  
  # allow your own app port
  iptables -A INPUT -p tcp -m state --state NEW -m tcp -s xxx.xxx.xxx.xxx --dport xxx -j ACCEPT
  
  iptables -A INPUT -j DROP
  echo -e "$GREEN INPUT rules created done. $NO_COLOR"
}

output_rules() {
  echo -en "Creating rules for allowed OUTPUT traffic: $RED\n"
  # Unlimited lo access
  iptables -A OUTPUT -o lo -j ACCEPT
  # Unlimited vpn / pnet access
  if ifconfig eth1 &> /dev/null;then
	  iptables -A OUTPUT -o eth0 -j ACCEPT
  else
    # Local traffic - allow all on intranet interface. <<<Apply to VPC environment>>>
    iptables -A OUTPUT -p tcp -m state --state NEW -m tcp -s $MY_ETH0_IP_SEG -j ACCEPT
  fi
  iptables -A OUTPUT -p tcp -m state --state NEW -m tcp -s localhost -j ACCEPT
  
  iptables -A OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
  iptables -A OUTPUT -p icmp -m icmp --icmp-type echo-request -m limit --limit 10/second -j ACCEPT
  iptables -A OUTPUT -p icmp -m icmp --icmp-type echo-reply -m limit --limit 10/second -j ACCEPT
  iptables -A OUTPUT -p icmp -m icmp --icmp-type time-exceeded -m limit --limit 10/second -j ACCEPT
  iptables -A OUTPUT -p icmp -m icmp --icmp-type destination-unreachable -m limit --limit 10/second -j ACCEPT
  iptables -A OUTPUT -p icmp -j DROP
  
  ###### Add the output rules here:
  # iptables -A OUTPUT -p tcp -m state --state NEW -d <destnation_address> --dport <destnation_port> -j ACCEPT
  ###### Add an end
  
  # allow DNS-NTP-FTP-HTTP-HTTPS-SMTP
  PORTS1="53 123"
  for port1 in $PORTS1;do iptables -A OUTPUT -p udp -m state --state NEW --dport $port1 -j ACCEPT;done
  PORTS2="22 21 80 443 25"
  for port2 in $PORTS2;do iptables -A OUTPUT -p tcp -m state --state NEW --dport $port2 -j ACCEPT;done
  
  # allow your own port
  PORTS3="8888 9999 "
  for port3 in $PORTS3;do iptables -A OUTPUT -p tcp -m state --state NEW --dport $port3 -j ACCEPT;done
  
  iptables -A OUTPUT -j DROP
  echo -e "$GREEN OUTPUT rules created done. $NO_COLOR"
}

if ! id |grep "uid=0(root)" &> /dev/null; then
	echo -e "$RED ERROR: You need to run this script as ROOT user $NO_COLOR" >&2
	exit 2
fi
if [ "$1" = "-h" ] || [ "$1" = "-H" ] || [ "$1" = "--help" ] || [ "$1" = "--HELP" ]; then
   echo "Please run in the root user: bash script_firewall.sh !!"
   exit 2
fi

save_rules(){
  if [ ! -f "/etc/iptables.conf" ]; then
      touch /etc/iptables.conf
  fi
  iptables-save > /etc/iptables.conf

  grep 'iptables-restore' /etc/rc.local &> /dev/null
  if [ $? != 0 ] ; then
    sed -i '/exit\s0/d' /etc/rc.local
    echo -e "iptables-restore < /etc/iptables.conf\nexit 0" >> /etc/rc.local
  fi
  
  echo -e "$GREEN iptables rules saved done. $NO_COLOR"
}

echo "############################################"
echo $(basename $0)
printf "Version: %s\n" $version_num
echo "############################################"
backup_rules
clean_iptables
input_rules
output_rules
save_rules
echo "############################################"
echo "Done. "
