#!/bin/bash
################################################
# Script Firewall for INPUT and OUTPUT rules
################################################
version_num=20150526
RED="\033[0;31m"
GREEN="\033[0;32m"
NO_COLOR="\033[0m"

# define interfaces IP
MY_ETH0_IP=$(ifconfig eth0 | grep inet | awk '{print $2}' | awk -F ":" '{print $2}')
MY_ETH0_IP_SEG="${MY_ETH0_IP%.*}.0/24"

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
  iptables -A INPUT -i lo -j ACCEPT
  if ifconfig eth1 &> /dev/null;then
	iptables -A INPUT -i eth0 -j ACCEPT
  else
    # Local traffic - allow all on intranet interface. <<<Apply to VPC environment>>>
    iptables -A INPUT -p tcp -m state --state NEW -m tcp -s $MY_ETH0_IP_SEG -j ACCEPT
  fi

  iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
  iptables -A INPUT -p icmp -m icmp --icmp-type echo-request -m limit --limit 10/second -j ACCEPT
  iptables -A INPUT -p icmp -m icmp --icmp-type echo-reply -m limit --limit 10/second -j ACCEPT
  iptables -A INPUT -p icmp -m icmp --icmp-type time-exceeded -m limit --limit 10/second -j ACCEPT
  iptables -A INPUT -p icmp -m icmp --icmp-type destination-unreachable -m limit --limit 10/second -j ACCEPT
  iptables -A INPUT -p icmp -j DROP

  ###### SSH inbound -- only from the main interface - to be changed in the future if we want to access it only through the private IF
  tiaobanji="115.29.244.224 42.96.192.168 115.29.209.204 121.42.151.134"
  for ip in $tiaobanji
    do
      iptables -A INPUT -p tcp -m state --state NEW -m tcp -s $ip --dport 40022 -j ACCEPT
    done

  ###### Zabbix agentd inbound
  iptables -A INPUT -p tcp -m state --state NEW -m tcp -s 114.215.177.175 --dport 10050:10051 -j ACCEPT
  iptables -A INPUT -p tcp -m state --state NEW -m tcp -s 116.62.38.146 --dport 10050:10051 -j ACCEPT
  iptables -A INPUT -p tcp -m state --state NEW -m tcp -s 59.110.24.125 --dport 10050:10051 -j ACCEPT

  ###### Add the input rules here:
#  iptables -A INPUT -p tcp -m state --state NEW -m tcp -s <source_address> --dport <destnation_port> -j ACCEPT
  ###### Add an end
  # 80 端口只对 SLB 开放
  iptables -A INPUT -p tcp -m state --state NEW -m tcp -s 42.121.254.88 --dport 80 -j ACCEPT
  iptables -A INPUT -p tcp -m state --state NEW -m tcp -s 100.98.227.68 --dport 80 -j ACCEPT
  iptables -A INPUT -p tcp -m state --state NEW -m tcp -s 115.29.253.54 --dport 80 -j ACCEPT

  # 开放 8150 端口 (lvguanjia)
  iptables -A INPUT -p tcp -m state --state NEW -m tcp -s 47.90.104.240 --dport 8150 -j ACCEPT
  iptables -A INPUT -p tcp -m state --state NEW -m tcp -s 10.0.0.0/8 --dport 8150 -j ACCEPT
  iptables -A INPUT -p tcp -m state --state NEW -m tcp -s 10.173.162.142 --dport 8150 -j DROP
  iptables -A INPUT -p tcp -m state --state NEW -m tcp -s 10.169.2.12 --dport 8150 -j DROP

  # 开放  8160 端口 (clubserver)
  iptables -A INPUT -p tcp -m state --state NEW -m tcp -s 10.0.0.0/8 --dport 8160 -j ACCEPT
  iptables -A INPUT -p tcp -m state --state NEW -m tcp -s 10.173.162.142 --dport 8160 -j DROP
  iptables -A INPUT -p tcp -m state --state NEW -m tcp -s 10.169.2.12 --dport 8160 -j DROP

  # 开放  8130 端口 (clubcloudserver)
  iptables -A INPUT -p tcp -m state --state NEW -m tcp -s 47.90.104.240 --dport 8130 -j ACCEPT
  iptables -A INPUT -p tcp -m state --state NEW -m tcp -s 10.0.0.0/8 --dport 8130 -j ACCEPT
  iptables -A INPUT -p tcp -m state --state NEW -m tcp -s 10.173.162.142 --dport 8130 -j DROP
  iptables -A INPUT -p tcp -m state --state NEW -m tcp -s 10.169.2.12 --dport 8130 -j DROP

  # 开放  8140 端口 (taskserver)
  iptables -A INPUT -p tcp -m state --state NEW -m tcp -s 10.0.0.0/8 --dport 8140 -j ACCEPT
  iptables -A INPUT -p tcp -m state --state NEW -m tcp -s 10.173.162.142 --dport 8140 -j DROP
  iptables -A INPUT -p tcp -m state --state NEW -m tcp -s 10.169.2.12 --dport 8140 -j DROP

  # 开放  8140 端口 (dangkrserver)
  iptables -A INPUT -p tcp -m state --state NEW -m tcp -s 10.0.0.0/8 --dport 8110 -j ACCEPT
  iptables -A INPUT -p tcp -m state --state NEW -m tcp -s 10.173.162.142 --dport 8110 -j DROP
  iptables -A INPUT -p tcp -m state --state NEW -m tcp -s 10.169.2.12 --dport 8110 -j DROP

  # 开放 zookeeper 端口 3762 2882 3883
  iptables -A INPUT -p tcp -m state --state NEW -m tcp -s 10.169.2.12 --dport 3762 -j DROP
  iptables -A INPUT -p tcp -m state --state NEW -m tcp -s 10.160.1.233 --dport 3762 -j DROP
  iptables -A INPUT -p tcp -m state --state NEW -m tcp -s 10.173.162.142 --dport 3762 -j DROP
  iptables -A INPUT -p tcp -m state --state NEW -m tcp -s 10.0.0.0/8 --dport 3762 -j ACCEPT

  iptables -A INPUT -p tcp -m state --state NEW -m tcp -s 10.0.0.0/8 --dport 2882 -j ACCEPT
  iptables -A INPUT -p tcp -m state --state NEW -m tcp -s 10.0.0.0/8 --dport 3883 -j ACCEPT

  iptables -A INPUT -j DROP
  echo -e "$GREEN INPUT rules created done. $NO_COLOR"
}

output_rules() {
  echo -en "Creating rules for allowed OUTPUT traffic: $RED\n"
  # Local traffic allowed accept al on lo interface
  iptables -A OUTPUT -o lo -j ACCEPT
  if ifconfig eth1 &> /dev/null;then
	iptables -A OUTPUT -o eth0 -j ACCEPT
  fi

  iptables -A OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
  iptables -A OUTPUT -p icmp -m icmp --icmp-type echo-request -m limit --limit 10/second -j ACCEPT
  iptables -A OUTPUT -p icmp -m icmp --icmp-type echo-reply -m limit --limit 10/second -j ACCEPT
  iptables -A OUTPUT -p icmp -m icmp --icmp-type time-exceeded -m limit --limit 10/second -j ACCEPT
  iptables -A OUTPUT -p icmp -m icmp --icmp-type destination-unreachable -m limit --limit 10/second -j ACCEPT
  iptables -A OUTPUT -p icmp -j DROP

  # allow DNS-NTP-FTP-HTTP-HTTPS-SMTP
  PORTS1="53 123 21 80 443 25"
  for port1 in $PORTS1;do iptables -A OUTPUT -p udp -m state --state NEW --dport $port1 -j ACCEPT;done
  
  # allow SSH
  PORTS2=""
  for port2 in $PORTS2;do iptables -A OUTPUT -p tcp -m state --state NEW --dport $port2 -j ACCEPT;done

  ###### Add the output rules here:
#  iptables -A OUTPUT -p tcp -m state --state NEW -d <destnation_address> --dport <destnation_port> -j ACCEPT
  ###### Add an end

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

echo "############################################"
echo $(basename $0)
printf "Version: %s\n" $version_num
echo "############################################"
backup_rules
clean_iptables
input_rules
#output_rules
echo "############################################"
echo "Done. "