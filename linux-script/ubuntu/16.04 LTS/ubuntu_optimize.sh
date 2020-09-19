#!/bin/bash
# 
# https://www.cyberciti.biz/tips/linux-security.html
# 
#set -x
echo "#--------------------------------------------------------------------"
echo "# Ubuntu 16.04 4.4.0-117-generic init script"
echo "# @author https://wangwei.one"
echo "# @date   20181108"
echo "#--------------------------------------------------------------------"

MY_NEW_USER='gxchainuser'
MY_DATA_DEV='vda1'
MY_SSH_PORT=41837
name=`hostname`
ETH1=""
if ifconfig eth1 &> /dev/null;then
   ETH1=$(ifconfig eth1 | grep inet | awk '{print $2}' | awk -F ":" '{print $2}')
fi
ETH0=$(ifconfig eth0 | grep inet | awk '{print $2}' | awk -F ":" '{print $2}')

# set random password
MATRIX="0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ \
abcdefghijklmnopqrstuvwxyz./*&^%$#@!()"
# May change 'LENGTH' for longer password, of course.
LENGTH="32"

  while [ "${n:=1}" -le "$LENGTH" ]; do
    PASS="$PASS${MATRIX:$(($RANDOM%${#MATRIX})):1}"
    let n+=1
  done

#echo "$PASS" # ==> Or, redirect to file, as desired.
#exit 0

hostname_check(){
HOSTNAME=$1
  while [ -z "$HOSTNAME" ];do
    printf "Please input %s: " "hostname"
    read HOSTNAME
  done
}

hostname_check

while [ "$HOSTNAME" != *-* ];do
  echo "Wrong name,example:xxx-xxx"; hostname_check
done

change_hostname(){
  # change hostname for server
  echo "Starting change hostname"
  hostname $HOSTNAME
  sed -i "s/^.*/$HOSTNAME/g" /etc/hostname
  sed -i "s/^${ETH0}.*/${ETH0} ${HOSTNAME} ${HOSTNAME}/g" /etc/hosts
  echo "Finished change hostname"
}

sshuser_tunning(){
  # https://www.digitalocean.com/community/tutorials/how-to-add-and-delete-users-on-ubuntu-16-04
  # backup file
  echo "Starting sshuser tunning"

  cp -p /etc/passwd /etc/passwd.bak
  cp -p /etc/shadow /etc/shadow.bak
  cp -p /etc/group /etc/group.bak

  # Create Home Directory + .ssh Directory
  if [ ! -d "/home/$MY_NEW_USER/.ssh" ]; then
    mkdir -p /home/$MY_NEW_USER/.ssh
  fi

  # Create Authorized Keys File
  if [ ! -f "/home/$MY_NEW_USER/.ssh/authorized_keys" ]; then
    touch "/home/$MY_NEW_USER/.ssh/authorized_keys"
  fi

  # Create User + Set Home Directory
  useradd -d /home/$MY_NEW_USER $MY_NEW_USER

  # Set Permissions
  chmod 755 /home/$MY_NEW_USER
  chmod 700 /home/$MY_NEW_USER/.ssh
  chmod 644 /home/$MY_NEW_USER/.ssh/authorized_keys
  chown -R $MY_NEW_USER:$MY_NEW_USER /home/$MY_NEW_USER

  # Create Group sshers
  groupadd -g 4999 sshers

  # Add User to sudo Group
  usermod -aG sudo,sshers $MY_NEW_USER

  # Set Password on User
  echo $MY_NEW_USER:$PASS | /usr/sbin/chpasswd

  # customizing bash prompt
  if [ ! -f "/home/$MY_NEW_USER/.bashrc" ]; then
    touch "/home/$MY_NEW_USER/.bashrc"
    cat /root/.bashrc > /home/$MY_NEW_USER/.bashrc
    chmod 644 /home/$MY_NEW_USER/.bashrc
    chown $MY_NEW_USER:$MY_NEW_USER /home/$MY_NEW_USER/.bashrc
  fi

  if [ ! -f "/home/$MY_NEW_USER/.profile" ]; then
    touch "/home/$MY_NEW_USER/.profile"
    cat /root/.profile > /home/$MY_NEW_USER/.profile
    chmod 644 /home/$MY_NEW_USER/.profile
    chown $MY_NEW_USER:$MY_NEW_USER /home/$MY_NEW_USER/.profile
  fi

  echo "Finished sshuser tunning"
}

sshd_config_tunning(){
  echo "Starting sshd_config_tunning"

  # sshd config
  # https://www.cyberciti.biz/tips/linux-unix-bsd-openssh-server-best-practices.html

  # backup file
  cp -p /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

  # disable root login
  sed -ri 's/PermitRootLogin\s+yes/PermitRootLogin\tno/g; s/ChallengeResponseAuthentication\s+yes/ChallengeResponseAuthentication\tno/g; s/UsePAM\s+yes/UsePAM\tno/g; ' /etc/ssh/sshd_config
  
  # Disable password based login
  # sed -ri 's/PasswordAuthentication\s+yes/PasswordAuthentication\tno/g;' /etc/ssh/sshd_config
  sed -ri 's/PubkeyAuthentication\s+no/PubkeyAuthentication\tyes/g;' /etc/ssh/sshd_config
  
  # Disable Empty Passwords
  sed -ri 's/PermitEmptyPasswords\s+yes/PermitEmptyPasswords\tno/g;' /etc/ssh/sshd_config

  # Limit Users’ ssh access
  if ! grep 'AllowGroups sshers' /etc/ssh/sshd_config >/dev/null;then echo "AllowGroups sshers" >> /etc/ssh/sshd_config;fi
  if ! grep 'DenyUsers root' /etc/ssh/sshd_config >/dev/null;then echo "DenyUsers root" >> /etc/ssh/sshd_config;fi
  
  # change ssh port from 22 to 41837
  sed -ri "s/Port 22/Port $MY_SSH_PORT/g" /etc/ssh/sshd_config

  # Configure idle log out timeout interval
  if ! grep 'ClientAliveInterval 300' /etc/ssh/sshd_config >/dev/null;then echo "ClientAliveInterval 300" >> /etc/ssh/sshd_config;fi
  if ! grep 'ClientAliveCountMax 0' /etc/ssh/sshd_config >/dev/null;then echo "ClientAliveCountMax 0" >> /etc/ssh/sshd_config;fi

  # Disable .rhosts files (verification)
  sed -ri 's/IgnoreRhosts\s+no/IgnoreRhosts\tyes/g;' /etc/ssh/sshd_config  
  
  # Disable host-based authentication (verification)
  sed -ri 's/HostbasedAuthentication\s+yes/HostbasedAuthentication\tno/g;' /etc/ssh/sshd_config 

  ## change ntp conf
  # sed -i s/server\ 0.*/'server 0.asia.pool.ntp.org'/ /etc/ntp.conf
  # sed -i s/server\ 1.*/'server 1.asia.pool.ntp.org'/ /etc/ntp.conf
  # sed -i s/server\ 2.*/'server 2.asia.pool.ntp.org'/ /etc/ntp.conf
  # sed -i "/.*127.127.1.0/s/^/#/" /etc/ntp.conf

  ## Logrotate
  #  sed -i 's/\#compress/compress/' /etc/logrotate.conf

  echo "Finished sshd_config_tunning"
}

sshd_pwd_auth_tunning(){
    sed -ri 's/#PasswordAuthentication\s+yes/PasswordAuthentication\tno/g;' /etc/ssh/sshd_config
    if ! grep 'AuthenticationMethods publickey' /etc/ssh/sshd_config >/dev/null;then echo "AuthenticationMethods publickey" >> /etc/ssh/sshd_config;fi
}

package_tunning(){
  echo "Starting package_tunning"

  # update & upgrade
  apt-get update && apt-get upgrade -y
  add-apt-repository ppa:ubuntu-toolchain-r/test
  
  # install some package
  apt-get install -y iptables iptables-persistent unzip ntp htop git-core software-properties-common libstdc++-7-dev
  # update & upgrade again
  apt-get update && apt-get upgrade -y
  # The following packages were automatically installed and are no longer required
  # apt autoremove linux-headers-4.4.0-87 linux-headers-4.4.0-87-generic linux-image-4.4.0-87-generic linux-image-extra-4.4.0-87-generic
  apt-get autoremove
  echo "Finished package_tunning"
  
}

base_system_tunning(){
  echo "Starting base_system_tunning"
  
  # set language US
  if ! grep 'LANGUAGE=en_US.UTF-8' /etc/profile >/dev/null; then
  echo 'export LANGUAGE=en_US.UTF-8
export LANG=en_US.UTF-8
export LC_ALL=en_US.UTF-8
  ' >> /etc/profile
  fi

  ## bash prompt for new user
  chsh -s /bin/bash $MY_NEW_USER

  # timezone set
  timedatectl set-timezone Asia/Shanghai

  # Add serial tty
  if ! grep 'ttyS0' /etc/securetty >/dev/null; then echo 'ttyS0' >> /etc/securetty; fi

  # Add useful settings to /etc/sysctl.conf
  # change hashsize
  cp /etc/rc.local /etc/rc.local.bak
  cp /etc/sysctl.conf /etc/sysctl.conf.bak

  modprobe ip_conntrack
  grep 'modprobe ip_conntrack' /etc/rc.local &> /dev/null
  if [ $? != 0 ] ; then
    sed -i '/exit\s0/d' /etc/rc.local
    echo -e 'modprobe ip_conntrack\nexit 0' >> /etc/rc.local
  fi

  grep '/sys/module/nf_conntrack/parameters/hashsize' /etc/rc.local &> /dev/null
  if [ $? != 0 ] ; then
    sed -i '/exit\s0/d' /etc/rc.local
    echo -e 'echo 64000 > /sys/module/nf_conntrack/parameters/hashsize\nexit 0' >> /etc/rc.local
  fi
  
  # https://wiki.ubuntu.com/ImprovedNetworking/KernelSecuritySettings
  grep 'kernel.panic' /etc/sysctl.conf &> /dev/null
  if [ $? != 0 ] ; then
    echo "# Reboot a minute after an Oops" >> /etc/sysctl.conf
    echo "kernel.panic = 60" >> /etc/sysctl.conf
  else
    sed -i s/"kernel.panic = [0-9]*"/"kernel.panic = 60"/ /etc/sysctl.conf
  fi

  grep 'kernel.exec-shield' /etc/sysctl.conf &> /dev/null
  if [ $? != 0 ] ; then
    echo "# Turn on execshield " >> /etc/sysctl.conf
    echo "kernel.exec-shield = 1" >> /etc/sysctl.conf
  else
    sed -i s/"kernel.exec-shield = [0-9]*"/"kernel.exec-shield = 1"/ /etc/sysctl.conf
  fi
  grep 'kernel.randomize_va_space' /etc/sysctl.conf &> /dev/null
  if [ $? != 0 ] ; then
    echo "kernel.randomize_va_space = 1" >> /etc/sysctl.conf
  else
    sed -i s/"kernel.randomize_va_space = [0-9]*"/"kernel.randomize_va_space = 1"/ /etc/sysctl.conf
  fi

  grep 'net.core.rmem_max' /etc/sysctl.conf &> /dev/null
  if [ $? != 0 ] ; then
    echo "# Increase Linux auto tuning TCP buffer limits min, default, and max number of bytes to use set max to at least 4MB, or higher if you use very high BDP paths " >> /etc/sysctl.conf
    echo "net.core.rmem_max = 8388608" >> /etc/sysctl.conf
  else
    sed -i s/"net.core.rmem_max = [0-9]*"/"net.core.rmem_max = 8388608"/ /etc/sysctl.conf
  fi
  grep 'net.core.wmem_max' /etc/sysctl.conf &> /dev/null
  if [ $? != 0 ] ; then
    echo "net.core.wmem_max = 8388608" >> /etc/sysctl.conf
  else
    sed -i s/"net.core.wmem_max = [0-9]*"/"net.core.wmem_max = 8388608"/ /etc/sysctl.conf
  fi

  grep 'net.core.netdev_max_backlog' /etc/sysctl.conf &> /dev/null
  if [ $? != 0 ] ; then
    echo "net.core.netdev_max_backlog = 32768" >> /etc/sysctl.conf
  else
    sed -i s/"net.core.netdev_max_backlog = [0-9]*"/"net.core.netdev_max_backlog = 32768"/ /etc/sysctl.conf
  fi

  grep 'net.core.somaxconn' /etc/sysctl.conf &> /dev/null
  if [ $? != 0 ] ; then
    echo "net.core.somaxconn = 32768" >> /etc/sysctl.conf
  else
    sed -i s/"net.core.somaxconn = [0-9]*"/"net.core.somaxconn = 32768"/ /etc/sysctl.conf
  fi

  # Tuen IPv4.
  grep 'net.ipv4.icmp_ratelimit' /etc/sysctl.conf &> /dev/null
  if [ $? != 0 ] ; then
    echo "# Default value is 100; we relax this to limit it to 5 per second." >> /etc/sysctl.conf
    echo "net.ipv4.icmp_ratelimit = 20" >> /etc/sysctl.conf
  else
    sed -i s/"net.ipv4.icmp_ratelimit = [0-9]*"/"net.ipv4.icmp_ratelimit = 20"/ /etc/sysctl.conf
  fi

  grep 'net.ipv4.icmp_ratemask' /etc/sysctl.conf &> /dev/null
  if [ $? != 0 ] ; then
    echo "# Default value is 6168; we set a few ICMP masks to be rate limited" >> /etc/sysctl.conf
    echo "net.ipv4.icmp_ratemask = 88089" >> /etc/sysctl.conf
  else
    sed -i s/"net.ipv4.icmp_ratemask = [0-9]*"/"net.ipv4.icmp_ratemask = 88089"/ /etc/sysctl.conf
  fi

  grep 'net.ipv4.icmp_echo_ignore_broadcasts' /etc/sysctl.conf &> /dev/null
  if [ $? != 0 ] ; then
    echo "# Ignore bad ICMP, Avoid a smurf attack" >> /etc/sysctl.conf
    echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.conf
  else
    sed -i s/"net.ipv4.icmp_echo_ignore_broadcasts = [0-9]*"/"net.ipv4.icmp_echo_ignore_broadcasts = 1"/ /etc/sysctl.conf
  fi

  grep 'net.ipv4.icmp_ignore_bogus_error_responses' /etc/sysctl.conf &> /dev/null
  if [ $? != 0 ] ; then
    echo "# Turn on protection for bad icmp error messages. " >> /etc/sysctl.conf
    echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> /etc/sysctl.conf
  else
    sed -i s/"net.ipv4.icmp_ignore_bogus_error_responses = [0-9]*"/"net.ipv4.icmp_ignore_bogus_error_responses = 1"/ /etc/sysctl.conf
  fi
  grep 'net.ipv4.conf.all.accept_redirects' /etc/sysctl.conf &> /dev/null
  if [ $? != 0 ] ; then
    echo "# Disable ICMP Redirect Acceptance, make sure no one can alter the routing tables" >> /etc/sysctl.conf
    echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
  else
    sed -i s/"net.ipv4.conf.all.accept_redirects = [0-9]*"/"net.ipv4.conf.all.accept_redirects = 0"/ /etc/sysctl.conf
  fi
  grep 'net.ipv4.conf.default.accept_redirects' /etc/sysctl.conf &> /dev/null
  if [ $? != 0 ] ; then
    echo "net.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.conf
  else
    sed -i s/"net.ipv4.conf.default.accept_redirects = [0-9]*"/"net.ipv4.conf.default.accept_redirects = 0"/ /etc/sysctl.conf
  fi
  grep 'net.ipv4.conf.all.secure_redirects' /etc/sysctl.conf &> /dev/null
  if [ $? != 0 ] ; then
    echo "net.ipv4.conf.all.secure_redirects = 0" >> /etc/sysctl.conf
  else
    sed -i s/"net.ipv4.conf.all.secure_redirects = [0-9]*"/"net.ipv4.conf.all.secure_redirects = 0"/ /etc/sysctl.conf
  fi
  grep 'net.ipv4.conf.default.secure_redirects' /etc/sysctl.conf &> /dev/null
  if [ $? != 0 ] ; then
    echo "net.ipv4.conf.default.secure_redirects = 0" >> /etc/sysctl.conf
  else
    sed -i s/"net.ipv4.conf.default.secure_redirects = [0-9]*"/"net.ipv4.conf.default.secure_redirects = 0"/ /etc/sysctl.conf
  fi

  grep 'net.ipv4.conf.all.accept_source_route' /etc/sysctl.conf &> /dev/null
  if [ $? != 0 ] ; then
    echo "# Generally bad, may give a way to route a packet through a firewall to an unreachable IP by specifying that IP in the route." >> /etc/sysctl.conf
    echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
  else
    sed -i s/"net.ipv4.conf.all.accept_source_route = [0-9]*"/"net.ipv4.conf.all.accept_source_route = 0"/ /etc/sysctl.conf
  fi
  grep 'net.ipv4.conf.default.accept_source_route' /etc/sysctl.conf &> /dev/null
  if [ $? != 0 ] ; then
    echo "net.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.conf
  else
    sed -i s/"net.ipv4.conf.default.accept_source_route = [0-9]*"/"net.ipv4.conf.default.accept_source_route = 0"/ /etc/sysctl.conf
  fi

  grep 'net.ipv4.conf.all.rp_filter' /etc/sysctl.conf &> /dev/null
  if [ $? != 0 ] ; then
    echo "# Enable IP spoofing protection, turn on source route verification" >> /etc/sysctl.conf
    echo "net.ipv4.conf.all.rp_filter = 1" >> /etc/sysctl.conf
  else
    sed -i s/"net.ipv4.conf.all.rp_filter = [0-9]*"/"net.ipv4.conf.all.rp_filter = 1"/ /etc/sysctl.conf
  fi
  grep 'net.ipv4.conf.default.rp_filter' /etc/sysctl.conf &> /dev/null
  if [ $? != 0 ] ; then
    echo "net.ipv4.conf.default.rp_filter = 1" >> /etc/sysctl.conf
  else
    sed -i s/"net.ipv4.conf.default.rp_filter = [0-9]*"/"net.ipv4.conf.default.rp_filter = 1"/ /etc/sysctl.conf
  fi

  grep 'net.ipv4.conf.all.log_martians' /etc/sysctl.conf &> /dev/null
  if [ $? != 0 ] ; then
    echo "# Turn on and log spoofed, source routed, and redirect packets" >> /etc/sysctl.conf
    echo "net.ipv4.conf.all.log_martians = 1" >> /etc/sysctl.conf
  else
    sed -i s/"net.ipv4.conf.all.log_martians = [0-9]*"/"net.ipv4.conf.all.log_martians = 1"/ /etc/sysctl.conf
  fi
  grep 'net.ipv4.conf.default.log_martians' /etc/sysctl.conf &> /dev/null
  if [ $? != 0 ] ; then
    echo "net.ipv4.conf.default.log_martians = 1" >> /etc/sysctl.conf
  else
    sed -i s/"net.ipv4.conf.default.log_martians = [0-9]*"/"net.ipv4.conf.default.log_martians = 1"/ /etc/sysctl.conf
  fi
  grep 'net.ipv4.conf.all.arp_announce' /etc/sysctl.conf &> /dev/null
  if [ $? != 0 ] ; then
    echo "# Reply to ARPs only from correct interface (required for DSR load-balancers)" >> /etc/sysctl.conf
    echo "net.ipv4.conf.all.arp_announce = 2" >> /etc/sysctl.conf
  else
    sed -i s/"net.ipv4.conf.all.arp_announce = [0-9]*"/"net.ipv4.conf.all.arp_announce = 2"/ /etc/sysctl.conf
  fi

  grep 'net.ipv4.conf.all.arp_ignore' /etc/sysctl.conf &> /dev/null
  if [ $? != 0 ] ; then
    echo "net.ipv4.conf.all.arp_ignore = 1" >> /etc/sysctl.conf
  else
    sed -i s/"net.ipv4.conf.all.arp_ignore = [0-9]*"/"net.ipv4.conf.all.arp_ignore = 1"/ /etc/sysctl.conf
  fi

  grep 'net.ipv4.ip_forward' /etc/sysctl.conf &> /dev/null
  if [ $? != 0 ] ; then
    echo "# Don't act as a router" >> /etc/sysctl.conf
    echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.conf
  else
    sed -i s/"net.ipv4.ip_forward = [0-9]*"/"net.ipv4.ip_forward = 0"/ /etc/sysctl.conf
  fi
  grep 'net.ipv4.conf.all.send_redirects' /etc/sysctl.conf &> /dev/null
  if [ $? != 0 ] ; then
    echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.conf
  else
    sed -i s/"net.ipv4.conf.all.send_redirects = [0-9]*"/"net.ipv4.conf.all.send_redirects = 0"/ /etc/sysctl.conf
  fi
  grep 'net.ipv4.conf.default.send_redirects' /etc/sysctl.conf &> /dev/null
  if [ $? != 0 ] ; then
    echo "net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.conf
  else
    sed -i s/"net.ipv4.conf.default.send_redirects = [0-9]*"/"net.ipv4.conf.default.send_redirects = 0"/ /etc/sysctl.conf
  fi
  
  grep 'net.ipv4.tcp_syncookies' /etc/sysctl.conf &> /dev/null
  if [ $? != 0 ] ; then
    echo "# Turn on syncookies for SYN flood attack protection" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf
  else
    sed -i s/"net.ipv4.tcp_syncookies = [0-9]*"/"net.ipv4.tcp_syncookies = 1"/ /etc/sysctl.conf
  fi

  grep 'net.ipv4.tcp_max_syn_backlog' /etc/sysctl.conf &> /dev/null
  if [ $? != 0 ] ; then
    echo "net.ipv4.tcp_max_syn_backlog = 65536" >> /etc/sysctl.conf
  else
    sed -i s/"net.ipv4.tcp_max_syn_backlog = [0-9]*"/"net.ipv4.tcp_max_syn_backlog = 65536"/ /etc/sysctl.conf
  fi

  grep 'net.ipv4.tcp_rfc1337' /etc/sysctl.conf &> /dev/null
  if [ $? != 0 ] ; then
    echo "# Implements RFC 1337 fix F1 to counteract hazards H1, H2, and H3. This accounts for all hazards discussed in RFC 1337." >> /etc/sysctl.conf
    echo "net.ipv4.tcp_rfc1337 = 1" >> /etc/sysctl.conf
  else
    sed -i s/"net.ipv4.tcp_rfc1337 = [0-9]*"/"net.ipv4.tcp_rfc1337 = 1"/ /etc/sysctl.conf
  fi

  grep 'net.ipv4.tcp_timestamps' /etc/sysctl.conf &> /dev/null
  if [ $? != 0 ] ; then
    echo "net.ipv4.tcp_timestamps = 0" >> /etc/sysctl.conf
  else
    sed -i s/"net.ipv4.tcp_timestamps = [0-9]*"/"net.ipv4.tcp_timestamps = 0"/ /etc/sysctl.conf
  fi

  grep 'net.ipv4.tcp_synack_retries' /etc/sysctl.conf &> /dev/null
  if [ $? != 0 ] ; then
    echo "net.ipv4.tcp_synack_retries = 2" >> /etc/sysctl.conf
  else
    sed -i s/"net.ipv4.tcp_synack_retries = [0-9]*"/"net.ipv4.tcp_synack_retries = 2"/ /etc/sysctl.conf
  fi

  grep 'net.ipv4.tcp_syn_retries' /etc/sysctl.conf &> /dev/null
  if [ $? != 0 ] ; then
    echo "net.ipv4.tcp_syn_retries = 2" >> /etc/sysctl.conf
  else
    sed -i s/"net.ipv4.tcp_syn_retries = [0-9]*"/"net.ipv4.tcp_syn_retries = 2"/ /etc/sysctl.conf
  fi

  grep 'net.ipv4.tcp_tw_recycle' /etc/sysctl.conf &> /dev/null
  if [ $? != 0 ] ; then
    echo "net.ipv4.tcp_tw_recycle = 0" >> /etc/sysctl.conf
  else
    sed -i s/"net.ipv4.tcp_tw_recycle = [0-9]*"/"net.ipv4.tcp_tw_recycle = 0"/ /etc/sysctl.conf
  fi

  grep 'net.ipv4.tcp_tw_reuse' /etc/sysctl.conf &> /dev/null
  if [ $? != 0 ] ; then
    echo "net.ipv4.tcp_tw_reuse = 1" >> /etc/sysctl.conf
  else
    sed -i s/"net.ipv4.tcp_tw_reuse = [0-9]*"/"net.ipv4.tcp_tw_reuse = 1"/ /etc/sysctl.conf
  fi

  # increase for more connection
  grep 'net.ipv4.tcp_keepalive_time' /etc/sysctl.conf &> /dev/null
  if [ $? != 0 ] ; then
    echo "net.ipv4.tcp_keepalive_time = 1200" >> /etc/sysctl.conf
  else
    sed -i s/"net.ipv4.tcp_keepalive_time = [0-9]*"/"net.ipv4.tcp_keepalive_time = 1200"/ /etc/sysctl.conf
  fi

  grep 'net.ipv4.tcp_keepalive_intvl' /etc/sysctl.conf &> /dev/null
  if [ $? != 0 ] ; then
    echo "net.ipv4.tcp_keepalive_intvl = 15" >> /etc/sysctl.conf
  else
    sed -i s/"net.ipv4.tcp_keepalive_intvl = [0-9]*"/"net.ipv4.tcp_keepalive_intvl = 15"/ /etc/sysctl.conf
  fi

  grep 'net.ipv4.tcp_keepalive_probes' /etc/sysctl.conf &> /dev/null
  if [ $? != 0 ] ; then
    echo "net.ipv4.tcp_keepalive_probes = 5" >> /etc/sysctl.conf
  else
    sed -i s/"net.ipv4.tcp_keepalive_probes = [0-9]*"/"net.ipv4.tcp_keepalive_probes = 5"/ /etc/sysctl.conf
  fi

  grep 'net.ipv4.tcp_fin_timeout' /etc/sysctl.conf &> /dev/null
  if [ $? != 0 ] ; then
    echo "net.ipv4.tcp_fin_timeout = 30" >> /etc/sysctl.conf
  else
    sed -i s/"net.ipv4.tcp_fin_timeout = [0-9]*"/"net.ipv4.tcp_fin_timeout = 30"/ /etc/sysctl.conf
  fi

  grep 'net.ipv4.tcp_rmem' /etc/sysctl.conf &> /dev/null
  if [ $? != 0 ] ; then
    echo "# Increase TCP max buffer size setable using setsockopt() " >> /etc/sysctl.conf
    echo "net.ipv4.tcp_rmem = 4096 87380 8388608" >> /etc/sysctl.conf
  else
    sed -i s/"net.ipv4.tcp_rmem = .*"/"net.ipv4.tcp_rmem = 4096 87380 8388608"/ /etc/sysctl.conf
  fi
  grep 'net.ipv4.tcp_wmem' /etc/sysctl.conf &> /dev/null
  if [ $? != 0 ] ; then
    echo "net.ipv4.tcp_wmem = 4096 87380 8388608 " >> /etc/sysctl.conf
  else
    sed -i s/"net.ipv4.tcp_wmem = .*"/"net.ipv4.tcp_wmem = 4096 87380 8388608 "/ /etc/sysctl.conf
  fi

  grep 'fs.file-max' /etc/sysctl.conf &> /dev/null
  if [ $? != 0 ] ; then
    echo "# Increase system file descriptor limit " >> /etc/sysctl.conf
    echo "fs.file-max = 1024000" >> /etc/sysctl.conf
  else
    sed -i s/"fs.file-max = [0-9]*"/"fs.file-max = 1024000"/ /etc/sysctl.conf
  fi
  grep 'kernel.pid_max' /etc/sysctl.conf &> /dev/null
  if [ $? != 0 ] ; then
    echo "# Allow for more PIDs (to reduce rollover problems); may break some programs 32768" >> /etc/sysctl.conf
    echo "kernel.pid_max = 65536" >> /etc/sysctl.conf
  else
    sed -i s/"kernel.pid_max = [0-9]*"/"kernel.pid_max = 65536"/ /etc/sysctl.conf
  fi
  grep 'net.ipv4.ip_local_port_range' /etc/sysctl.conf &> /dev/null
  if [ $? != 0 ] ; then
    echo "# Increase system IP port limits " >> /etc/sysctl.conf
    echo "net.ipv4.ip_local_port_range = 1024 65535" >> /etc/sysctl.conf
  else
    sed -i s/"net.ipv4.ip_local_port_range = .*"/"net.ipv4.ip_local_port_range = 1024 65535"/ /etc/sysctl.conf
  fi

  # Tuen IPv6.
  grep 'net.ipv6.conf.default.router_solicitations' /etc/sysctl.conf &> /dev/null
  if [ $? != 0 ] ; then
    echo "# Tuen IPv6. " >> /etc/sysctl.conf
    echo "net.ipv6.conf.default.router_solicitations = 0" >> /etc/sysctl.conf
  else
    sed -i s/"net.ipv6.conf.default.router_solicitations = [0-9]*"/"net.ipv6.conf.default.router_solicitations = 0"/ /etc/sysctl.conf
  fi
  grep 'net.ipv6.conf.default.accept_ra_rtr_pref' /etc/sysctl.conf &> /dev/null
  if [ $? != 0 ] ; then
    echo "net.ipv6.conf.default.accept_ra_rtr_pref = 0" >> /etc/sysctl.conf
  else
    sed -i s/"net.ipv6.conf.default.accept_ra_rtr_pref = [0-9]*"/"net.ipv6.conf.default.accept_ra_rtr_pref = 0"/ /etc/sysctl.conf
  fi
  grep 'net.ipv6.conf.default.accept_ra_pinfo' /etc/sysctl.conf &> /dev/null
  if [ $? != 0 ] ; then
    echo "net.ipv6.conf.default.accept_ra_pinfo = 0" >> /etc/sysctl.conf
  else
    sed -i s/"net.ipv6.conf.default.accept_ra_pinfo = [0-9]*"/"net.ipv6.conf.default.accept_ra_pinfo = 0"/ /etc/sysctl.conf
  fi
  grep 'net.ipv6.conf.default.accept_ra_defrtr' /etc/sysctl.conf &> /dev/null
  if [ $? != 0 ] ; then
    echo "net.ipv6.conf.default.accept_ra_defrtr = 0" >> /etc/sysctl.conf
  else
    sed -i s/"net.ipv6.conf.default.accept_ra_defrtr = [0-9]*"/"net.ipv6.conf.default.accept_ra_defrtr = 0"/ /etc/sysctl.conf
  fi
  grep 'net.ipv6.conf.default.autoconf' /etc/sysctl.conf &> /dev/null
  if [ $? != 0 ] ; then
    echo "net.ipv6.conf.default.autoconf = 0" >> /etc/sysctl.conf
  else
    sed -i s/"net.ipv6.conf.default.autoconf = [0-9]*"/"net.ipv6.conf.default.autoconf = 0"/ /etc/sysctl.conf
  fi
  grep 'net.ipv6.conf.default.dad_transmits' /etc/sysctl.conf &> /dev/null
  if [ $? != 0 ] ; then
    echo "net.ipv6.conf.default.dad_transmits = 0" >> /etc/sysctl.conf
  else
    sed -i s/"net.ipv6.conf.default.dad_transmits = [0-9]*"/"net.ipv6.conf.default.dad_transmits = 0"/ /etc/sysctl.conf
  fi
  grep 'net.ipv6.conf.default.max_addresses' /etc/sysctl.conf &> /dev/null
  if [ $? != 0 ] ; then
    echo "net.ipv6.conf.default.max_addresses = 1" >> /etc/sysctl.conf
  else
    sed -i s/"net.ipv6.conf.default.max_addresses = [0-9]*"/"net.ipv6.conf.default.max_addresses = 1"/ /etc/sysctl.conf
  fi

  grep 'net.netfilter.nf_conntrack_tcp_timeout_time_wait' /etc/sysctl.conf &> /dev/null
  if [ $? != 0 ] ; then
    echo "net.netfilter.nf_conntrack_tcp_timeout_time_wait = 30" >> /etc/sysctl.conf
  else
    sed -i s/"net.netfilter.nf_conntrack_tcp_timeout_time_wait = [0-9]*"/"net.netfilter.nf_conntrack_tcp_timeout_time_wait = 30"/ /etc/sysctl.conf
  fi

  grep 'vm.swappiness' /etc/sysctl.conf &> /dev/null
  if [ $? != 0 ] ; then
    echo "vm.swappiness = 0" >> /etc/sysctl.conf
  else
    sed -i s/"vm.swappiness = [0-9]*"/"vm.swappiness = 0"/ /etc/sysctl.conf
  fi
  
  grep 'net.nf_conntrack_max' /etc/sysctl.conf &> /dev/null
  if [ $? != 0 ] ; then
    echo "net.nf_conntrack_max = 655350" >> /etc/sysctl.conf
  else
    sed -i s/"net.nf_conntrack_max = [0-9]*"/"net.nf_conntrack_max = 655350"/ /etc/sysctl.conf
  fi

#    grep 'perf_event_paranoid' /etc/sysctl.conf &> /dev/null
#    if [ $? != 0 ] ; then
#            echo "#vulnerability from 2.6.37 till 3.8.8" >> /etc/sysctl.conf
#            echo "perf_event_paranoid = 2" >> /etc/sysctl.conf
#    else
#            sed -i s/"perf_event_paranoid = [0-9]*"/"perf_event_paranoid = 2"/ /etc/sysctl.conf
#    fi

  sysctl -p

  echo "Finished base_system_tunning"
}

disk_dev_tunning(){
  echo "Starting disk_dev_tunning"

  # install lvm
  apt-get install -y lvm2

  # change lvm config
  cp /etc/lvm/lvm.conf /etc/lvm/lvm.conf.bak
  sed -i 's/umask = 077/umask = 022/g' /etc/lvm/lvm.conf

  # enable service 
  systemctl enable lvm2-lvmetad.service
  systemctl enable lvm2-lvmetad.socket
  systemctl start lvm2-lvmetad.service
  systemctl start lvm2-lvmetad.socket

  # create lvm first
  ls /dev/$MY_DATA_DEV >/dev/null 2>&1;
  if [ $? = 0 ]; then
    /sbin/pvcreate /dev/$MY_DATA_DEV
    /sbin/vgcreate domuvg /dev/$MY_DATA_DEV
    /sbin/lvcreate -L 1G -n swap domuvg
    /sbin/mkswap /dev/domuvg/swap
    /sbin/swapon /dev/domuvg/swap
    cp /etc/fstab /etc/fstab.bak
    echo "/dev/domuvg/swap        swap                    swap    defaults        0 0" >> /etc/fstab
    # Adjusting the Swappiness Property
    sed -ri 's/vm.swappiness\s+=\s+0/vm.swappiness=10/g' /etc/sysctl.conf
    # Adjusting the Cache Pressure Setting
    if ! grep 'vm.vfs_cache_pressure' /etc/sysctl.conf >/dev/null;then echo "vm.vfs_cache_pressure=50" >> /etc/sysctl.conf;fi

    # create mydata
    mkdir -p /mydata
    chmod 755 /mydata
    chown -R $MY_NEW_USER:$MY_NEW_USER /mydata

    /sbin/lvcreate -l +100%FREE -n alidata domuvg
    /sbin/mkfs.ext4 /dev/domuvg/alidata
    /bin/mount /dev/domuvg/alidata /mydata
    echo "/dev/domuvg/alidata         /mydata                    ext4    defaults        0 0" >> /etc/fstab
  fi

  echo "Finished disk_dev_tunning"
}

output_passwd(){
  echo "output system user password"
  PASS_FILE=/tmp/pass_temp
  HOSTNAME=$(hostname)
  echo "----SYSTEM INFORMATION---- " > $PASS_FILE
  if [ ! "$ETH1" = "" ];then
    echo "    eth1 is $ETH1" >> $PASS_FILE
  fi
  echo "    eth0 is $ETH0
      hostname is $HOSTNAME
      username is $MY_NEW_USER
      port is $MY_SSH_PORT
      password is $PASS
  -----------END-----------" >> $PASS_FILE
  cat $PASS_FILE
  rm -rf $PASS_FILE
  exit 0
  echo "Finished output passowrd"
}

/usr/bin/id $MY_NEW_USER >/dev/null 2>&1;

if [ $? = 0 ]; then
    echo "Account $MY_NEW_USER has already exists, Don't run the scripts twice.";
else
    change_hostname
    sshuser_tunning
    sshd_config_tunning   
    package_tunning
    base_system_tunning
    disk_dev_tunning
    output_passwd
    service sshd restart
    echo "Please send the output information to the administrator to update KeePass"
fi
