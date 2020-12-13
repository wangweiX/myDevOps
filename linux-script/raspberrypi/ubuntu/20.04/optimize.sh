#!/bin/bash
# 
# https://www.cyberciti.biz/tips/linux-security.html
# 
#set -x
echo "#--------------------------------------------------------------------"
echo "# Ubuntu 20.04 arm64 Optimize Script"
echo "# @author https://wangwei.one"
echo "# @date   20200718"
echo "#--------------------------------------------------------------------"

MY_NEW_USER='wangwei'
MY_SSH_PORT=41837
EXFAT_DISK='/dev/sda'
MY_PROXY='192.168.0.100:6152'
SYSCTL_CONFIG="$PWD/sysctl.conf"
NEW_USER_HOME=/home/${MY_NEW_USER}
ZSH_HOME=${NEW_USER_HOME}/.oh-my-zsh
STATIC_IP='192.168.0.105/24'
GATEWAY4='192.168.0.1'
DNS_SERVER='192.168.0.1'

# check user permission
if [[ `whoami` != root ]]; then
    echo "Please execute the script with root privileges ! "
    exit 1
fi

ETH1=""
# https://linuxize.com/post/linux-ip-command/
if ip addr show eth1 &> /dev/null;then
   ETH1=$(ip addr show eth1 | grep "inet\b" | awk '{print $2}' | cut -d/ -f1)
fi
ETH0=$(ip addr show eth0 | grep "inet\b" | awk '{print $2}' | cut -d/ -f1)

# set random password
MATRIX="0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz./*&^%$#@!()"
# May change 'LENGTH' for longer password, of course.
LENGTH="64"
while [ "${n:=1}" -le "$LENGTH" ]; do
  PASS="$PASS${MATRIX:$(($RANDOM%${#MATRIX})):1}"
  let n+=1
done
#echo "$PASS" # ==> Or, redirect to file, as desired.
#exit 0

static_ip(){
  echo "Start to config static ip ... "
  if [ ! -f "/etc/cloud/cloud.cfg.d/99-disable-network-config.cfg" ]; then
    touch "/etc/cloud/cloud.cfg.d/99-disable-network-config.cfg"
    echo "network: {config: disabled}" > /etc/cloud/cloud.cfg.d/99-disable-network-config.cfg
  fi

  cp /etc/netplan/50-cloud-init.yaml /etc/netplan/50-cloud-init.yaml.bak

  echo "network:
  version: 2
  renderer: networkd
  ethernets:
    eth0:
      dhcp4: no
      addresses:
        - ${STATIC_IP}
      gateway4: ${GATEWAY4}
      nameservers:
        addresses: [${DNS_SERVER}]" > /etc/netplan/50-cloud-init.yaml

  netplan apply

  echo "Static ip config is complate ! "
}

set_proxy(){
  echo "Start to set proxy..."
  export https_proxy=http://${MY_PROXY};
  export http_proxy=http://${MY_PROXY};
  export all_proxy=socks5://${MY_PROXY};
  echo "Proxy setting completed!"
}

hostname_check(){
HOSTNAME=$1
  while [ -z "$HOSTNAME" ];do
    printf "Please input %s: " "hostname"
    read HOSTNAME
  done
}

change_hostname(){
  echo "Start to change hostname..."
  hostname_check
  
  hostname_pattern='wangwei-rpi4-+([[:digit:]])'
  while [[ $HOSTNAME != $hostname_pattern ]];do
    echo "Wrong name,example:wangwei-rpi4-xxx"; hostname_check
  done
  hostnamectl set-hostname $HOSTNAME
  sed -i "s/^.*/$HOSTNAME/g" /etc/hostname
  sed -i "s/^${ETH0}.*/${ETH0} ${HOSTNAME}/g" /etc/hosts
  echo "Hostname change complated!"
}

package_tuning(){
  echo "Start to tuning package..."
  # set language US
  if ! grep 'LANGUAGE=en_US.UTF-8' /etc/profile >/dev/null; then
  echo 'export LANGUAGE=en_US.UTF-8
export LC_ALL=en_US.UTF-8
export LC_CTYPE=UTF-8
export LANG=en_US.UTF-8
  ' >> /etc/profile
  fi

  source /etc/profile

  # upgrade & update
  apt upgrade -y && apt update -y

  # install some package
  apt install -y ufw unzip ntp htop git-core zsh wireless-tools exfat-fuse exfat-utils net-tools lvm2
  # update & upgrade again
  apt upgrade -y && apt update -y
  # The following packages were automatically installed and are no longer required
  apt-get autoremove
  echo "Package tuning completed! "
}

sshuser_tuning(){
  echo "Start to tuning sshuser ..."

  /usr/bin/id $MY_NEW_USER >/dev/null 2>&1;
  if [ $? = 0 ]; then
    echo "Account $MY_NEW_USER has already exists, Don't run the scripts twice.";
  fi

  # https://www.digitalocean.com/community/tutorials/how-to-add-and-delete-users-on-ubuntu-16-04
  

  # backup file
  cp -p /etc/passwd /etc/passwd.bak
  cp -p /etc/shadow /etc/shadow.bak
  cp -p /etc/group /etc/group.bak

  # Create User + Home Directory
  useradd -d ${NEW_USER_HOME} ${MY_NEW_USER}

  # Create Group sshers
  groupadd -g 4999 sshers

  # Add User to sudo Group
  usermod -aG sudo,sshers ${MY_NEW_USER}

  # Set Password on User
  echo ${MY_NEW_USER}:${PASS} | /usr/sbin/chpasswd

  # Create .ssh Directory
  if [ ! -d "${NEW_USER_HOME}/.ssh" ]; then
    mkdir -p ${NEW_USER_HOME}/.ssh
  fi

  # Create Authorized Keys File
  if [ ! -f "${NEW_USER_HOME}/.ssh/authorized_keys" ]; then
    touch "${NEW_USER_HOME}/.ssh/authorized_keys"
  fi

  # customizing bash prompt
  if [ ! -f "${NEW_USER_HOME}/.bashrc" ]; then
    touch "${NEW_USER_HOME}/.bashrc"
    cat /home/ubuntu/.bashrc > ${NEW_USER_HOME}/.bashrc
    chmod 644 ${NEW_USER_HOME}/.bashrc
  fi

  if [ ! -f "${NEW_USER_HOME}/.bash_logout" ]; then
    touch "${NEW_USER_HOME}/.bash_logout"
    cat /home/ubuntu/.bash_logout > ${NEW_USER_HOME}/.bash_logout
    chmod 644 ${NEW_USER_HOME}/.bash_logout
  fi

  if [ ! -f "${NEW_USER_HOME}/.profile" ]; then
    touch "${NEW_USER_HOME}/.profile"
    cat /home/ubuntu/.profile > ${NEW_USER_HOME}/.profile
    chmod 644 ${NEW_USER_HOME}/.profile
  fi

  # set language
  if ! grep 'LANGUAGE=en_US.UTF-8' ${NEW_USER_HOME}/.profile >/dev/null; then
  echo 'export LANGUAGE=en_US.UTF-8
export LC_ALL=en_US.UTF-8
export LC_CTYPE=UTF-8
export LANG=en_US.UTF-8
  ' >> ${NEW_USER_HOME}/.profile
  fi

  # install oh-my-zsh
  git config --global http.proxy ${MY_PROXY}
  git config --global https.proxy ${MY_PROXY}
  git clone https://github.com/ohmyzsh/ohmyzsh.git ${ZSH_HOME}
  cp ${ZSH_HOME}/templates/zshrc.zsh-template ${NEW_USER_HOME}/.zshrc

  # add .profile >> .zshrc
  if ! grep 'source ~/.profile' ${NEW_USER_HOME}/.zshrc >/dev/null; then
   echo 'source ~/.profile' >> ${NEW_USER_HOME}/.zshrc
  fi

  # set motd message
  if ! grep 'run-parts /etc/update-motd.d/' ${NEW_USER_HOME}/.profile >/dev/null; then
    echo 'run-parts /etc/update-motd.d/' >> ${NEW_USER_HOME}/.profile
  fi
  
  # custom prompt
  echo "PROMPT=\"%{\$fg[green]%}%n@%{\$fg[green]%}%m%{\$reset_color%} \${PROMPT}\"" >> ${NEW_USER_HOME}/.zshrc

  # set ZSH as the default login shell
  usermod -s $(which zsh) ${MY_NEW_USER}
  
  # Set Permissions
  chmod 755 ${NEW_USER_HOME}
  chmod 700 ${NEW_USER_HOME}/.ssh
  chmod 644 ${NEW_USER_HOME}/.ssh/authorized_keys
  chown -R ${MY_NEW_USER}:${MY_NEW_USER} ${NEW_USER_HOME}
  
  echo "Sshuser tuning is completed ! "
}

sshd_config_tuning(){
  echo "Start to tuning sshd config ... "

  # sshd config
  # https://www.cyberciti.biz/tips/linux-unix-bsd-openssh-server-best-practices.html

  # backup file
  cp -p /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

  # Disable ChallengeResponseAuthentication
  sed -ri 's/^#?ChallengeResponseAuthentication\s+(yes|no)$/ChallengeResponseAuthentication no/g;' /etc/ssh/sshd_config

  # Disable UsePAM
  sed -ri 's/^#?UsePAM\s+(yes|no)$/UsePAM no/g;' /etc/ssh/sshd_config

  # Disable Empty Passwords
  sed -ri 's/^#?PermitEmptyPasswords\s+(yes|no)$/PermitEmptyPasswords no/g;' /etc/ssh/sshd_config

  # Disable .rhosts files (verification)
  sed -ri 's/^#?IgnoreRhosts\s+(yes|no)$/IgnoreRhosts no/g;' /etc/ssh/sshd_config

  # Disable host-based authentication (verification)
  sed -ri 's/^#?HostbasedAuthentication\s+(yes|no)$/HostbasedAuthentication no/g;' /etc/ssh/sshd_config

  # Disable root login
  sed -ri 's/^#?PermitRootLogin\s+[a-zA-Z-]+$/PermitRootLogin no/g;' /etc/ssh/sshd_config

  # Disable password login and Enable Pubkey login
  sed -ri 's/^#?PubkeyAuthentication\s+(yes|no)$/PubkeyAuthentication yes/g;' /etc/ssh/sshd_config
  #sed -ri 's/^#?PasswordAuthentication\s+(yes|no)$/PasswordAuthentication no/g;' /etc/ssh/sshd_config

  # Limit Users ssh access
  if ! grep 'AllowGroups sshers' /etc/ssh/sshd_config >/dev/null; then 
    echo "AllowGroups sshers" >> /etc/ssh/sshd_config
  fi
  if ! grep 'DenyUsers root' /etc/ssh/sshd_config >/dev/null; then 
    echo "DenyUsers root" >> /etc/ssh/sshd_config
  fi

  # Configure idle log out timeout interval
  sed -ri 's/^#?ClientAliveInterval\s+[0-9]+$/ClientAliveInterval 300/g;' /etc/ssh/sshd_config
  if ! grep 'ClientAliveInterval 300' /etc/ssh/sshd_config >/dev/null; then 
    echo "ClientAliveInterval 300" >> /etc/ssh/sshd_config
  fi
  sed -ri 's/^#?ClientAliveCountMax\s+[0-9]+$/ClientAliveCountMax 0/g;' /etc/ssh/sshd_config
  if ! grep 'ClientAliveCountMax 0' /etc/ssh/sshd_config >/dev/null; then 
    echo "ClientAliveCountMax 0" >> /etc/ssh/sshd_config
  fi

  # Change ssh port from 22 to custom port
  sed -ri "s/^#?Port\s+[0-9]+$/Port ${MY_SSH_PORT}/g;" /etc/ssh/sshd_config

  ## Logrotate
  #  sed -i 's/\#compress/compress/' /etc/logrotate.conf
  
  service sshd restart
  echo "Sshd config tuning completed ! "
}

kernel_tuning(){
  echo "Starting tuning system kernel ... "
  
  # timezone set
  timedatectl set-timezone Asia/Shanghai

  if [ ! -f "$SYSCTL_CONFIG" ]; then
    print "$SYSCTL_CONFIG don't exist ! "
    exit 1
  fi
  # sysctl.conf optimization
  cp /etc/sysctl.conf /etc/sysctl.conf.bak
  cat $SYSCTL_CONFIG > /etc/sysctl.conf
  sysctl -p
  
  # limits.conf optimization
  echo "System kernel tuning completed ! "
}

disk_dev_tuning(){
  echo "Start to tuning disk ... "

  # https://linux.cn/article-3218-1.html
  # fdisk -l
  # mkfs.ext3 /dev/sdb1

  # change lvm config
  cp /etc/lvm/lvm.conf /etc/lvm/lvm.conf.bak
  sed -i 's/umask = 077/umask = 022/g' /etc/lvm/lvm.conf
  
  # /dev/sda
  # create lvm first
  ls ${EXFAT_DISK} >/dev/null 2>&1;
  if [ $? = 0 ]; then
    # 创建物理卷 | 删除物理卷 pvremove
    pvcreate ${EXFAT_DISK}
    # 创建卷组 domuvg | 删除卷组 vgremove
    vgcreate domuvg ${EXFAT_DISK}
    # 创建1g大小的swap逻辑卷 | 删除逻辑卷 lvremove
    lvcreate -L 1G -n swap domuvg
    mkswap /dev/domuvg/swap
    swapon /dev/domuvg/swap

    # Adjusting the Swappiness Property
    # sed -ri 's/vm.swappiness\s+=\s+0/vm.swappiness=10/g' /etc/sysctl.conf
    # Adjusting the Cache Pressure Setting
    if ! grep 'vm.vfs_cache_pressure' /etc/sysctl.conf >/dev/null; then 
      echo "vm.vfs_cache_pressure=50" >> /etc/sysctl.conf
    fi
    
    # 剩余的全部用来创建mydata逻辑卷
    lvcreate -l +100%FREE -n mydata domuvg
    # 格式化逻辑卷
    mkfs.exfat /dev/domuvg/mydata

    # 创建目录 /mydata 并挂在逻辑卷
    mkdir -p /mydata
    mount /dev/domuvg/mydata /mydata
    
    chmod 755 /mydata
    chown -R ${MY_NEW_USER}:${MY_NEW_USER} /mydata

    cp /etc/fstab /etc/fstab.bak
    echo "/dev/domuvg/swap          swap                    swap      defaults        0 0" >> /etc/fstab
    echo "/dev/domuvg/mydata        /mydata                 exfat     defaults        0 0" >> /etc/fstab
  fi
  echo "Disk tuning is completed ! "
}

output_passwd(){
  PASS_FILE=/tmp/pass_temp
  HOSTNAME=$(hostname)
  echo "----SYSTEM INFORMATION---- " > $PASS_FILE
  if [ ! "$ETH1" = "" ];then
    echo "     eth1 is $ETH1" >> $PASS_FILE
  fi
  echo "     eth0 is $ETH0
      hostname is $HOSTNAME
      username is $MY_NEW_USER
      port is $MY_SSH_PORT
      password is $PASS
  -----------END-----------" >> $PASS_FILE
  cat $PASS_FILE
  rm -rf $PASS_FILE
  echo "Please send the output information to the administrator to update KeePass"
}

remove_ubuntu_user(){
  sudo deluser --remove-home ubuntu
  /usr/bin/id ubuntu >/dev/null 2>&1;
  if [ $? = 0 ]; then
    echo "ubuntu account removed ! "
  fi
}

case $1 in
    ip)
      static_ip
      ;;
    proxy)
      set_proxy
      ;;
    hostname)
      change_hostname
      ;;
    pkg)
      package_tuning
      ;;
    sshuser)
      sshuser_tuning
      output_passwd
      ;;
    sshd)
      sshd_config_tuning
      ;;
    kernel)
      kernel_tuning
      ;;  
    disk)
      disk_dev_tuning
      ;;
    *)
      echo "illegal command: %s\n" "$1" >&2
	  exit 1
	  ;;
esac
exit 0