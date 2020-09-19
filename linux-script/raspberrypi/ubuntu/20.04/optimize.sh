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
MY_PROXY='http://192.168.0.100:6152'
SYSCTL_CONFIG="/root/sysctl.conf"
NEW_USER_HOME=/home/${MY_NEW_USER}
ZSH_HOME=${NEW_USER_HOME}/.oh-my-zsh

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

export http_proxy=${MY_PROXY}
export https_proxy=${MY_PROXY}

proxy_tunning(){
  echo "Starting proxy_tunning"
  echo "http_proxy=${MY_PROXY}" >> /etc/environment
  echo "https_proxy=${MY_PROXY}" >> /etc/environment
  echo "http_proxy=${MY_PROXY}" >> /etc/wgetrc
  echo "https_proxy=${MY_PROXY}" >> /etc/wgetrc
  echo "Finished proxy_tunning"
}

hostname_check(){
HOSTNAME=$1
  while [ -z "$HOSTNAME" ];do
    printf "Please input %s: " "hostname"
    read HOSTNAME
  done
}

change_hostname(){
  # change hostname for server
  echo "Starting change hostname"
  hostname_check
  
  hostname_pattern='wangwei-pi4-+([[:digit:]])'
  while [[ $HOSTNAME != $hostname_pattern ]];do
    echo "Wrong name,example:wangwei-pi4-xxx"; hostname_check
  done
  
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
  if [ ! -d "${NEW_USER_HOME}/.ssh" ]; then
    mkdir -p ${NEW_USER_HOME}/.ssh
  fi

  # Create Authorized Keys File
  if [ ! -f "${NEW_USER_HOME}/.ssh/authorized_keys" ]; then
    touch "${NEW_USER_HOME}/.ssh/authorized_keys"
  fi

  # Create User + Set Home Directory
  useradd -d ${NEW_USER_HOME} ${MY_NEW_USER}

  # Create Group sshers
  groupadd -g 4999 sshers

  # Add User to sudo Group
  usermod -aG sudo,sshers ${MY_NEW_USER}

  # Set Password on User
  echo ${MY_NEW_USER}:${PASS} | /usr/sbin/chpasswd

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

  # set motd message
  if ! grep 'run-parts /etc/update-motd.d/' ${NEW_USER_HOME}/.profile >/dev/null; then
    echo 'run-parts /etc/update-motd.d/' >> ${NEW_USER_HOME}/.profile
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

  # custom prompt
  echo "PROMPT=\"%{\$fg[green]%}%n@%{\$fg[green]%}%m%{\$reset_color%} \${PROMPT}\"" >> ${NEW_USER_HOME}/.zshrc

  # set ZSH as the default login shell
  usermod -s $(which zsh) ${MY_NEW_USER}
  
  # Set Permissions
  chmod 755 ${NEW_USER_HOME}
  chmod 700 ${NEW_USER_HOME}/.ssh
  chmod 644 ${NEW_USER_HOME}/.ssh/authorized_keys
  chown -R ${MY_NEW_USER}:${MY_NEW_USER} ${NEW_USER_HOME}
  
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
  sed -ri "s/#Port 22/Port ${MY_SSH_PORT}/g" /etc/ssh/sshd_config

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
  
  service sshd restart
  echo "Finished sshd_config_tunning"
}

sshd_pwd_auth_tunning(){
    sed -ri 's/#PasswordAuthentication\s+yes/PasswordAuthentication\tno/g;' /etc/ssh/sshd_config
    if ! grep 'AuthenticationMethods publickey' /etc/ssh/sshd_config >/dev/null;then echo "AuthenticationMethods publickey" >> /etc/ssh/sshd_config;fi
}

package_tunning(){
  echo "Starting package_tunning"
  # set language US
  if ! grep 'LANGUAGE=en_US.UTF-8' /etc/profile >/dev/null; then
  echo 'export LANGUAGE=en_US.UTF-8
export LC_ALL=en_US.UTF-8
export LC_CTYPE=UTF-8
export LANG=en_US.UTF-8
  ' >> /etc/profile
  fi

  source /etc/profile

  # update & upgrade
  apt-get update && apt-get upgrade -y
  
  # install some package
  apt-get install -y iptables iptables-persistent unzip ntp htop git-core zsh wireless-tools exfat-fuse exfat-utils 
  # update & upgrade again
  apt-get update && apt-get upgrade -y
  # The following packages were automatically installed and are no longer required
  apt-get autoremove
  echo "Finished package_tunning"
}

base_system_tunning(){
  echo "Starting base_system_tunning"
  
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
  echo "Finished base_system_tunning"
}

disk_dev_tunning(){
  echo "Starting disk_dev_tunning"

  # change lvm config
  cp /etc/lvm/lvm.conf /etc/lvm/lvm.conf.bak
  sed -i 's/umask = 077/umask = 022/g' /etc/lvm/lvm.conf
  
  # /dev/sda
  # create lvm first
  ls ${EXFAT_DISK} >/dev/null 2>&1;
  if [ $? = 0 ]; then
    /sbin/pvcreate ${EXFAT_DISK}
    /sbin/vgcreate domuvg ${EXFAT_DISK}
    /sbin/lvcreate -L 1G -n swap domuvg
    /sbin/mkswap /dev/domuvg/swap
    /sbin/swapon /dev/domuvg/swap
    # Adjusting the Swappiness Property
    # sed -ri 's/vm.swappiness\s+=\s+0/vm.swappiness=10/g' /etc/sysctl.conf
    # Adjusting the Cache Pressure Setting
    if ! grep 'vm.vfs_cache_pressure' /etc/sysctl.conf >/dev/null;then echo "vm.vfs_cache_pressure=50" >> /etc/sysctl.conf;fi

    # create mydata
    mkdir -p /mydata
    
    /sbin/lvcreate -l +100%FREE -n mydata domuvg
    /sbin/mkfs.exfat /dev/domuvg/mydata
    /bin/mount /dev/domuvg/mydata /mydata
    
    chmod 755 /mydata
    chown -R ${MY_NEW_USER}:${MY_NEW_USER} /mydata

    cp /etc/fstab /etc/fstab.bak
    echo "/dev/domuvg/swap          swap                    swap      defaults        0 0" >> /etc/fstab
    echo "/dev/domuvg/mydata        /mydata                 exfat     defaults        0 0" >> /etc/fstab
  fi
  echo "Finished disk_dev_tunning"
}

output_passwd(){
  echo "output system user password"
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
  exit 0
  echo "Finished output passowrd"
}

remove_ubuntu_user(){
  sudo deluser --remove-home ubuntu
  /usr/bin/id ubuntu >/dev/null 2>&1;
  if [ $? = 0 ]; then
    echo "ubuntu account removed ! "
  fi
}

/usr/bin/id $MY_NEW_USER >/dev/null 2>&1;

if [ $? = 0 ]; then
    echo "Account $MY_NEW_USER has already exists, Don't run the scripts twice.";
else
    package_tunning
    # proxy_tunning
    change_hostname
    sshuser_tunning
    sshd_config_tunning  
    # sshd_pwd_auth_tunning
    base_system_tunning
    # disk_dev_tunning
    output_passwd
    # remove_ubuntu_user
    echo "Please send the output information to the administrator to update KeePass"
fi
