# 服务器优化配置

## 背景

通常来讲，我们在买完云服务器之后，需要修改一些服务器的默认配置。例如，修改hostname、新增普通用户、配置ssh登录权限、更新安装包、磁盘挂载、swap分区配置、防火墙设置、内核安全设置等等一系列措施。这些操作费时费力，还容易出错，弄不好一天就过去了，再搞不好，两天就过去了。

通过此脚本，则可以分分钟准确地完成以上一系列配置。

## 适用

- 适用于 **阿里云** **新购**的 **Ubuntu 16.04 LTS** 服务器
- 版本：`Ubuntu 16.04 4.4.0-117-generic`
- 其他linux版本的请自行修改，大同小异，只是一些命令有些许区别

## 功能

该脚本对**新服务器**的处理，主要如下：

| 项目     | 子项目                               | 说明                                                         |
| -------- | ------------------------------------ | ------------------------------------------------------------ |
| 基础设置 | 修改主机名                           | 修改默认的hostname                                           |
|          | 系统编码                             | 添加 LANGUAGE、LANG、LC_ALL = en_US.UTF-8                    |
|          | 时区设置                             | 设置为`Asia/Shanghai`                                        |
| 普通用户 | 新建普通用户                         | 1. 创建`/home`目录下的用户目录.<br />2. 创建用户目录下一些必要的文件及文件夹：`.ssh`,  `authorized_keys`, `.bashrc`, `.profile`.<br />3.设置bash.<br />4.设置普通用户密码，32位强度密码.<br />5.添加`sudo`权限.<br />6.设置ssh登录权限. |
| SSH登录  | 优化sushi_config配置                 | 1.修改默认ssh端口(22).<br />2.关闭root登录权限.<br />3.新增的普通用户的ssh登录权限.<br />4.设置ssh会话超时时间. |
| 软件更新 | 更新系统软件包<br />安装常用的软件包 | 1.apt-get update & upgrade<br />2.apt-get install -y iptables iptables-persistent unzip ntp htop zsh git-core |
| 内核优化 | 优化 /etc/sysctl.conf 配置           | kernel.panic<br />kernel.exec-shield<br />kernel.randomize_va_space<br />net.core.netdev_max_backlog<br />net.core.somaxconn<br />net.ipv4.icmp_ratelimit<br />net.ipv4.icmp_ratemask<br />net.ipv4.icmp_echo_ignore_broadcasts<br />net.ipv4.icmp_ignore_bogus_error_responses<br />net.ipv4.conf.all.accept_redirects<br />net.ipv4.conf.all.accept_source_route<br />net.ipv4.conf.all.rp_filter<br />net.ipv4.conf.all.log_martians<br />net.ipv4.conf.all.arp_announce<br />net.ipv4.conf.all.arp_ignore<br />fs.file-max<br />net.ipv4.tcp_syncookies<br />net.ipv4.tcp_max_syn_backlog<br />net.ipv4.tcp_rfc1337<br />net.ipv4.tcp_timestamps<br />net.ipv4.tcp_synack_retries<br />net.ipv4.tcp_syn_retries<br />net.ipv4.tcp_tw_recycle<br />net.ipv4.tcp_tw_reuse<br />net.ipv4.tcp_keepalive_time<br />net.ipv4.tcp_keepalive_intvl<br />net.ipv4.tcp_keepalive_probes<br />net.ipv4.tcp_fin_timeout<br />net.netfilter.nf_conntrack_tcp_timeout_time_wait<br />vm.swappiness<br />net.ipv4.ip_local_port_range<br />net.nf_conntrack_max |
| 磁盘优化 | swap分区配置                         | 从阿里云数据盘中分出1G来作为swap                             |
|          | 挂载数据盘                           | 将数据盘余下的空间挂载到 `/mydata` 目录下                    |

> - ssh key登录需要等到后面再去单独设置。这里只是初步优化配置，并未强制关闭密码登录，未强制开启ssh key登录，不然在ssh key未配置的情况下，等该脚本执行完，你就无法登录服务器了。
> - 阿里云的ECS默认挂载了系统盘，而该脚本主要是对**数据盘**做分区处理，系统盘无法处理



## 服务器优化配置

### 下载脚本

> [ubuntu-optimize](https://github.com/gxcdac/gxchain-script/blob/master/ubuntu-script/ubuntu-optimize.sh)

```shell
$ wget https://raw.githubusercontent.com/wangweiX/linux-script/master/ubuntu-optimize.sh
```

### 自定义功能

你可以根据自己的需要，修改脚本末尾的调用的函数，注释或开启你想要优化的配置

```shell
change_hostname
sshuser_tunning
sshd_config_tunning
package_tunning
base_system_tunning
disk_dev_tunning
```

### 配置参数

修改脚本，配置以下参数：

```shell
# 配置新建的普通用户名
MY_NEW_USER='myserver'
# 配置ssh端口
MY_SSH_PORT=41837
# 配置数据盘路劲
MY_DATA_DEV='vda1'
```

> 执行命令 `fdisk -l` 查看服务器数据盘
>
> ```powershell
> $ sudo fdisk -l
> 
> ## 输出如下信息
> Disk /dev/vda1: 42.9 GB, 42949672960 bytes, 83886080 sectors
> Units = sectors of 1 * 512 = 512 bytes
> Sector size (logical/physical): 512 bytes / 512 bytes
> I/O size (minimum/optimal): 512 bytes / 512 bytes
> Disk label type: dos
> Disk identifier: 0x0008d73a
> ```
>
> 数据盘路劲为：`/dev/vda1`
>
> 则 `MY_DATA_DEV`  配置为 `vda1` 



### 执行脚本

1. 执行脚本

   ```shell
   $ bash +x ubuntu-optimize.sh
   ```

2. 按照提示，输入你想要设置的`hostname`，例如: `gxchain-test-node-01`

3. 途中会有要出入'Y'或按回车键的地方

4. 耐心等待脚本执行完毕

5. 若无问题，最后会输出如下内容：

   ```tex
   eth0 is 10.10.10.06
   hostname is gxchain-test-node-01
   username is gxchainuser
   port is 41837
   password is BmY1Fm2prNT*lZWSmEYMzuI1rg8S*lSl
   -----------END-----------
   ```

6. 保存好密码，用于后期登录：

   ```shell
   $ ssh -p 41837 myserver@10.10.10.06
   
   enter password: BmY1Fm2prNT*lZWSmEYMzuI1rg8S*lSl
   ```



## 安全

### SSH Key登录

> 根据自己需要，这一步也可以省略

一般我们登录生产机器，会通过跳板机去登录，我们需要在跳板机上生成SSH公私钥，用于登录生产机器

登录跳板机，生成ssh key，可以修改后面的备注remark。

```powershell
$ ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa_aws_$(date +%Y-%m-%d) -C "remark"
```

安装ssh public key，将上一步生成的ssh public key安装到指定的生产机上。

> 替换`.pub`文件名、`user`和`remote-server-ip`

```powershell
$ ssh-copy-id -i id_rsa_aws_2015-03-04.pub user@remote-server-ip
```

使用新生成的ssh key 登录生产机，并再次优化sshd_config配置，强制关闭密码登录，强制开启pubkey登录
1. 使用ssh key登录，例如：

   ```shell
   $ ssh -i ssh_private_file -p 41837 gxchainuser@101.71.23.9
   ```

2. 优化`sshd_config`配置，强制关闭密码登录，强制开启pubkey登录，单独执行下面的脚本：

   ```shell
   sshd_pwd_auth_tunning(){
       sed -ri 's/#PasswordAuthentication\s+yes/PasswordAuthentication\tno/g;' /etc/ssh/sshd_config
       if ! grep 'AuthenticationMethods publickey' /etc/ssh/sshd_config >/dev/null;then echo "AuthenticationMethods publickey" >> /etc/ssh/sshd_config;fi
   }
   
   sshd_pwd_auth_tunning
   
   service sshd restart
   ```

### 防火墙设置

> **注意**：使用该脚本时，请务必认真检查要设置规则的IP与端口，避免服务器及应用功能异常！

#### 下载脚本

> [ubuntu-firewall](https://github.com/gxcdac/gxchain-script/blob/master/ubuntu-script/ubuntu-firewall.sh)

```shell
$ wget https://raw.githubusercontent.com/wangweiX/linux-script/master/ubuntu-firewall.sh
```

#### 配置 INPUT 规则

找到 `ubuntu-firewall.sh` 中 `input_rules()`  方法中的下面这段内容，按照你的实际需求，对要开发的端口和IP进行配置

```shell
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

```

#### 配置 OUTPUT 规则

找到 `ubuntu-firewall.sh` 中 `output_rules()`  方法中的下面这段内容，按照你的实际需求，对要开发的端口和IP进行配置

```shell
###### Add the output rules here:
# iptables -A OUTPUT -p tcp -m state --state NEW -d <destnation_address> --dport <destnation_port> -j ACCEPT
###### Add an end

# allow DNS-NTP-FTP-HTTP-HTTPS-SMTP
PORTS1="53 123 21 80 443 25"
for port1 in $PORTS1;do iptables -A OUTPUT -p udp -m state --state NEW --dport $port1 -j ACCEPT;done

# allow your custom SSH port
PORTS2="22"
for port2 in $PORTS2;do iptables -A OUTPUT -p tcp -m state --state NEW --dport $port2 -j ACCEPT;done

# allow your own app port
PORTS3="22"
for port3 in $PORTS3;do iptables -A OUTPUT -p tcp -m state --state NEW --dport $port3 -j ACCEPT;done
```

#### 执行脚本

必须要以root的权限进行运行

```powershell
# ./ubuntu-firewall.sh
```



#### 阿里云安全组设置

如果你用的是阿里云的ECS服务，我们还需要做一道防御，将上面配置的防火墙规则同步到ECS安全组配置中去。



## 重启服务器

- 重启服务器，使一系列配置生效



## 制作镜像

可以使用优化过的服务器系统盘，制作自定义镜像，后面可以直接只用制作好的镜像来初始化服务器，大大减少了服务器的优化配置的时间。



## 其他

- 配置阿里云服务器快照策略
- 配置阿里云磁盘快照策略

