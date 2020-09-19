# Nginx优化配置



## 前言

对于Nginx的部署，你可以使用`apt-get`的方式来进行安装，也可以使用该脚本来进行安装。

对于比原生的安装方式，该脚本有以下几点优势：

-  nginx版本为mainline最新版本
-  默认提供已经优化过的配置文件，例如限流处理

- 增加了 [incubator-pagespeed-ngx](https://github.com/apache/incubator-pagespeed-ngx) 、[ngx_cache_purge](https://github.com/FRiCKLE/ngx_cache_purge)、[naxsi](https://github.com/nbs-system/naxsi) 等有有用的第三方module，有助于提升站点的性能与安全性。
- 提供SSL证书的部署以及SSL证书的自动更新。
- 通过fail2ban提供DDos防护处理。



## 安装

### 脚本下载

```powershell
$ cd ~
$ git clone git@github.com:wangweiX/nginx-script.git
$ chmod +x ~/nginx-script/nginx-install.sh
```

### 参数配置

配置`nginx-install.sh`脚本参数：

```powershell
#设置Nginx脚本目录
NGINX_SCRIPT_HOME="/home/user/nginx-script"
# 设置Nginx编译构建的目录
BUILD_HOME="/home/user/compile"
# 配置Nginx最新mainline版本
NGINX_VERSION='1.15.6'

# 修改Nginx源码，对Nginx的名称和版本进行混淆
MIX_NGINX_NAME='MyServer'
MIX_NGINX_VERSION='1.2.3'
```

### 编译

执行编译命令，等待编译完成，大约5min左右：

```powershell
$ sudo ./nginx-install.sh compile

**********************************************************************

 Done. The new package has been saved to

 /home/gxcdac/compile/nginx-1.15.6/nginx_1.15.6-1_amd64.deb
 You can install it in your system anytime using:

      dpkg -i nginx_1.15.6-1_amd64.deb

**********************************************************************

 Nginx .deb package create finished !
```

### 安装

```powershell
$ sudo ./nginx-install.sh install

Preparing to unpack .../nginx_1.15.6-1_amd64.deb ...
Unpacking nginx (1.15.6-1) over (1.15.6-1) ...
Setting up nginx (1.15.6-1) ...
 Nginx install finished !
```

### 验证

```powershell
# 版本检查
$ sudo nginx -v && sudo nginx -V

nginx version: MyServer/1.2.3 (Ubuntu)
nginx version: MyServer/1.2.3 (Ubuntu)
built by gcc 5.5.0 20171010 (Ubuntu 5.5.0-12ubuntu1~16.04)
built with OpenSSL 1.1.1  11 Sep 2018
TLS SNI support enabled

configure arguments: --prefix=/etc/nginx/  ... ...

```

> 如果你想重新安装，则可以执行卸载命令：
>
> ```powershell
> $ sudo ./nginx-install.sh uninstall
> ```



## Nginx配置

### conf配置

替换掉Nginx默认的配置文件，使用我们优化过的配置文件：

```powershell
$ sudo ./nginx-install.sh config

Nginx default config files clean finished !
Nginx config files set finished !
Created symlink from /etc/systemd/system/multi-user.target.wants/nginx.service to /lib/systemd/system/nginx.service.
```

在 `/etc/nginx/sites-enabled` 目录下会提供四种样例配置文件：`http.com.conf`、`https.com.conf`、`php.com.conf`、`static.com.conf`，你可以依据这些模板创建自己的站点配置。

验证Nginx配置

```powershell
$ sudo nginx -t

nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
nginx: configuration file /etc/nginx/nginx.conf test is successful
```

我们的模板里面配置了SSL，接下来，我们还需要生成SSL证书.

### SSL配置

配置 `nginx-install.sh`参数`DOMAIN_LIST`，设置你想要配置的域名，例如：

```powershell
DOMAIN_LIST=("example.com" "example.cn" "www.example.com" "www.example.cn")
```

> 注意：
>
> 1）确保域名已做过DNS解析和域名解析
>
> 2）并能够正常访问，可以先使用 `http.com.conf` 模板来临时创建站点配置
>
> 3）待 SSL 证书生成成功后，再使用 `https.com.conf` 模板配置站点

启动Nginx，确保Nginx处于运行状态：

```powershell
$ sudo systemctl start nginx
```

生成SSL证书

```powershell
$ sudo ./nginx-install.sh certbot

Nginx SSL cert config finished !
```

> 脚本添加了定期更新任务，域名的SSL证书，每天会定时更新。

**验证SSL证书**

使用 https://www.ssllabs.com/ssltest/analyze.html 来测试你的站点的SSL证书

## DDos防御

对于Nginx 的DDos防御配置，只能起到缓解攻击的作用，并不能完全杜绝DDos攻击。

### NGINX 部分

> 该部分配置，已通过命令 `sudo ./nginx-install.sh config` 配置添加到了Nginx中

在 http 部分中配置：

```nginx
limit_req_zone $binary_remote_addr zone=sym:10m rate=5r/s;
limit_conn_zone $binary_remote_addr zone=conn_sym:10m;
```

然后在需要流控的 location 部分配置：

```nginx
limit_req zone=sym burst=5;
limit_conn conn_sym 10;
```

重启 NGINX 后当有超流客户端请求时将在 NGINX error.log（默认在 `/var/log/nginx/error.log`） 中看到类似记录：

```
2017/02/12 18:03:57 [error]15965#15965: *61240 limiting requests, excess: 6.000 by zone "sym", client: 121.41.106.121, server: hacpai.com, request: "GET / HTTP/1.0", host: "hacpai.com"
```

此时请求已经被 NGINX 限流，但是客户端仍然能够继续发送请求，占用服务器资源。

### fail2ban

执行命令，安装fail2ban，并配置fail2ban

```powershell
$ sudo ./nginx-install.sh fail2ban 
```

查看配置：`/etc/fail2ban/jail.local`，其中这三个参数`findtime`、`bantime`、`maxretry`表示的含义是：

findtime 600 秒内如果有超过 maxretry 10 次匹配到则禁止连接 bantime 7200 秒。禁止连接通过操作 iptables 实现 。（要发送邮件，需要安装配置好 sendmail）

谨慎设置这三个参数。

#### 操作

- 查看超流日志：

  ```powershell
  $ tail -f /var/log/fail2ban.log
  
  ## 类似记录：
  2017-02-12 18:01:26,968 fail2ban.actions: WARNING [sym-cc] Ban 121.41.106.121
  2017-02-12 18:01:26,968 fail2ban.actions: WARNING [sym-cc] Ban 121.41.106.121
  ```

- 查看当前禁止信息：

  ```powershell
  $ sudo fail2ban-client status
  
  或
  
  $ sudo fail2ban-client status nginx-req-limit
  ```

- 查看配置匹配情况：

  ```powershell
  $ fail2ban-regex /var/log/nginx/error.log /etc/fail2ban/jail.local
  ```



## 问题

- 如果服务器是在国内，在执行nginx编译的过程中，可能会发生有部分github上的tar包下载超时的情况，鉴于这种情况请直接安装我们已经编译好的`.deb`包。
- 如果使用 [cloudflare](https://www.cloudflare.com/) 来解析域名，再配置HTTPS时，可能会出现 Too many redirects 的错误。解决如下：
  - https://stackoverflow.com/questions/35143193/cloudflare-and-nginx-too-many-redirects
  - https://stackoverflow.com/questions/41583088/http-to-https-nginx-too-many-redirects



## 工具

- 推荐一个生成Nginx配置的工具：https://github.com/valentinxxx/nginxconfig.io



## 参考

-  https://gist.github.com/denji/8359866
-  https://chasmathis.com/2017/10/28/fail2ban-ubuntu-16-04/
-  https://www.digitalocean.com/community/tutorials/how-to-protect-an-nginx-server-with-fail2ban-on-ubuntu-14-04
-  https://easyengine.io/tutorials/nginx/fail2ban/