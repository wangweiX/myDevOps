#!/bin/bash
#------------------------------------------------------
#
# Nginx compile install script on CentOS 7
#
# @author https://wangwei.one/
# @date 2018/11/13
#------------------------------------------------------
# https://www.vultr.com/docs/how-to-compile-nginx-from-source-on-centos-7

set -e

HOME_USER="gxcchainuser"
# config nginx script home
NGINX_SCRIPT_HOME="/home/$HOME_USER/nginx-script"
# config build home
BUILD_HOME="/home/$HOME_USER/compile/"

# nginx mainline version
NGINX_VERSION='1.15.7'
#defind version
OPENSSL_VERSION='1.1.1'
# https://www.modpagespeed.com/doc/release_notes
NPS_VERSION='1.13.35.2-stable'
# defind pcre version(4.4 — 8.41)
PCRE_VERSION='8.41'
# defind zlib version
ZLIB_VERSION='1.2.11'

# domain list
DOMAIN_LIST=("example.com" "example.cn" "www.example.com" "www.example.cn")

# mix nginx name and version
MIX_NGINX_NAME='MyServer'
MIX_NGINX_VERSION='1.2.3'

NGINX_HOME="/etc/nginx/"
NGINX_GROUP="nginx"
NGINX_USER="nginx"

RED="\033[0;31m"
GREEN="\033[0;32m"
NO_COLOR="\033[0m"

compile(){
	
	echo "Install dependencies"
	yum update && yum upgrade -y
	yum autoremove

	# Install dependencies
	# 
	# * checkinstall: package the .deb
	# * libpcre3, libpcre3-dev: required for HTTP rewrite module
	# * zlib1g zlib1g-dbg zlib1g-dev: required for HTTP gzip module
	# apt-get install openssl libssl-dev libperl-dev libpcre3 libpcre3-dev zlib1g zlib1g-dbg zlib1g-dev libxslt1-dev libxml2-dev libgd2-xpm-dev
	yum install -y rpm-build rpmdevtools perl perl-devel perl-ExtUtils-Embed libxslt libxslt-devel libxml2 libxml2-devel gd gd-devel GeoIP GeoIP-devel libuuid-devel google-perftools-devel

	# create build home
	if [ ! -d ${BUILD_HOME} ]; then
	   echo "create build home"
	   mkdir -p ${BUILD_HOME}
	fi

	cd ${BUILD_HOME}
	if ! rpm -q checkinstall >/dev/null; then
		wget ftp://ftp.pbone.net/mirror/rnd.rajven.net/centos/6.5/os/x86_64/checkinstall-1.6.2-1.cnt6.x86_64.rpm
		rpm -ivvh checkinstall-1.6.2-1.cnt6.x86_64.rpm
	fi

	# download pcre
	echo "Delete exist pcre file"
	rm -rf ${BUILD_HOME}/pcre-*
	echo "Download pcre-$PCRE_VERSION"
	wget --no-check-certificate https://ftp.pcre.org/pub/pcre/pcre-$PCRE_VERSION.tar.gz && tar -xzvf pcre-$PCRE_VERSION.tar.gz

	# zlib version 1.1.3 - 1.2.11
	rm -rf ${BUILD_HOME}/zlib-$ZLIB_VERSION*
	echo "Download zlib-$ZLIB_VERSION"
	wget http://www.zlib.net/zlib-$ZLIB_VERSION.tar.gz && tar -xzvf zlib-$ZLIB_VERSION.tar.gz

	# Compile against OpenSSL to enable NPN
	echo "Delete exist openssl-${OPENSSL_VERSION} file"
	rm -rf ${BUILD_HOME}/$*openssl-${OPENSSL_VERSION}*
	echo "Download openssl-${OPENSSL_VERSION}"
	wget http://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz && tar -xzvf openssl-${OPENSSL_VERSION}.tar.gz

	# Download the Cache Purge module
	echo "Delete exist ngx_cache_purge"
	rm -rf ${BUILD_HOME}/*ngx_cache_purge*
	echo "Download ngx_cache_purge"
	git clone https://github.com/FRiCKLE/ngx_cache_purge.git

    echo "Delete naxsi module source"
	rm -rf ${BUILD_HOME}/*naxsi*
	git clone https://github.com/nbs-system/naxsi.git

	# Download PageSpeed
	# https://www.modpagespeed.com/doc/build_ngx_pagespeed_from_source
	echo "Delete pagespeed ngx ${NPS_VERSION} "
	rm -rf ${BUILD_HOME}/*${NPS_VERSION}*
	echo "Download pagespeed ngx ${NPS_VERSION} "
	wget https://github.com/apache/incubator-pagespeed-ngx/archive/v${NPS_VERSION}.zip
	unzip v${NPS_VERSION}.zip
	nps_dir=$(find . -name "*pagespeed-ngx-${NPS_VERSION}" -type d)
	cd "$nps_dir"
	NPS_RELEASE_NUMBER=${NPS_VERSION/beta/}
	NPS_RELEASE_NUMBER=${NPS_VERSION/stable/}
	psol_url=https://dl.google.com/dl/page-speed/psol/${NPS_RELEASE_NUMBER}.tar.gz
	[ -e scripts/format_binary_url.sh ] && psol_url=$(scripts/format_binary_url.sh PSOL_BINARY_URL)
	# extracts to psol/
	wget ${psol_url} && tar -xzvf $(basename ${psol_url})

	# Get the Nginx source.
	#
	# Best to get the latest mainline release. Of course, your mileage may
	# vary depending on future changes
	cd ${BUILD_HOME}
	echo "Delete exist nginx-${NGINX_VERSION} file"
	rm -rf ${BUILD_HOME}/*nginx-${NGINX_VERSION}*
	echo "Download nginx-${NGINX_VERSION} source file "
	wget http://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz && tar -xzvf nginx-${NGINX_VERSION}.tar.gz

	# Change Nginx Version Header
	echo "Start Change Nginx Version Header"
	# modify nginx.h to mix version
	sed -ri "s/#define\s+NGINX_VERSION\s+\"${NGINX_VERSION}\"/#define NGINX_VERSION      \"${MIX_NGINX_VERSION}\"/g;" ${BUILD_HOME}/nginx-${NGINX_VERSION}/src/core/nginx.h
	sed -ri "s/#define\s+NGINX_VER\s+\"nginx\/\" NGINX_VERSION/#define NGINX_VER          \"${MIX_NGINX_NAME}\/\" NGINX_VERSION /g;" ${BUILD_HOME}/nginx-${NGINX_VERSION}/src/core/nginx.h
	# modify ngx_http_header_filter_module.c to mix name
	sed -ri "s/static\s+u_char\s+ngx_http_server_string\[\]\s+=\s+\"Server: nginx\" CRLF;/static u_char ngx_http_server_string\[\] = \"Server: ${MIX_NGINX_NAME}\" CRLF;/g;" ${BUILD_HOME}/nginx-${NGINX_VERSION}/src/http/ngx_http_header_filter_module.c

	# Copy NGINX manual page to /usr/share/man/man8
	cp ${BUILD_HOME}/nginx-${NGINX_VERSION}/man/nginx.8 /usr/share/man/man8
	gzip /usr/share/man/man8/nginx.8
	# Check that Man page for NGINX is working
	man nginx

	# Configure nginx.
	# 
	# http://nginx.org/en/docs/configure.html
	# https://www.vultr.com/docs/how-to-compile-nginx-from-source-on-ubuntu-16-04
	# https://gist.github.com/tollmanz/8662688
	#
	# This is based on the default package in Debian. Additional flags have
	# been added:
	#
	# * --with-debug: adds helpful logs for debugging
	# * --with-openssl=$HOME/sources/openssl-1.0.1e: compile against newer version of openssl
	# * --with-http_v2_module: include the SPDY module
	cd ${BUILD_HOME}/nginx-${NGINX_VERSION}
	./configure --prefix=$NGINX_HOME \
	--sbin-path=/usr/sbin/nginx \
	--conf-path=/etc/nginx/nginx.conf \
	--error-log-path=/var/log/nginx/error.log \
	--http-log-path=/var/log/nginx/access.log \
	--pid-path=/var/run/nginx.pid \
	--lock-path=/var/run/nginx.lock \
	--http-client-body-temp-path=/var/cache/nginx/client_temp \
	--http-proxy-temp-path=/var/cache/nginx/proxy_temp \
	--http-fastcgi-temp-path=/var/cache/nginx/fastcgi_temp \
	--http-uwsgi-temp-path=/var/cache/nginx/uwsgi_temp \
	--http-scgi-temp-path=/var/cache/nginx/scgi_temp \
	--modules-path=/usr/lib/nginx/modules \
	--user=$NGINX_USER \
	--group=$NGINX_GROUP \
	--build=CentOS7 \
	--with-select_module \
    --with-poll_module \
    --with-threads \
    --with-file-aio \
    --with-http_ssl_module \
    --with-http_v2_module \
    --with-http_realip_module \
    --with-http_addition_module \
    --with-http_xslt_module=dynamic \
    --with-http_image_filter_module=dynamic \
    --with-http_geoip_module=dynamic \
    --with-http_sub_module \
    --with-http_dav_module \
    --with-http_flv_module \
    --with-http_mp4_module \
    --with-http_gunzip_module \
    --with-http_gzip_static_module \
    --with-http_auth_request_module \
    --with-http_random_index_module \
    --with-http_secure_link_module \
    --with-http_degradation_module \
    --with-http_slice_module \
    --with-http_stub_status_module \
    --with-mail=dynamic \
    --with-mail_ssl_module \
    --with-stream=dynamic \
	--with-stream_realip_module \
	--with-stream_geoip_module=dynamic \
	--with-stream_ssl_module \
	--with-stream_ssl_preread_module \
	--with-google_perftools_module \
	--with-compat \
	--with-openssl=$BUILD_HOME/openssl-${OPENSSL_VERSION} \
	--with-openssl-opt=enable-ec_nistp_64_gcc_128 \
	--with-openssl-opt=no-nextprotoneg \
	--with-openssl-opt=no-weak-ssl-ciphers \
	--with-openssl-opt=no-ssl3 \
	--with-pcre=$BUILD_HOME/pcre-$PCRE_VERSION \
	--with-pcre-jit \
	--with-zlib=$BUILD_HOME/zlib-$ZLIB_VERSION \
	--with-zlib-asm=cpu \
	--with-cc-opt='-g -O2 -fstack-protector --param=ssp-buffer-size=4 -Wformat -Werror=format-security -Wp,-D_FORTIFY_SOURCE=2' \
    --with-ld-opt='-Wl,-z,relro -Wl,--as-needed' \
    --add-dynamic-module=$BUILD_HOME/$nps_dir \
    --add-dynamic-module=$BUILD_HOME/ngx_cache_purge \
    --add-dynamic-module=$BUILD_HOME/naxsi/naxsi_src \
	--with-debug

	echo -e "$GREEN Nginx configure finished ! $NO_COLOR"

	# Make the package.
	make install
	echo -e "$GREEN Nginx package make finished ! $NO_COLOR"
	echo -e "$GREEN Nginx install finished ! $NO_COLOR"

	return 0
}

install(){
	# Install the package.
	if [ ! -d '/var/log/nginx' ]; then
		mkdir -p /var/log/nginx
	fi
	if [ ! -d '/var/cache/nginx' ]; then
		mkdir -p /var/cache/nginx
	fi
	if [ ! -d '/usr/lib/nginx/modules' ]; then
		mkdir -p /usr/lib/nginx/modules
	fi
	echo -e "$GREEN Nginx install finished ! $NO_COLOR"
	return 0
}

uninstall(){

	# delete user and group
	if grep "$NGINX_USER" /etc/passwd &> /dev/null ; then
	    userdel $NGINX_USER
	fi

	# rm -rf some nginx files
	rm -rf /etc/nginx
	rm -rf /usr/sbin/nginx
	rm -rf /var/log/nginx
	rm -rf /var/run/nginx*
	rm -rf /var/cache/nginx
	rm -rf /usr/lib/nginx
	rm -rf /lib/systemd/system/nginx.service
	rm -rf /usr/share/nginx

	# uninstall .rpm package
	if rpm -q nginx >/dev/null; then
		rpm -e --nodeps nginx
	fi
	echo -e "$GREEN Nginx uninstall finished ! $NO_COLOR"
	return 0
}

config(){

	# config naxsi rules
	if [ -f "$BUILD_HOME/naxsi/naxsi_config/naxsi_core.rules" ]; then
       cp $BUILD_HOME/naxsi/naxsi_config/naxsi_core.rules $NGINX_HOME
	fi
	
	# set nginx vim contrb
	if [ ! -d "/root/.vim" ]; then
		mkdir -p /root/.vim
	fi
	if [ ! -d "/home/$HOME_USER/.vim" ]; then
		mkdir -p /home/$HOME_USER/.vim
	fi
	cp -rp $BUILD_HOME/nginx-$NGINX_VERSION/contrib/vim/* /root/.vim/
	cp -rp $BUILD_HOME/nginx-$NGINX_VERSION/contrib/vim/* /home/$HOME_USER/.vim/

	# create user and group
	if ! grep "$NGINX_USER" /etc/passwd &> /dev/null; then
	    useradd -s /bin/false $NGINX_USER
	    echo -e "$GREEN Create nginx user finished ! $NO_COLOR"
	fi
	# clean default config files
	rm -rf $NGINX_HOME/*
	echo -e "$GREEN Nginx default config files clean finished ! $NO_COLOR"
	
	# config nginx
	cp -rp $NGINX_SCRIPT_HOME/nginx-conf/* $NGINX_HOME
	# set nginx file permission
	chmod -R 644 $NGINX_HOME
	chmod 755 $NGINX_HOME/html
	chown -R root:root $NGINX_HOME
	echo -e "$GREEN Nginx config files set finished ! $NO_COLOR"

	# config systemctl nginx.service
	chmod 644 $NGINX_SCRIPT_HOME/nginx.service 
	if [ -f /lib/systemd/system/nginx.service ]; then
		systemctl unmask nginx.service
		rm -rf /lib/systemd/system/nginx.service
	fi
	
	cp $NGINX_SCRIPT_HOME/nginx.service /lib/systemd/system/
	systemctl enable nginx
		
    return 0
}

certbot(){
	# install certbot
	# https://medium.com/@jgefroh/a-guide-to-using-nginx-for-static-websites-d96a9d034940
	# https://www.digitalocean.com/community/tutorials/how-to-secure-nginx-with-let-s-encrypt-on-ubuntu-16-04
	yum -y install yum-utils
	yum-config-manager --enable rhui-REGION-rhel-server-extras rhui-REGION-rhel-server-optional
	yum install python2-certbot-nginx
    
	# crate certificate for nginx
	domains=$(printf "%s -d %s" "${DOMAIN_LIST[@]}")
	certbot --nginx -d $domains
	
	# auto certbot renew config
	if [ ! -f "/etc/cron.daily/certbot" ]; then
	   touch "/etc/cron.daily/certbot"
	   chmod +x "/etc/cron.daily/certbot"
	fi
	line="#!/bin/bash\ncertbot renew --post-hook \"systemctl reload nginx\""
        #echo new cron into cron file
        echo -e "$line" > "/etc/cron.daily/certbot"
	echo -e "$GREEN Nginx SSL cert config finished ! $NO_COLOR"
	return 0
}

fail2ban(){
	# https://www.cyberciti.biz/tips/linux-unix-bsd-nginx-webserver-security.html
	yum install fail2ban
	if [ ! -f "/etc/fail2ban/filter.d/nginx-req-limit.conf" ]; then
		touch "/etc/fail2ban/filter.d/nginx-req-limit.conf"
	fi
	echo "# Fail2Ban configuration file
#
# supports: ngx_http_limit_req_module module

[Definition]

failregex = limiting requests, excess:.* by zone.*client: <HOST>

# Option: ignoreregex
# Notes.: regex to ignore. If this regex matches, the line is ignored.
# Values: TEXT
#
ignoreregex =" > /etc/fail2ban/filter.d/nginx-req-limit.conf
	
	if [ ! -f "/etc/fail2ban/jail.local" ]; then
		cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
	fi
	echo "[nginx-req-limit]

enabled = true
filter = nginx-req-limit
action = iptables-multiport[name=ReqLimit, port="http,https", protocol=tcp]
logpath = /var/log/nginx/*error.log
findtime = 600
bantime = 7200
maxretry = 10" > /etc/fail2ban/jail.local
	
	systemctl enable fail2ban
	systemctl restart fail2ban

	echo -e "$GREEN DDos mitigation config finished ! $NO_COLOR"

	echo "Usage: 
		1. see fail2ban log            : tail -f /var/log/fail2ban.log
		2. sedd particular jail status : fail2ban-client status nginx-req-limit
		3. see fail2ban-server config  : fail2ban-client -d
		4. see fail2ban filter works   : fail2ban-regex /var/log/nginx/example.com.error.log"

	return 0
}

usage="Usage: ./$(basename "$0") [command]

command:
    h            show help info.
    compile      compile nginx and module source.
    install      install nginx
    uninstall    uninstall nginx
    config       update nginx default config
    certbot      generate nginx ssl certificate
    fail2ban     install fail2ban for nginx"

case $1 in
    h|help)
      echo "$usage"
      exit
      ;;
	compile)
	  compile
	;;
	install)
	  install
	;;
	uninstall)
	  uninstall
	;;  
	config)
	  config
	;;
	certbot)
	  certbot
	;;
	fail2ban)
	  fail2ban
	;;
	*)
      printf "illegal command: %s\n" "$1" >&2
      echo "$usage" >&2
      exit 1
      ;;
esac
exit 0
