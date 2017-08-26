# framed


## 安装

### 安装OpenSSL

```
cd /usr/local/src
wget https://www.openssl.org/source/openssl-1.0.2-latest.tar.gz
tar -zxf openssl-1.0.2-latest.tar.gz -C /usr/local/
cd /usr/local/openssl-1.0.2l
./config
make depend
make
make test
make install
mv /usr/bin/openssl /usr/bin/openssl_1.0.1e
ln -s /usr/local/ssl/bin/openssl /usr/bin/openssl
openssl version
```

### 安装OpenResty
```
./configure --prefix=/opt/openresty \
            --with-luajit \
            --without-http_redis2_module \
            --with-http_iconv_module \
            --with-http_ssl_module --with-openssl=/usr/local/openssl-1.0.2l/ \
            --with-luajit-xcflags=-DLUAJIT_ENABLE_LUA52COMPAT \
            --with-http_gunzip_module
gmake
gmake install
```

安装完毕覆盖`nginx`目录

### 部署`framed.service`

```
[Unit]
Description=framed - high performance web server
Documentation=http://openresty.org
After=network.target remote-fs.target nss-lookup.target

[Service]
Type=forking
PIDFile=/opt/openresty/nginx/logs/nginx.pid
ExecStartPre=/opt/openresty/nginx/sbin/nginx -p /opt/openresty/nginx/ -t -c /opt/openresty/nginx/conf/nginx.conf
ExecStart=/opt/openresty/nginx/sbin/nginx -p /opt/openresty/nginx/ -c /opt/openresty/nginx/conf/nginx.conf
ExecReload=/opt/openresty/nginx/sbin/nginx -p /opt/openresty/nginx/ -c /opt/openresty/nginx/conf/nginx.conf -s reload
ExecStop=/opt/openresty/nginx/sbin/nginx -p /opt/openresty/nginx/ -c /opt/openresty/nginx/conf/nginx.conf -s stop
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```
