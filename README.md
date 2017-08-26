# framed


## 安装

### 安装依赖

```
yum install readline-devel pcre-devel openssl-devel gcc uuid-devel
```

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
cd /usr/local/src
wget "https://openresty.org/download/openresty-1.11.2.5.tar.gz"
tar -xzvf openresty-1.11.2.5.tar.gz
cd openresty-1.11.2.5
./configure --prefix=/opt/openresty \
            --with-luajit \
            --without-http_redis2_module \
            --with-http_iconv_module \
            --with-http_ssl_module --with-openssl=/usr/local/openssl-1.0.2l/ \
            --with-luajit-xcflags=-DLUAJIT_ENABLE_LUA52COMPAT \
            --with-http_gunzip_module
gmake
gmake install
mkdir -p /data0/logs/
```

安装完毕覆盖`nginx`目录下必要的目录, 并设置`resolver`

```
cp -r ./nginx/conf /opt/openresty/nginx/boot/conf
cp -r ./nginx/src /opt/openresty/nginx/boot/src
cp -r ./nginx/html /opt/openresty/nginx/boot/html
echo resolver $(awk 'BEGIN{ORS=" "} /nameserver/{print $2}' /etc/resolv.conf | sed "s/ $/;/g") > /opt/openresty/nginx/conf/resolvers.conf

```

### 部署 `framed.service`

```
cp framed.service /etc/systemd/system/framed.service
systemctl enable framed
systemctl start framed
```
