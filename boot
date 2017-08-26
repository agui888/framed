#!/bin/bash
mkdir -p /data0/logs
alidns=""
echo resolver $alidns $(awk 'BEGIN{ORS=" "} /nameserver/{print $2}' /etc/resolv.conf | sed "s/ $/;/g") > /opt/openresty/nginx/conf/resolvers.conf

/opt/openresty/nginx/sbin/nginx -p /opt/openresty/nginx/ -c /opt/openresty/nginx/conf/nginx.conf -g "daemon off;"
