#!/bin/bash
#pcre libraries
./objs/nginx -s stop
#sudo apt-get install libpcre3 libpcre3-dev
make clean
#configure options
#make clean
./configure \
 --conf-path=/etc/nginx/nginx.conf \
 --error-log-path=/var/log/nginx/error.log \
 --pid-path=/var/run/nginx.pid \
 --lock-path=/var/lock/nginx.lock \
 --http-log-path=/var/log/nginx/access.log \
 --http-client-body-temp-path=/var/lib/nginx/body \
 --http-proxy-temp-path=/var/lib/nginx/proxy \
 --without-http_fastcgi_module \
 --without-http_uwsgi_module \
 --with-http_stub_status_module \
 --with-http_gzip_static_module \
 --with-http_ssl_module \
 --with-debug \
 --add-module=./virgil-nginx-noise-link \

make
make install
