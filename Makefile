
.PHONY: build clean download-nginx build-nginx

build: clean download-nginx build-nginx

download-nginx:
	curl https://nginx.org/download/nginx-1.26.3.tar.gz > nginx.tar.gz
	tar -zxvf nginx.tar.gz

build-nginx:
	cd nginx-1.26.3 && ./configure --prefix=$(PWD)/build --add-dynamic-module=..
	cd nginx-1.26.3 && make && make install

build-module:
	cd nginx-1.26.3 && make modules && make install

clean:
	rm -rf nginx-1.26.3
	rm -rf nginx.tar.gz