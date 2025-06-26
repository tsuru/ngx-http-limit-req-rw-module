.PHONY: build clean download-nginx build-nginx configure build-module run test debug

setup: clean download-nginx configure

build: build-nginx build-module

download-nginx:
	curl https://nginx.org/download/nginx-1.26.3.tar.gz > nginx.tar.gz
	tar -zxvf nginx.tar.gz

configure:
	cd nginx-1.26.3 && ./configure --prefix=$(PWD)/build --add-dynamic-module=..

build-nginx:
	cd nginx-1.26.3 && make && make install

build-module:
	cd nginx-1.26.3 && make modules && make install

clean:
	rm -rf nginx-1.26.3
	rm -rf nginx.tar.gz

run:
	./build/sbin/nginx -g "daemon off;" -c $(PWD)/nginx.conf

test:
	./scripts/test.sh

debug:
	cd ./reader-go; go build -o debugger main.go; mv ./debugger ..
	./debugger one.bin
	./debugger two.bin

log:
	go run log_zone/*.go log

send:
	go run log_zone/*.go send
