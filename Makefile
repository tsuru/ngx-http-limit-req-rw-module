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

build-proto:
	protoc --c_out=. ngx_http_limit_req_rw_message.proto

clean:
	rm -rf nginx-1.26.3
	rm -rf nginx.tar.gz

.PHONY: run
run:
	./build/sbin/nginx -c $(PWD)/nginx.conf

debug:
	cc -o main main.c ngx_http_limit_req_rw_message.pb-c.c -L/opt/homebrew/Cellar/protobuf-c/1.5.1/lib -lprotobuf-c  -I/opt/homebrew/Cellar/protobuf-c/1.5.1/include
