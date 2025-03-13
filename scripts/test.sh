#!/bin/bash

curl --parallel --parallel-immediate \
  "http://localhost:8888/test" \
  "http://localhost:8888/test" \
  "http://localhost:8888/test" \
  "http://localhost:8888/test" \
  "http://localhost:8888/test"

curl --parallel --parallel-immediate \
  "http://192.168.3.21:8888/test" \
  "http://192.168.3.21:8888/test" \
  "http://192.168.3.21:8888/test" \
  "http://192.168.3.21:8888/test" \
  "http://192.168.3.21:8888/test"

echo "Last Request"

curl "http://localhost:8888/api/one" -v --output out.bin
