#!/bin/bash

curl --parallel --parallel-immediate \
  "http://localhost:8888/test" \
  "http://localhost:8888/test" \
  "http://localhost:8888/test" \
  "http://localhost:8888/test" \
  "http://localhost:8888/test"

echo "Last Request"

curl "http://localhost:8888/api" -i
