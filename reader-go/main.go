package main

import (
	"bytes"
	"fmt"
	"io"

	msgpack "github.com/vmihailenco/msgpack/v5"
)

func main() {
	var buf bytes.Buffer

	msgs := []any{
		[]any{"hello", 1, 2},
		[]any{"congratulations", 3, 1},
	}

	encoder := msgpack.NewEncoder(&buf)
	for _, msg := range msgs {
		encoder.Encode(msg)
	}
	fmt.Println("encoded bytes", buf.Bytes())

	fmt.Println("starting decoding")

	decoder := msgpack.NewDecoder(&buf)
	for {
		var msg any
		if err := decoder.Decode(&msg); err != nil {
			if err == io.EOF {
				fmt.Println("EOF found")
			}
			break
		}
		fmt.Println(msg)
	}
}
