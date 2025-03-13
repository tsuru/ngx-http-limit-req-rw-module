package main

import (
	"fmt"
	"io"
	"os"

	msgpack "github.com/vmihailenco/msgpack/v5"
)

func main() {
	fmt.Println("starting decoding")

	f, err := os.Open("../out.bin")
	if err != nil {
		fmt.Println("error opening file", err)
		return
	}

	decoder := msgpack.NewDecoder(f)
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
