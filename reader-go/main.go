package main

import (
	"fmt"
	"io"
	"log"
	"os"

	msgpack "github.com/vmihailenco/msgpack/v5"
)

type RateLimitHeader struct {
	Key          string
	Now          int64
	NowMonotonic int64
}

type RateLimitEntry struct {
	Key    []byte
	Last   int64
	Excess int64
}

func main() {
	argc := len(os.Args)
	argv := os.Args

	file := "./out.bin"
	if argc == 2 {
		file = argv[1]
	}
	fmt.Printf("Decoding file %s\n", file)

	f, err := os.Open(file)
	if err != nil {
		fmt.Println("error opening file", err)
		return
	}

	decoder := msgpack.NewDecoder(f)
	var header RateLimitHeader
	entries := []RateLimitEntry{}

	if err := decoder.Decode(&header); err != nil {
		log.Fatalln(err)
	}
	for {
		var entry RateLimitEntry
		if err := decoder.Decode(&entry); err != nil {
			if err == io.EOF {
				fmt.Println("EOF found")
				break
			}
			log.Fatalln(err)
		}
		entries = append(entries, entry)
	}
	fmt.Println(header)
	for _, entry := range entries {
		fmt.Println(entry)
	}
  fmt.Println(len(entries))
}
