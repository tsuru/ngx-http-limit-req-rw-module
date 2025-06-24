package main

import (
	"net"
	"os"
)

func main() {
	arg := os.Args[1:]
	zone := "one"
	if arg[0] == "log" {
		if len(arg) >= 2 {
			zone = arg[1]
		}
		logs(zone)
		return
	}
	if arg[0] == "send" {
		if len(arg) >= 2 {
			zone = arg[1]
		}
		send(zone)
	}
}

func toNonMonotonic(last int64, header RateLimitHeader) int64 {
	return header.Now - (header.NowMonotonic - last)
}

type Zone struct {
	Name             string
	RateLimitHeader  RateLimitHeader
	RateLimitEntries []RateLimitEntry
}

type RateLimitHeader struct {
	Key          string
	Now          int64
	NowMonotonic int64
}

type RateLimitEntry struct {
	Key    Key
	Last   int64
	Excess int64
}

const (
	BinaryRemoteAddress = "$binary_remote_addr"
	RemoteAddress       = "$remote_addr"
)

type Key []byte

func (r Key) String(header RateLimitHeader) string {
	switch header.Key {
	case BinaryRemoteAddress:
		return net.IP(r).String()
	case RemoteAddress:
		fallthrough
	default:
		return string(r)
	}
}
