package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/vmihailenco/msgpack/v5"
)

func main() {
	for {
		zone, err := handleRequest("one")
		if err != nil {
			logrus.Error("Error handling request", "error", err)
			return
		}
		fmt.Print("\033[H\033[2J")
		logrus.Infof("Zone: %s, RateLimitHeader: %+v, RateLimitEntries: %d",
			zone.Name, zone.RateLimitHeader, len(zone.RateLimitEntries))
		for _, entry := range zone.RateLimitEntries {
			logrus.Infof("Entry Key: %s, Last: %d, Excess: %d",
				entry.Key.String(zone.RateLimitHeader), entry.Last, entry.Excess)
		}
		fmt.Println("\nPress Ctrl+C to exit")
		time.Sleep(2 * time.Second)
	}
}

func handleRequest(zone string) (Zone, error) {
	endpoint := "http://localhost:9000/api/one"
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return Zone{}, err
	}

	response, err := http.DefaultClient.Do(req)
	if err != nil {
		return Zone{}, fmt.Errorf("error making request to %s: %w", endpoint, err)
	}
	defer response.Body.Close()
	decoder := msgpack.NewDecoder(response.Body)
	var rateLimitHeader RateLimitHeader
	rateLimitEntries := []RateLimitEntry{}
	log := logrus.New()
	if err := decoder.Decode(&rateLimitHeader); err != nil {
		if err == io.EOF {
			return Zone{
				Name:             zone,
				RateLimitHeader:  rateLimitHeader,
				RateLimitEntries: rateLimitEntries,
			}, nil
		}
		log.Error("Error decoding header", "error", err)
		return Zone{}, err
	}
	for {
		var message RateLimitEntry
		if err := decoder.Decode(&message); err != nil {
			if err == io.EOF {
				break
			}
			log.Error("Error decoding entry", "error", err)
			return Zone{}, err
		}
		message.Last = toNonMonotonic(message.Last, rateLimitHeader)
		rateLimitEntries = append(rateLimitEntries, message)
	}
	log.Debug("Received rate limit entries", "zone", zone, "entries", len(rateLimitEntries))
	return Zone{
		Name:             zone,
		RateLimitHeader:  rateLimitHeader,
		RateLimitEntries: rateLimitEntries,
	}, nil
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
