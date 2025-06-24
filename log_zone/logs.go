package main

import (
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/vmihailenco/msgpack/v5"
)

func logs(zone string) {
	for {
		zone, err := handleRequest(zone)
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
	endpoint := fmt.Sprintf("http://localhost:9000/api/%s", zone)
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
