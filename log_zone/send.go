package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/vmihailenco/msgpack/v5"
)

func send(zone string) {
	err := sendRequest(
		zone,
		RateLimitHeader{
			Key:          BinaryRemoteAddress,
			Now:          time.Now().Unix(),
			NowMonotonic: time.Now().UnixNano() / int64(time.Millisecond),
		}, []RateLimitEntry{
			{Key([]byte{127, 0, 0, 0}), 7, 99},
			{Key([]byte{127, 0, 0, 1}), 7, 12},
			{Key([]byte{127, 6, 4, 00}), 2, 98},
			{Key([]byte{127, 0, 0, 99}), 30, 300},
			{Key([]byte{10, 0, 0, 1}), 444, 21},
		})
	if err != nil {
		logrus.Fatalf("Error sending request: %v", err)
	}
}

func sendRequest(zone string, header RateLimitHeader, entries []RateLimitEntry) error {
	var buf bytes.Buffer
	encoder := msgpack.NewEncoder(&buf)
	var values []interface{} = []interface{}{
		headerToArray(header),
	}
	for _, entry := range entries {
		values = append(values, entryToArray(entry, header))
	}
	if err := encoder.Encode(values); err != nil {
		return fmt.Errorf("error encoding entries: %w", err)
	}
	endpoint := fmt.Sprintf("http://localhost:9000/api/%s", zone)
	req, err := http.NewRequest(http.MethodPost, endpoint, &buf)
	if err != nil {
		return fmt.Errorf("error creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-msgpack")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("error sending request to %s: %w", endpoint, err)
	}
	fmt.Println(resp.Status)
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	logrus.Infof("response status: %s, body: %s", resp.Status, respBody)
	return nil
}

func headerToArray(header RateLimitHeader) []interface{} {
	return []interface{}{
		header.Key,
		header.Now,
		header.NowMonotonic,
	}
}

func entryToArray(entry RateLimitEntry, header RateLimitHeader) []interface{} {
	return []interface{}{
		entry.Key,
		entry.Last,
		entry.Excess,
	}
}
