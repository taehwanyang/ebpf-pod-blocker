package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"
)

const (
	totalRequests = 100000
	workerCount   = 50
)

func main() {
	jobs := make(chan int, totalRequests)

	var success int64
	var failure int64

	transport := &http.Transport{
		DisableKeepAlives: true,
	}

	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: transport,
	}

	var wg sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go worker(&wg, client, jobs, &success, &failure)
	}

	start := time.Now()

	for i := 0; i < totalRequests; i++ {
		jobs <- i
	}
	close(jobs)

	wg.Wait()

	elapsed := time.Since(start)

	fmt.Println("==== RESULT ====")
	fmt.Println("total:", totalRequests)
	fmt.Println("success:", success)
	fmt.Println("failure:", failure)
	fmt.Println("elapsed:", elapsed)
	fmt.Printf("RPS: %.2f\n", float64(totalRequests)/elapsed.Seconds())
}

func worker(
	wg *sync.WaitGroup,
	client *http.Client,
	jobs <-chan int,
	success *int64,
	failure *int64,
) {
	defer wg.Done()

	for jobID := range jobs {
		log.Printf("processing request #%d", jobID)

		err := sendRequest(client)
		if err != nil {
			atomic.AddInt64(failure, 1)
			log.Printf("request #%d FAILED: %v", jobID, err)
			continue
		}

		atomic.AddInt64(success, 1)
		log.Printf("request #%d SUCCEEDED", jobID)
	}
}

func sendRequest(client *http.Client) error {
	tokenURL := "http://auth-test-authorization-server.auth.svc.cluster.local/oauth2/token"

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("scope", "read")

	req, err := http.NewRequest(http.MethodPost, tokenURL, bytes.NewBufferString(form.Encode()))
	if err != nil {
		return err
	}

	req.Close = true
	req.Header.Set("Connection", "close")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	basicAuth := base64.StdEncoding.EncodeToString([]byte("client:secret123"))
	req.Header.Set("Authorization", "Basic "+basicAuth)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	time.Sleep(500 * time.Millisecond)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	log.Printf("status=%d body=%s", resp.StatusCode, string(body))

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}

	return fmt.Errorf("status: %d", resp.StatusCode)
}
