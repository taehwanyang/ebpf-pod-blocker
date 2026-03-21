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
	totalRequests = 1000
	workerCount   = 50
)

func main() {
	jobs := make(chan int, totalRequests)

	var success int64
	var failure int64

	client := &http.Client{
		Timeout: 5 * time.Second,
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

	for jobId := range jobs {
		log.Printf("processing request #%d\n", jobId)
		err := sendRequest(client)
		if err != nil {
			atomic.AddInt64(failure, 1)
			log.Printf("request #%d FAILED\n", jobId)
			continue
		}
		atomic.AddInt64(success, 1)
		log.Printf("request #%d SUCCEEDED\n", jobId)
	}
}

func sendRequest(client *http.Client) error {
	tokenURL := "http://auth.ythwork.com/oauth2/token"

	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:password")
	form.Set("username", "user")
	form.Set("password", "1234")
	form.Set("scope", "read")

	req, err := http.NewRequest(http.MethodPost, tokenURL, bytes.NewBufferString(form.Encode()))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	basicAuth := base64.StdEncoding.EncodeToString([]byte("client:secret"))
	req.Header.Set("Authorization", "Basic "+basicAuth)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	log.Printf("status=%d body=%s\n", resp.StatusCode, string(body))

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}

	return fmt.Errorf("status: %d", resp.StatusCode)
}
