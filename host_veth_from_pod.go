package main

import (
	"bytes"
	"fmt"
	"log"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

func hostVethFromPod(pods []PodInfo) (string, error) {
	podName := pods[0].Name
	hostVethIfIndex, err := getPodIfLinkIndex(podName)
	if err != nil {
		return "", fmt.Errorf("Failed to get host veth interface index from pod name: %s: %w", podName, err)
	}
	hostVeth, err := getHostVethNameByIfindex(hostVethIfIndex)
	if err != nil {
		return "", fmt.Errorf("Failed to get host veth interface name from interface index: %d: %w", hostVethIfIndex, err)
	}
	log.Printf("host veth interface name [%s] from pod[%s]\n", hostVeth, podName)

	return hostVeth, nil
}

func getPodIfLinkIndex(podName string) (int, error) {
	cmd := exec.Command(
		"kubectl",
		"exec",
		podName,
		"--",
		"cat",
		"/sys/class/net/eth0/iflink",
	)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return 0, fmt.Errorf("kubectl exec failed: %w, stderr=%s", err, stderr.String())
	}

	out := strings.TrimSpace(stdout.String())
	return strconv.Atoi(out)
}

func getHostVethNameByIfindex(ifindex int) (string, error) {
	cmd := exec.Command("ip", "link")

	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("ip link failed: %w", err)
	}

	lines := strings.Split(stdout.String(), "\n")

	re := regexp.MustCompile(`^\s*(\d+):\s+([^:@]+)(?:@[^:]+)?:`)

	for _, line := range lines {
		matches := re.FindStringSubmatch(line)
		if len(matches) != 3 {
			continue
		}

		idx, _ := strconv.Atoi(matches[1])
		if idx == ifindex {
			return matches[2], nil
		}
	}

	return "", fmt.Errorf("interface not found for ifindex %d", ifindex)
}
