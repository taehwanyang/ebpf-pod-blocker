package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"runtime"
	"strconv"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

type PodVethInfo struct {
	Namespace string
	PodName   string
	PodUID    string
	PodIP     string
	NodeName  string

	SandboxID string
	PID       int

	VethName string
	IfIndex  int
}

type crictlPodsResponse struct {
	Items []crictlPodSandbox `json:"items"`
}

type crictlPodSandbox struct {
	ID       string            `json:"id"`
	Metadata crictlMetadata    `json:"metadata"`
	Labels   map[string]string `json:"labels"`
	State    string            `json:"state"`
}

type crictlMetadata struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	UID       string `json:"uid"`
}

type sandboxKey struct {
	Namespace string
	Name      string
	UID       string
}

func FindHostVethsForPods(ctx context.Context, pods []PodInfo, localNodeName string) ([]PodVethInfo, error) {
	if len(pods) == 0 {
		return nil, fmt.Errorf("pods is empty")
	}

	sandboxes, err := listCriPodSandboxes(ctx)
	if err != nil {
		return nil, fmt.Errorf("list cri pod sandboxes: %w", err)
	}

	sandboxIndex := indexSandboxesByPod(sandboxes)

	results := make([]PodVethInfo, 0, len(pods))

	for _, pod := range pods {
		if pod.NodeName != localNodeName {
			continue
		}

		key := sandboxKey{
			Namespace: pod.Namespace,
			Name:      pod.Name,
			UID:       pod.UID,
		}

		sb, ok := sandboxIndex[key]
		if !ok {
			return nil, fmt.Errorf("sandbox not found for pod %s/%s uid=%s", pod.Namespace, pod.Name, pod.UID)
		}

		pid, err := inspectSandboxPID(ctx, sb.ID)
		if err != nil {
			return nil, fmt.Errorf("inspect sandbox pid for pod %s/%s: %w", pod.Namespace, pod.Name, err)
		}

		vethName, ifindex, err := hostVethFromSandboxPID(pid)
		if err != nil {
			return nil, fmt.Errorf("find host veth for pod %s/%s: %w", pod.Namespace, pod.Name, err)
		}

		results = append(results, PodVethInfo{
			Namespace: pod.Namespace,
			PodName:   pod.Name,
			PodUID:    pod.UID,
			PodIP:     pod.PodIP,
			NodeName:  pod.NodeName,
			SandboxID: sb.ID,
			PID:       pid,
			VethName:  vethName,
			IfIndex:   ifindex,
		})
	}

	if len(results) == 0 {
		return nil, fmt.Errorf("no matching pods found on local node %q", localNodeName)
	}

	return results, nil
}

func indexSandboxesByPod(items []crictlPodSandbox) map[sandboxKey]crictlPodSandbox {
	out := make(map[sandboxKey]crictlPodSandbox, len(items))

	for _, item := range items {
		ns := item.Metadata.Namespace
		name := item.Metadata.Name
		uid := item.Metadata.UID

		if ns == "" && item.Labels != nil {
			ns = item.Labels["io.kubernetes.pod.namespace"]
		}
		if name == "" && item.Labels != nil {
			name = item.Labels["io.kubernetes.pod.name"]
		}
		if uid == "" && item.Labels != nil {
			uid = item.Labels["io.kubernetes.pod.uid"]
		}

		if ns == "" || name == "" || uid == "" {
			continue
		}

		out[sandboxKey{
			Namespace: ns,
			Name:      name,
			UID:       uid,
		}] = item
	}

	return out
}

func listCriPodSandboxes(ctx context.Context) ([]crictlPodSandbox, error) {
	cmd := exec.CommandContext(ctx, "crictl", "pods", "-o", "json")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("run crictl pods: %w", err)
	}

	var resp crictlPodsResponse
	if err := json.Unmarshal(out, &resp); err != nil {
		return nil, fmt.Errorf("parse crictl pods json: %w", err)
	}

	return resp.Items, nil
}

func inspectSandboxPID(ctx context.Context, sandboxID string) (int, error) {
	cmd := exec.CommandContext(ctx, "crictl", "inspectp", sandboxID, "-o", "json")
	out, err := cmd.Output()
	if err != nil {
		return 0, fmt.Errorf("run crictl inspectp %s: %w", sandboxID, err)
	}

	var raw any
	if err := json.Unmarshal(out, &raw); err != nil {
		return 0, fmt.Errorf("parse crictl inspectp json: %w", err)
	}

	pid, ok := findIntFieldRecursive(raw, "pid")
	if !ok || pid <= 0 {
		return 0, fmt.Errorf("pid not found in crictl inspectp output for sandbox %s", sandboxID)
	}

	return pid, nil
}

func findIntFieldRecursive(v any, fieldName string) (int, bool) {
	switch x := v.(type) {
	case map[string]any:
		if val, ok := x[fieldName]; ok {
			switch n := val.(type) {
			case float64:
				return int(n), true
			case int:
				return n, true
			case int64:
				return int(n), true
			case json.Number:
				i, err := strconv.Atoi(n.String())
				if err == nil {
					return i, true
				}
			}
		}
		for _, child := range x {
			if n, ok := findIntFieldRecursive(child, fieldName); ok {
				return n, true
			}
		}
	case []any:
		for _, child := range x {
			if n, ok := findIntFieldRecursive(child, fieldName); ok {
				return n, true
			}
		}
	}
	return 0, false
}

func hostVethFromSandboxPID(pid int) (string, int, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	hostNS, err := netns.Get()
	if err != nil {
		return "", 0, fmt.Errorf("get host netns: %w", err)
	}
	defer hostNS.Close()

	targetNS, err := netns.GetFromPid(pid)
	if err != nil {
		return "", 0, fmt.Errorf("get target netns from pid %d: %w", pid, err)
	}
	defer targetNS.Close()

	if err := netns.Set(targetNS); err != nil {
		return "", 0, fmt.Errorf("set target netns: %w", err)
	}

	podEth0, err := netlink.LinkByName("eth0")
	if err != nil {
		_ = netns.Set(hostNS)
		return "", 0, fmt.Errorf("find pod eth0: %w", err)
	}

	peerIfIndex := podEth0.Attrs().ParentIndex
	if peerIfIndex == 0 {
		_ = netns.Set(hostNS)
		return "", 0, fmt.Errorf("pod eth0 has no peer ifindex")
	}

	if err := netns.Set(hostNS); err != nil {
		return "", 0, fmt.Errorf("restore host netns: %w", err)
	}

	hostLink, err := netlink.LinkByIndex(peerIfIndex)
	if err != nil {
		return "", 0, fmt.Errorf("find host link by index %d: %w", peerIfIndex, err)
	}

	return hostLink.Attrs().Name, peerIfIndex, nil
}
