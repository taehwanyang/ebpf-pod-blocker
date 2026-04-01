package main

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/remotecommand"
)

func hostVethFromPod(ctx context.Context, pod PodInfo) (*net.Interface, error) {
	hostVethIfIndex, err := getPodIfLinkIndex(ctx, pod)
	if err != nil {
		return nil, fmt.Errorf("Failed to get host veth interface index from pod %s/%s : %w", pod.Namespace, pod.Name, err)
	}

	iface, err := net.InterfaceByIndex(hostVethIfIndex)
	if err != nil {
		return nil, fmt.Errorf("find host interface by ifindex=%d: %w", hostVethIfIndex, err)
	}

	log.Printf("host veth interface name [%s] from pod[%s/%s]", iface.Name, pod.Namespace, pod.Name)

	return iface, nil
}

func getPodIfLinkIndex(ctx context.Context, pod PodInfo) (int, error) {
	stdout, stderr, err := podExec(ctx, pod.Namespace, pod.Name, []string{
		"cat", "/sys/class/net/eth0/iflink",
	})
	if err != nil {
		return 0, fmt.Errorf("exec iflink from pod %s/%s failed: %w, stderr=%s", pod.Namespace, pod.Name, err, stderr)
	}
	out := strings.TrimSpace(stdout)
	ifindex, err := strconv.Atoi(out)
	if err != nil {
		return 0, fmt.Errorf("parse iflink %q from pod %s/%s: %w", out, pod.Namespace, pod.Name, err)
	}

	return ifindex, nil
}

func podExec(ctx context.Context, namespace, podName string, command []string) (string, string, error) {
	clientset, restCfg, err := GetKubeClient()
	if err != nil {
		return "", "", err
	}

	req := clientset.CoreV1().RESTClient().
		Post().
		Resource("pods").
		Name(podName).
		Namespace(namespace).
		SubResource("exec")

	req.VersionedParams(&corev1.PodExecOptions{
		Command: command,
		Stdin:   false,
		Stdout:  true,
		Stderr:  true,
		TTY:     false,
	}, scheme.ParameterCodec)

	exec, err := remotecommand.NewSPDYExecutor(restCfg, "POST", req.URL())
	if err != nil {
		return "", "", fmt.Errorf("new spdy executor: %w", err)
	}

	var stdout, stderr bytes.Buffer
	if err := exec.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdout: &stdout,
		Stderr: &stderr,
	}); err != nil {
		return "", stderr.String(), fmt.Errorf("remote exec stream: %w", err)
	}

	return stdout.String(), stderr.String(), nil
}
