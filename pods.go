package main

import (
	"context"
	"fmt"
	"log"
	"os"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type PodInfo struct {
	Name      string
	Namespace string
	PodIP     string
	NodeName  string
}

var (
	Namespace     = envOrDefault("TARGET_NAMESPACE", "auth")
	LabelSelector = envOrDefault("LABEL_SELECTOR", "app=authorization-server")
)

func envOrDefault(key, def string) string {
	value := os.Getenv(key)
	if value == "" {
		return def
	}
	return value
}

func PodsByLabel(ctx context.Context) ([]PodInfo, error) {
	clientset, _, err := GetKubeClient()
	if err != nil {
		return nil, err
	}
	myNodeName := os.Getenv("MY_NODE_NAME")
	if myNodeName == "" {
		return nil, fmt.Errorf("MY_NODE_NAME is empty")
	}

	podList, err := clientset.CoreV1().
		Pods(Namespace).
		List(ctx, metav1.ListOptions{
			LabelSelector: LabelSelector,
		})
	if err != nil {
		return nil, fmt.Errorf("list pods: %w", err)
	}

	pods := make([]PodInfo, 0, len(podList.Items))
	for _, p := range podList.Items {
		if p.Spec.NodeName != myNodeName {
			continue
		}
		if p.Status.Phase != "Running" {
			continue
		}
		if p.Status.PodIP == "" {
			continue
		}

		pods = append(pods, PodInfo{
			Name:      p.Name,
			Namespace: p.Namespace,
			PodIP:     p.Status.PodIP,
			NodeName:  p.Spec.NodeName,
		})
	}

	log.Printf("Pods matching selector %q in namespace %q:\n", LabelSelector, Namespace)
	for _, pod := range pods {
		log.Printf("name=%s ip=%s node=%s", pod.Name, pod.PodIP, pod.NodeName)
	}

	return pods, nil
}
