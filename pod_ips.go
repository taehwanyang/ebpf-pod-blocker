package main

import (
	"context"
	"fmt"
	"log"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	Namespace     = "auth"
	LabelSelector = "app=authorization-server"
)

func PodIpsByLabel() []string {
	clientset, err := GetKubeClient()
	if err != nil {
		log.Fatalf("Failed to create kubernetes client: %v", err)
	}
	ips, err := getPodIPsByLabel(context.Background(), clientset, Namespace, LabelSelector)
	if err != nil {
		log.Fatalf("Failed to get pod IPs: %v", err)
	}
	log.Printf("Pods matching selector %q in namespace %q:\n", LabelSelector, Namespace)
	for _, ip := range ips {
		log.Println(ip)
	}

	return ips
}

func getPodIPsByLabel(ctx context.Context, clientset *kubernetes.Clientset, namespace, labelSelector string) ([]string, error) {
	podList, err := clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: labelSelector,
	})
	if err != nil {
		return nil, fmt.Errorf("Failed to list pods: %w", err)
	}

	ips := make([]string, 0, len(podList.Items))
	for _, pod := range podList.Items {
		if pod.Status.PodIP == "" {
			continue
		}
		ips = append(ips, pod.Status.PodIP)
	}

	return ips, nil
}
