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

type PodInfo struct {
	Namespace string
	Name      string
	UID       string
	PodIP     string
	NodeName  string
}

func PodsByLabel() []PodInfo {
	clientset, err := GetKubeClient()
	if err != nil {
		log.Fatalf("Failed to create kubernetes client: %v", err)
	}
	pods, err := getPodsByLabel(context.Background(), clientset, Namespace, LabelSelector)
	if err != nil {
		log.Fatalf("Failed to get pods: %v", err)
	}
	log.Printf("Pods matching selector %q in namespace %q:\n", LabelSelector, Namespace)
	for _, pod := range pods {
		log.Printf("name=%s ip=%s node=%s uid=%s", pod.Name, pod.PodIP, pod.NodeName, pod.UID)
	}

	return pods
}

func getPodsByLabel(ctx context.Context, clientset *kubernetes.Clientset, namespace, labelSelector string) ([]PodInfo, error) {
	podList, err := clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: labelSelector,
	})
	if err != nil {
		return nil, fmt.Errorf("Failed to list pods: %w", err)
	}
	result := make([]PodInfo, 0, len(podList.Items))
	for _, pod := range podList.Items {
		if pod.Status.PodIP == "" {
			continue
		}
		result = append(result, PodInfo{
			Namespace: pod.Namespace,
			Name:      pod.Name,
			UID:       string(pod.UID),
			PodIP:     pod.Status.PodIP,
			NodeName:  pod.Spec.NodeName,
		})
	}

	return result, nil
}
