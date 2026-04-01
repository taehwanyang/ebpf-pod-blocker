package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

var (
	clientset *kubernetes.Clientset
	restCfg   *rest.Config
	once      sync.Once
	initErr   error
)

func GetKubeClient() (*kubernetes.Clientset, *rest.Config, error) {
	once.Do(func() {
		clientset, restCfg, initErr = newKubeClient()
	})
	return clientset, restCfg, initErr
}

func newKubeClient() (*kubernetes.Clientset, *rest.Config, error) {
	if cfg, err := rest.InClusterConfig(); err == nil {
		cs, err := kubernetes.NewForConfig(cfg)
		if err != nil {
			return nil, nil, fmt.Errorf("create in-cluster clientset: %w", err)
		}
		return cs, cfg, nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get home dir: %w", err)
	}

	kubeconfig := filepath.Join(home, ".kube", "config")

	cfg, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build kubeconfig: %w", err)
	}

	cs, err := kubernetes.NewForConfig(cfg)

	if err != nil {
		return nil, nil, fmt.Errorf("create clientset from kubeconfig: %w", err)
	}

	return cs, cfg, nil
}
