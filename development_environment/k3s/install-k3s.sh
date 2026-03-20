#!/usr/bin/env bash
set -e

echo "Installing k3s..."

curl -sfL https://get.k3s.io | \
  INSTALL_K3S_EXEC="server --write-kubeconfig-mode=644" sh -

echo "k3s installed."

echo "Checking cluster..."
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml

kubectl get nodes -o wide
kubectl get pods -A