#!/usr/bin/env bash
set -euxo pipefail

echo "[INFO] Installing Helm..."
curl -fsSL -o /tmp/get_helm.sh https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3
chmod +x /tmp/get_helm.sh
/tmp/get_helm.sh
rm -f /tmp/get_helm.sh

echo "[INFO] Verifying Helm installation..."
helm version

echo "[INFO] Installing kubectx and kubens..."
if [ ! -d /opt/kubectx ]; then
  sudo git clone https://github.com/ahmetb/kubectx /opt/kubectx
else
  sudo git -C /opt/kubectx pull --ff-only || true
fi

sudo ln -sf /opt/kubectx/kubectx /usr/local/bin/kubectx
sudo ln -sf /opt/kubectx/kubens /usr/local/bin/kubens

echo "[INFO] Installing fzf for current user..."
if [ ! -d "$HOME/.fzf" ]; then
  git clone --depth 1 https://github.com/junegunn/fzf.git "$HOME/.fzf"
else
  git -C "$HOME/.fzf" pull --ff-only || true
fi

"$HOME/.fzf/install" --all

if ! grep -qxF 'export PATH="$HOME/.fzf/bin:$PATH"' "$HOME/.bashrc"; then
  echo 'export PATH="$HOME/.fzf/bin:$PATH"' >> "$HOME/.bashrc"
fi

export PATH="$HOME/.fzf/bin:$PATH"

echo "[INFO] Verifying kubectx / kubens / fzf..."
kubectx >/dev/null 2>&1 || true
kubens >/dev/null 2>&1 || true
fzf --version

echo "[INFO] Installation completed successfully."
echo "[INFO] Open a new shell or run: source ~/.bashrc"