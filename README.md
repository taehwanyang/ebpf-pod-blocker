# ebpf-pod-blocker

## 프로젝트 소개
  - eBPF는 리눅스 시스템 프로그래밍 분야에서 각광받고 있는 기술로 이를 활용하면 클라우드 운영에서 Observability, Security 등에서 다양한 기능을 구현할 수 있습니다.
  - 이 프로젝트는 eBPF로 TCP SYN 패킷을 카운트하여 제한 조건을 초과한 파드 사이의 트래픽을 차단하는 Pod Blocker라는 프로그램을 구현합니다.
  - auth-attacker는 keep-alive를 끈 채 대규모 HTTP 요청을 보냅니다. 이를 통해 TCP SYN flooding 공격을 비슷하게 구현할 수 있습니다.
  - 커널모드에서 동작하는 eBPF 프로그램은 (src-ip, dst-ip)의 SYN 요청 개수를 카운트하고 조건에 따라 패킷을 드롭합니다. 
    - count_conn_and_drop.c
  - 유저모드에서 동작하는 Go 프로그램은 패킷 드롭을 트리거하는 제한 조건을 커널모드로 전달하고 tc hook을 bridge 인터페이스에 추가합니다.
    - create_tc_hook_and_show_drop_log.go

## Clone할 때 주의사항
```
git clone --recurse-submodules https://github.com/taehwanyang/ebpf-pod-blocker.git
```

## K3S 개발환경 및 애플리케이션 배포
### Lima VM 설치
  - Mac을 사용하는 개발자의 경우, 개발 환경은 lima를 통해 구축합니다. lima를 설치하고 아래 명령을 실행합니다.
```sh
cd development_environment
limactl start ubuntu-ebpf.yaml
limactl shell ubuntu-ebpf
# eBPF를 실행하기 위해서는 루트 권한이 필요합니다.
sudo -s
```

### k3s 설치
```sh
./install-k3s.sh
./install-k8s-tools.sh

mkdir -p ~/.kube
sudo cp /etc/rancher/k3s/k3s.yaml ~/.kube/config
sudo chown $(id -u):$(id -g) ~/.kube/config
export KUBECONFIG=~/.kube/config
```

### authorization server & resource server image 명령어 모음
  - docker로 이미지를 만든 후 tar 파일로 압축합니다.
  - lima vm에서 이 파일을 이미지로 로드합니다.
```sh
# 도커 이미지 tar로 압축
docker save -o authorization-server.tar ythwork/authorization-server:0.0.1
docker save -o resource-server.tar ythwork/resource-server:0.0.1

# tar 파일을 k3s의 이미지로 로드
sudo k3s ctr images import ./authorization-server.tar
sudo k3s ctr images import ./resource-server.tar

# 이미지 확인 
sudo k3s ctr images ls

# 이미지 삭제
sudo k3s ctr images rm docker.io/ythwork/authorization-server:0.0.1
sudo k3s ctr images rm docker.io/ythwork/resource-server:0.0.1
```

### helm으로 authorization server & resource server 배포
```sh
git clone https://github.com/taehwanyang/helm-auth-servers.git
cd helm-auth-servers
helm install auth-test . -n auth --create-namespace
```

## eBPF 개발환경 
### bpftool 설치
```sh
git clone --recurse-submodules https://github.com/libbpf/bpftool.git
cd bpftool/src 
make install 
```

### bpf2go 설치
```sh
go install github.com/cilium/ebpf/cmd/bpf2go@latest
echo 'export PATH="$HOME/go/bin:$PATH"' >> /root/.bashrc
```

### vmlinux.h 추가
```sh
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

## attacker 파드 실행
```sh
cd attacker
kubectl apply -f attacker-pod.yaml
```

## tc 명령어
```sh
tc filter show dev cni0 ingress
tc qdisc del dev cni0 clsact
tc qdisc add dev cni0 clsact
```

## tcpdump
```sh
tcpdump -i cni0 'dst host 10.42.0.30 and tcp[tcpflags] & tcp-syn != 0'
```

## bpf_printk 커널 모드 로그 출력
```sh
cat /sys/kernel/debug/tracing/trace_pipe
```
