BINARY_NAME = pod_blocker
MY_NODE_NAME ?= $(shell kubectl get node -o jsonpath='{.items[0].metadata.name}')
GENERATED_FILES = count_conn_and_drop_bpfel.go count_conn_and_drop_bpfeb.go count_conn_and_drop_bpfel.o count_conn_and_drop_bpfeb.o

.PHONY: generate build clean run help

generate: ## Generate Go code from eBPF C source
	go generate ./...

build: generate ##  Generate eBPF code and build Go binary
	go build -buildvcs=false -o $(BINARY_NAME) .

run: build ##  Run the autoscaler program
	MY_NODE_NAME=$(MY_NODE_NAME) ./$(BINARY_NAME)

clean: ## Remove generated files and binary
	rm -f $(BINARY_NAME)
	rm -f $(GENERATED_FILES)

help: ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'