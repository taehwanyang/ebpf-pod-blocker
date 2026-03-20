BINARY_NAME = auth-attacker

.PHONY: build clean

build:
	go build -buildvcs=false -o $(BINARY_NAME) auth-attacker.go

clean:
	rm -f $(BINARY_NAME)