# ---------- build stage ----------
FROM golang:1.25 AS builder

WORKDIR /src

RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    llvm \
    libelf-dev \
    libbpf-dev \
    gcc \
    make \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN make build

# ---------- runtime stage ----------
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /src/pod_blocker /app/pod_blocker

ENTRYPOINT ["/app/pod_blocker"]