FROM golang:1.24 AS builder

WORKDIR /src
COPY auth-attacker.go .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -buildvcs=false -o auth-attacker auth-attacker.go

FROM alpine:3.20
WORKDIR /app
COPY --from=builder /src/auth-attacker /app/auth-attacker

ENTRYPOINT ["/app/auth-attacker"]