# syntax=docker/dockerfile:1.6
ARG GO_VERSION=1.22
FROM golang:${GO_VERSION}-alpine AS builder
WORKDIR /src
ENV CGO_ENABLED=0 GOOS=linux

COPY go.mod go.sum* ./
RUN go mod download

COPY . .

ARG VERSION=dev
ARG COMMIT=unknown
ARG DATE=unknown
RUN go build \
    -ldflags="-s -w \
        -X main.version=${VERSION} \
        -X main.commit=${COMMIT} \
        -X main.date=${DATE}" \
    -o /out/bulwark \
    ./cmd/bulwark

FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -S bulwark && adduser -S -G bulwark bulwark && \
    mkdir -p /config /data && chown -R bulwark:bulwark /config /data

COPY --from=builder /out/bulwark /usr/local/bin/bulwark

USER bulwark
WORKDIR /
EXPOSE 8080

ENTRYPOINT ["bulwark"]
CMD ["version"]
