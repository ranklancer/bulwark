# syntax=docker/dockerfile:1.6
#
# Multi-stage build: Node compiles the React dashboard, Go embeds the
# resulting bundle and produces the daemon binary. The committed
# placeholder under internal/api/ui-react/dist/ keeps `go build` working
# for source builds without a Node toolchain; this image always
# replaces it with a real Vite artifact.

# Global build args — declared before the first FROM so they are in scope
# for every FROM line (Docker ARG scoping: pre-first-FROM args are global).
ARG NODE_VERSION=22
ARG GO_VERSION=1.26.5

# Stage 1: Build the React dashboard.
FROM node:${NODE_VERSION}-alpine AS web
WORKDIR /src

# package.json + lockfile first so `npm ci` is cacheable independently
# of source edits.
COPY web/package.json web/package-lock.json ./web/
RUN cd web && npm ci --no-audit --no-fund

# Vite's outDir is ../internal/api/ui-react/dist relative to the web/
# directory; mkdir the parent path so the build can write there.
RUN mkdir -p /src/internal/api/ui-react

# Now the actual sources.
COPY web/ ./web/
RUN cd web && npm run build
# /src/internal/api/ui-react/dist/{index.html,assets/*} now ready.

# Stage 2: Compile the Go binary with the real React bundle embedded.
FROM golang:${GO_VERSION}-alpine AS go
WORKDIR /src
ENV CGO_ENABLED=0 GOOS=linux

COPY go.mod go.sum* ./
RUN go mod download

COPY . .
# Replace the committed placeholder dist with the freshly-built one.
COPY --from=web /src/internal/api/ui-react/dist /src/internal/api/ui-react/dist

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

# Stage 3: Minimal runtime. ca-certificates for TLS to registries;
# tzdata so the cron + maintenance-window evaluator handles local time
# correctly when the operator sets TZ.
FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -S bulwark && adduser -S -G bulwark bulwark && \
    mkdir -p /config /data && chown -R bulwark:bulwark /config /data

COPY --from=go /out/bulwark /usr/local/bin/bulwark

USER bulwark
WORKDIR /
EXPOSE 8080

ENTRYPOINT ["bulwark"]
CMD ["version"]
