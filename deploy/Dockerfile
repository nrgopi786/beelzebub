# Hardened runtime image for per-client Xpod deployments.
# Build context is the repository root: docker build -f deploy/Dockerfile .
FROM golang:1.26-alpine AS builder

ENV CGO_ENABLED=0 GOOS=linux

RUN apk add --no-cache git

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .

ARG BEELZEBUB_GITHUB_TOKEN=""
RUN BEELZEBUB_GITHUB_TOKEN="$BEELZEBUB_GITHUB_TOKEN" go run . plugin install --no-build

ARG VERSION=dev
RUN go build -trimpath -ldflags "-s -w -X github.com/beelzebub-labs/beelzebub/v3/cli.Version=${VERSION}" -o /beelzebub . \
 && mkdir -p /rootfs/data/logs /rootfs/data/keys /rootfs/tmp

FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /rootfs/ /
COPY --from=builder /beelzebub /beelzebub

# Overridden at runtime with the deploying user's uid:gid (see compose.yml).
USER 65532:65532

ENTRYPOINT ["/beelzebub", "run", "--conf-core", "/config/beelzebub.yaml", "--conf-services", "/config/services/"]
