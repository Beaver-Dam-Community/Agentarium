# containerd-proxy image (TASK-09 3.6 containerd access boundary).
# Build: docker build -f build/docker/containerd-proxy.Dockerfile -t <image> .
# Same pinned base images as go-service.Dockerfile. The difference: /app is
# execute-only (0111). The proxy runs as UID 0 with every capability dropped,
# so it cannot read its own binary, and execve marks the process non-dumpable
# from its first instruction (fs/exec.c would_dump, fs.suid_dumpable != 1).
# The exporter, also UID 0, therefore cannot reach the containerd socket
# through /proc/<proxy>/root even before main runs PR_SET_DUMPABLE(0).
ARG GO_IMAGE=golang:1.27@sha256:820153096fda4de6ac1b7194d12e416b7dd8f4e9a33d17e0345b111b945162d8
ARG RUNTIME_IMAGE=gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

# Cross-compile on the build host (no emulated go build); the binary is
# static (CGO_ENABLED=0), so it matches a native TARGETPLATFORM build.
FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/app ./services/lifecycle-recorder/cmd/containerd-proxy

FROM ${RUNTIME_IMAGE}
COPY --from=build --chown=0:0 --chmod=0111 /out/app /app
USER 0:65532
ENTRYPOINT ["/app"]
