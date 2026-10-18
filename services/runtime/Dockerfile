# Agent runtime image (TASK-15 minimal M3-1 runtime): the supervisor at
# /app/bin/agent-runtime (agent-exec admission runtimeCommand) and the one
# approved worker executable at /app/bin/agent-worker (node-sensors
# worker_binaries). Two binaries need two COPY lines, so this file follows
# build/docker/go-service.Dockerfile (same pinned base digests, CGO off,
# -trimpath) instead of using it directly.
# Build: docker build -f services/runtime/Dockerfile -t <image> .
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
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/agent-runtime ./services/runtime/cmd/supervisor \
 && CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/agent-worker ./services/runtime/cmd/worker

FROM ${RUNTIME_IMAGE}
COPY --from=build /out/agent-runtime /app/bin/agent-runtime
COPY --from=build /out/agent-worker /app/bin/agent-worker
# agent-exec admission requires runAsUser 10001 (TASK-01).
USER 10001:10001
ENTRYPOINT ["/app/bin/agent-runtime"]
