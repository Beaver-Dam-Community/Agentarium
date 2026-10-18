# Probe runner image (TASK-10 3.2 answer probe): the runner at
# /probe/bin/probe-runner (the PROBE_ENTRYPOINTS path paired with this
# image's digest) and the fixed process-probe binary /probe/bin/marker. Two
# binaries need two COPY lines, so this file follows
# build/docker/go-service.Dockerfile (same pinned base digests, CGO off,
# -trimpath) instead of using it directly.
# Build: docker build -f services/probe-runner/Dockerfile -t <image> .
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
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/probe-runner ./services/probe-runner/cmd/probe-runner \
 && CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/marker ./services/probe-runner/cmd/marker

FROM ${RUNTIME_IMAGE}
COPY --from=build /out/probe-runner /probe/bin/probe-runner
COPY --from=build /out/marker /probe/bin/marker
# agent-exec probe admission requires runAsUser 10001 (TASK-01).
USER 10001:10001
ENTRYPOINT ["/probe/bin/probe-runner"]
