# Shared image template for Go services.
# Build: docker build -f build/docker/go-service.Dockerfile --build-arg CMD=./services/<name> -t <image> .
# Base images are pinned by multi-arch index digest (COMMON: image digests are
# fixed by dependency and environment locks; TASK-16 3.1 rejects floating tags).
# The tag in each default is informational; the digest decides. To move a base
# image, resolve the new index digest with
#   docker buildx imagetools inspect <image>:<tag>
# and update the default here in a reviewed PR.
ARG GO_IMAGE=golang:1.27@sha256:820153096fda4de6ac1b7194d12e416b7dd8f4e9a33d17e0345b111b945162d8
ARG RUNTIME_IMAGE=gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

# Cross-compile on the build host (no emulated go build); the binary is
# static (CGO_ENABLED=0), so it matches a native TARGETPLATFORM build.
FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS build
ARG TARGETOS
ARG TARGETARCH
ARG CMD
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/app ${CMD}

FROM ${RUNTIME_IMAGE}
COPY --from=build /out/app /app
USER nonroot:nonroot
ENTRYPOINT ["/app"]
