# syntax=docker/dockerfile:1
# Multi-stage build: a full Go toolchain compiles a static binary, then only
# that one file is copied into a minimal "distroless" image (no shell, no
# package manager, runs as a non-root user). Base images are pinned by digest
# so the build can't silently change underneath us.

# ---- build stage --------------------------------------------------------------
# --platform=$BUILDPLATFORM: compile natively on the build machine and
# cross-compile for the target (e.g. building linux/amd64 on an arm64 Mac).
FROM --platform=$BUILDPLATFORM golang:1.27.4-alpine@sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf AS build
ARG TARGETOS=linux
ARG TARGETARCH=amd64
WORKDIR /src

# Download modules first so this layer is cached until go.mod/go.sum change.
COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal
# CGO_ENABLED=0 -> fully static (pure-Go SQLite), -trimpath -> no local paths
# in the binary, -s -w -> strip debug symbols (smaller image).
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /out/plumbline ./cmd/plumbline

# ---- runtime stage ---------------------------------------------------------------
FROM gcr.io/distroless/static:nonroot@sha256:aafe993665bf6200db38a02c11a9351e782a84b6a45e7f33b6695638c88e3931
COPY --from=build /out/plumbline /plumbline
# /tmp is writable for the nonroot user. On Cloud Run it is an in-memory
# filesystem, so the demo database resets when the instance stops.
ENV PORT=8080 DB_PATH=/tmp/plumbline.db
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/plumbline"]
