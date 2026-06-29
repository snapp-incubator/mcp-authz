# syntax=docker/dockerfile:1.10
#
# Builds one of the repo's two binaries, selected by BIN (mcp-authz | mcp-gateway).

FROM --platform=$BUILDPLATFORM golang:1.23-bookworm AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go mod download

COPY . .

ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown
ARG BIN=mcp-authz

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w \
    -X github.com/snapp-incubator/mcp-authz/internal/version.Version=${VERSION} \
    -X github.com/snapp-incubator/mcp-authz/internal/version.Commit=${COMMIT} \
    -X github.com/snapp-incubator/mcp-authz/internal/version.Date=${DATE}" \
    -o /out/app ./cmd/${BIN}

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /out/app /usr/local/bin/app

USER nonroot:nonroot

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/app"]
CMD ["-addr=:8080"]
