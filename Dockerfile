# syntax=docker/dockerfile:1
FROM golang:1.23-alpine AS build
WORKDIR /src

ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown

COPY go.mod go.sum* ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w \
      -X github.com/snapp-incubator/mcp-authz/internal/version.Version=${VERSION} \
      -X github.com/snapp-incubator/mcp-authz/internal/version.Commit=${COMMIT} \
      -X github.com/snapp-incubator/mcp-authz/internal/version.Date=${DATE}" \
    -o /out/mcp-authz ./cmd/mcp-authz

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/mcp-authz /usr/local/bin/mcp-authz
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/mcp-authz"]
CMD ["-config=/etc/mcp-authz/config.yaml", "-addr=:8080", "-mode=both"]
