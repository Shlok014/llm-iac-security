# syntax=docker/dockerfile:1.7

FROM golang:1.22.5-alpine3.20@sha256:9a1a6a0f4f4d1c1a0b1c40b4a4b1a3f2a4b1c9d0e2f3a4b5c6d7e8f9a0b1c2d3 AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY cmd/ ./cmd/
COPY internal/ ./internal/

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o /out/reporting-api ./cmd/reporting-api

FROM gcr.io/distroless/static-debian12:nonroot@sha256:3d0f463de06b7ddff27684ec3bfd0b54a425149d0f8685308b1fdf297b0265e9

LABEL org.opencontainers.image.title="reporting-api" \
      org.opencontainers.image.description="Read-only reporting API" \
      org.opencontainers.image.vendor="Northwind Retail Platform" \
      org.opencontainers.image.licenses="Apache-2.0"

WORKDIR /app

COPY --from=build --chown=65532:65532 /out/reporting-api /app/reporting-api

USER 65532:65532

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/app/reporting-api", "-health-check"]

ENTRYPOINT ["/app/reporting-api"]
CMD ["-listen=127.0.0.1:8080"]
