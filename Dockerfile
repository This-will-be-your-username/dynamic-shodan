# syntax=docker/dockerfile:1

# ---- build stage: cross-compile natively on the build host ----
FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/dynamic-shodan .

# ---- runtime: LinuxServer.io Alpine base (s6-overlay, PUID/PGID, /config) ----
FROM ghcr.io/linuxserver/baseimage-alpine:3.22

ARG BUILD_DATE
ARG VERSION
LABEL build_version="dynamic-shodan version:- ${VERSION} Build-date:- ${BUILD_DATE}"
LABEL maintainer="dynamic-shodan"
LABEL org.opencontainers.image.title="dynamic-shodan" \
      org.opencontainers.image.description="Shodan intel for a dynamic public IP, with IP ownership history to discard stale findings"

# The base image runs with HOME=/config for user abc.
ENV HOME="/config"

COPY --from=build /out/dynamic-shodan /app/dynamic-shodan
COPY root/ /

EXPOSE 8080
VOLUME /config
