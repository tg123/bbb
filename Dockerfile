# syntax=docker/dockerfile:1

# ---- build stage ----
FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev

WORKDIR /src

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags "-s -w -X main.mainver=${VERSION}" -o /out/bbb .

# ---- runtime stage ----
# alpine keeps the image small (~10MB base) while still providing a real shell
# and a package manager, so users can script around bbb or add extra tools.
FROM alpine:3.22

RUN apk add --no-cache \
        ca-certificates \
        tzdata \
        bash \
        coreutils \
        findutils \
        curl \
        wget \
        sed \
        jq \
        tar \
        gzip \
        zstd

COPY --from=build /out/bbb /usr/local/bin/bbb

WORKDIR /data

ENTRYPOINT ["bbb"]
