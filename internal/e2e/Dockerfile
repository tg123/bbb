FROM golang:1.27-trixie AS minio

RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    GOBIN=/usr/local/bin go install github.com/minio/minio@RELEASE.2025-09-07T16-13-09Z

ENTRYPOINT ["/usr/local/bin/minio"]

FROM golang:1.27-trixie

WORKDIR /src
RUN --mount=type=cache,target=/root/.cache/go-build --mount=type=bind,source=.,target=/src go build -o /usr/local/bin/bbb
