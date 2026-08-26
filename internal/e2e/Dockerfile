FROM golang:1.27-trixie

WORKDIR /src
RUN --mount=type=cache,target=/root/.cache/go-build --mount=type=bind,source=.,target=/src go build -o /usr/local/bin/bbb
