FROM golang:1.27.0-alpine@sha256:4c9fe60190a2a3350ddc51de80d0224b8a6698d12bdfc999fee45ea9d6c46dbc AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/glasseqserver ./cmd/glasseqserver

FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b AS certificates

RUN apk add --no-cache ca-certificates

FROM scratch

ARG SOURCE_REVISION=development
LABEL org.opencontainers.image.licenses="AGPL-3.0-or-later"
LABEL org.opencontainers.image.revision="$SOURCE_REVISION"
LABEL org.opencontainers.image.source="https://github.com/juhokoskela/GlassEQServer"

COPY --from=certificates /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/glasseqserver /usr/local/bin/glasseqserver
COPY LICENSE /usr/share/licenses/GlassEQServer/LICENSE
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/glasseqserver"]
