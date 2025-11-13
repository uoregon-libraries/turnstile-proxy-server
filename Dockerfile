FROM golang:1-alpine AS build

RUN apk update && apk upgrade
RUN apk add make upx git

WORKDIR /usr/local/src/turnstile-proxy
COPY go.mod go.sum /usr/local/src/turnstile-proxy
RUN go mod download

COPY internal ./internal
COPY cmd ./cmd
COPY .git ./.git
COPY Makefile ./Makefile

RUN make
RUN upx ./bin/tps

FROM alpine AS app
WORKDIR /usr/local/tps
RUN apk update && apk upgrade && rm -rf /var/cache/apk/*
COPY --from=build /usr/local/src/turnstile-proxy/bin/tps tps
ENV GIN_MODE=release
ENTRYPOINT ["/usr/local/tps/tps"]
CMD ["serve"]
