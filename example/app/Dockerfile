FROM golang:1-alpine AS build

WORKDIR /app
ADD go.mod /app
ADD go.sum /app
RUN go mod download

ADD . /app
RUN go build

CMD ["/app/app"]
