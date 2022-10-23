# buildation
FROM golang:1.18-alpine3.16

ENV PROJECT_PATH /go/src/github.com/user/builder
ENV BINARY_NAME builded-go

WORKDIR $PROJECT_PATH
ADD . $PROJECT_PATH

RUN set -eux
RUN apk update
RUN apk add --no-cache gcc musl-dev libpcap-dev
RUN go install -v
CMD CGO_ENABLED=1 GOOS=linux GOARCH=arm64 go build -ldflags="-w -s" -o ./$BINARY_NAME ./main.go