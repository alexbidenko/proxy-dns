FROM golang:1.23.4-alpine AS build

ENV GOPATH="/go/src"

WORKDIR /app

COPY . .

RUN GOOS=linux go build -ldflags="-s -w" -o main .

FROM alpine

RUN adduser --system --uid 1001 app

USER app

WORKDIR /app

COPY --from=build --chown=app:app /app/main .

ENTRYPOINT  ["./main"]
