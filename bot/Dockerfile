# Сборка из КОРНЯ репозитория: docker build -f bot/Dockerfile .
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY bot/go.mod bot/go.sum ./bot/
RUN cd bot && go mod download
COPY bot/ ./bot/
RUN cd bot && CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/qorgau-bot .

FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata
COPY --from=build /out/qorgau-bot /usr/local/bin/qorgau-bot
CMD ["qorgau-bot"]
