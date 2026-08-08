# Сборка из КОРНЯ репозитория: docker build -f api/Dockerfile .
# (образу нужны web/, engine/, db/ — они лежат рядом с api/)
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY api/go.mod api/go.sum ./api/
RUN cd api && go mod download
COPY api/ ./api/
RUN cd api && CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/qorgau-api .

FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata
COPY --from=build /out/qorgau-api /usr/local/bin/qorgau-api
COPY web/    /app/web/
COPY engine/ /app/engine/
COPY db/     /app/db/
WORKDIR /app
ENV WEB_DIR=/app/web \
    ENGINE_PROMPT_PATH=/app/engine/prompt.md \
    SCHEMA_PATH=/app/db/schema.sql
EXPOSE 8080
# Railway передаёт порт через $PORT — уважаем его, локально дефолт 8080.
CMD ["sh", "-c", "API_ADDR=\":${PORT:-8080}\" exec qorgau-api"]
