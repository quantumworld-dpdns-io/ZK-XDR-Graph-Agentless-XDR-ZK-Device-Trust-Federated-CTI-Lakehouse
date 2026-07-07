FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /event-normalizer ./cmd/worker

FROM alpine:3.19
RUN apk --no-cache add ca-certificates
COPY --from=builder /event-normalizer /usr/local/bin/event-normalizer
ENTRYPOINT ["event-normalizer"]
