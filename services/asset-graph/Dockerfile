FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /asset-graph ./cmd/worker

FROM alpine:3.19
RUN apk --no-cache add ca-certificates
COPY --from=builder /asset-graph /usr/local/bin/asset-graph
ENTRYPOINT ["asset-graph"]
