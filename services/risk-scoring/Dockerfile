FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /risk-scoring ./cmd/worker

FROM alpine:3.19
RUN apk --no-cache add ca-certificates
COPY --from=builder /risk-scoring /usr/local/bin/risk-scoring
EXPOSE 8080
ENTRYPOINT ["risk-scoring"]
