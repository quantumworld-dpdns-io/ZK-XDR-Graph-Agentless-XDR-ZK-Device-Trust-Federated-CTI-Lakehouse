FROM golang:1.24-alpine AS builder
ENV GOTOOLCHAIN=auto
WORKDIR /app
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /soar-playbook ./cmd/worker

FROM alpine:3.19
RUN apk --no-cache add ca-certificates
COPY --from=builder /soar-playbook /usr/local/bin/soar-playbook
ENTRYPOINT ["soar-playbook"]
