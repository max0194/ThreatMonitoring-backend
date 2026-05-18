FROM golang:1.25.7-alpine AS builder
WORKDIR /app

COPY ./go.mod ./go.sum ./
RUN go mod download

COPY ./ ./
RUN CGO_ENABLED=0 GOOS=linux go build -o threat-monitoring ./cmd/threat-monitoring

FROM alpine:latest
RUN apk add --no-cache ca-certificates

WORKDIR /app/

COPY --from=builder /app/threat-monitoring .

EXPOSE 8080
CMD ["./threat-monitoring"]
