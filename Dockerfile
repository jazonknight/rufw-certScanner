# Stage 1: Build static binary
FROM golang:1.25-alpine AS builder

WORKDIR /app

# Copy Go module and source files
COPY go.mod ./
COPY *.go ./

# Build statically linked binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o certscanner .

# Stage 2: Production runtime image
FROM alpine:3.21

# Install ca-certificates and curl for health checks
RUN apk --no-cache add ca-certificates curl

WORKDIR /app
COPY --from=builder /app/certscanner /app/certscanner

# Default environment variables
ENV PORT=8080

EXPOSE ${PORT}

ENTRYPOINT ["/app/certscanner"]
CMD ["--server"]
