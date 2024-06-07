FROM docker.io/library/golang:latest

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -o /egressip-validator
EXPOSE 8080
CMD ["/egressip-validator"]
