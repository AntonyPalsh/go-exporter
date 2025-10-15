# go-exporter

go mod init exporter
go mod tidy
go build -o exporter


Simple Prometheus exporter in Go supporting TLS for the metrics endpoint
and both TLS and plain HTTP when calling upstream endpoints.

Features:
- Serve /metrics over HTTP or HTTPS (if -tls-cert and -tls-key are provided)
- Load endpoints from a YAML config file (see example below)
- For each endpoint: optional InsecureSkipVerify, optional client cert/key, optional CA
- Periodically poll endpoints and export metrics: endpoint_up and endpoint_response_seconds

Usage:
Create a config.yaml (example at bottom of file)
 Run (HTTP):  ./exporter -config config.yaml -listen ":9090"
 Or (HTTPS):   ./exporter -config config.yaml -listen ":9443" -tls-cert server.crt -tls-key server.key

Note: this file is intentionally self-contained and small; adapt error handling
and features (auth, retries, concurrency limits) as needed for production.
