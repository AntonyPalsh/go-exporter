package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/expfmt"
	"gopkg.in/yaml.v3"
)

// version - variable to store the application version
var version string = "1.1.0"

// ============================================
// DATA STRUCTURES
// ============================================

// Config - structure for storing application configuration
// Contains poll interval, list of endpoints, and TLS parameters
type Config struct {
	PollInterval string     `yaml:"poll_interval"` // Poll interval in time.Duration format (e.g. "10s", "1m")
	Endpoints    []Endpoint `yaml:"endpoints"`     // List of endpoints to monitor
	ClientCert   string     `yaml:"client_cert"`   // Path to client certificate for mTLS
	ClientKey    string     `yaml:"client_key"`    // Path to client private key for mTLS
	CA           string     `yaml:"ca"`            // Path to CA certificate file for server verification
}

// Endpoint - structure for describing a single endpoint to monitor
type Endpoint struct {
	Name               string `yaml:"name"`                 // Human-readable endpoint name for logs and metrics
	URL                string `yaml:"url"`                  // Full URL of the endpoint (e.g. https://example.com/health)
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"` // Flag to skip SSL certificate verification (insecure)
	TlsEnable          bool   `yaml:"TLS_enable"`           // Flag to enable/disable TLS
	TimeoutSeconds     int    `yaml:"timeout_seconds"`      // HTTP request timeout in seconds
}

// ============================================
// PROMETHEUS METRICS
// ============================================

// endpointUp - Prometheus metric (Gauge) for tracking endpoint status
// Value 1 = endpoint is up, 0 = endpoint is down
// Labels: "endpoint" (name) and "url" (address)
var endpointUp = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "exporter_endpoint_up",
		Help: "Whether the endpoint is up (1) or down (0)",
	},
	[]string{"endpoint", "url"},
)

// endpointRespSeconds - Prometheus metric (Gauge) for tracking endpoint response time
// Stores response time in seconds (float64)
// Labels: "endpoint" (name) and "url" (address)
var endpointRespSeconds = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "exporter_endpoint_response_seconds",
		Help: "Last response time in seconds for the endpoint",
	},
	[]string{"endpoint", "url"},
)

// endpointRespCode - Prometheus metric (Gauge) for tracking HTTP response code of endpoint
// Stores the last received HTTP status code (200, 404, 500, etc.)
// Labels: "endpoint" (name) and "url" (address)
var endpointRespCode = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "exporter_endpoint_response_code",
		Help: "HTTP response code for the endpoint",
	},
	[]string{"endpoint", "url"},
)

// ============================================
// INITIALIZATION
// ============================================

// init - initialization function, called automatically before main()
// Registers all Prometheus metrics in the global registry
func init() {
	prometheus.MustRegister(endpointUp)          // Register endpoint status metric
	prometheus.MustRegister(endpointRespSeconds) // Register response time metric
	prometheus.MustRegister(endpointRespCode)    // Register HTTP response code metric
}

// ============================================
// FUNCTIONS
// ============================================

// writeMetricsToTextfile serializes all metrics from the registry to Prometheus text format
// and atomically writes them to the specified file (for node_exporter textfile collector)
func writeMetricsToTextfile(path string) error {
	if path == "" {
		return nil
	}

	// Gather all metrics from the default registry
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		return fmt.Errorf("gather metrics: %w", err)
	}

	var buf bytes.Buffer
	enc := expfmt.NewEncoder(&buf, expfmt.FmtText)

	// Encode each metric to text format
	for _, mf := range mfs {
		if err := enc.Encode(mf); err != nil {
			return fmt.Errorf("encode metric: %w", err)
		}
	}

	// Atomic write: first to temporary file, then rename
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, buf.Bytes(), 0o644); err != nil {
		return fmt.Errorf("write tmp file: %w", err)
	}

	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("rename tmp file: %w", err)
	}

	return nil
}

// loadConfig - loads application configuration from YAML file
// Parameters:
// - path: string with path to config file
//
// Returns:
// - pointer to Config structure
// - error (if something went wrong during reading or parsing)
func loadConfig(path string) (*Config, error) {
	// Read file contents into bytes
	byteFile, err := os.ReadFile(path)
	if err != nil {
		return nil, err // Return error if we can't read the file
	}

	// Create empty Config structure
	var config Config

	// Parse YAML from read bytes into Config structure
	if err := yaml.Unmarshal(byteFile, &config); err != nil {
		return nil, err // Return error if YAML parsing failed
	}

	// Return successfully loaded configuration
	return &config, nil
}

// buildHTTPClient - creates and configures HTTP client for specific endpoint
// Parameters:
// - endpoint: Endpoint structure with specific endpoint parameters
// - config: Config structure with global parameters (certificate and key paths)
//
// Returns:
// - pointer to ready-to-use http.Client
// - error (if failed to load certificates or keys)
func buildHTTPClient(endpoint Endpoint, config Config) (*http.Client, error) {
	// Create new TLS configuration (initially empty)
	tlsConfig := &tls.Config{}

	// ===== CA certificate setup for server verification =====
	if config.CA != "" {
		// Read CA certificate from file
		caBytes, err := os.ReadFile(config.CA)
		if err != nil {
			return nil, fmt.Errorf("reading CA file: %w", err)
		}

		// Create new certificate pool
		pool := x509.NewCertPool()
		// Add CA certificate to pool
		if !pool.AppendCertsFromPEM(caBytes) {
			return nil, fmt.Errorf("failed to append CA certs from %s", config.CA)
		}

		// Set pool as root for server certificate verification
		tlsConfig.RootCAs = pool
	}

	// ===== Client certificate setup (mTLS) =====
	if endpoint.TlsEnable {
		// Load client certificate+key pair
		cert, err := tls.LoadX509KeyPair(config.ClientCert, config.ClientKey)
		if err != nil {
			return nil, fmt.Errorf("loading client cert/key: %w", err)
		}

		// Add client certificate to TLS configuration
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	// ===== SSL verification skip option setup =====
	if endpoint.InsecureSkipVerify {
		// WARNING: Insecure option! Disables server SSL certificate verification
		tlsConfig.InsecureSkipVerify = true
	}

	// ===== HTTP client creation =====
	// Create transport with our TLS configuration
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	// Create HTTP client with this transport
	client := &http.Client{Transport: transport}

	// ===== Timeout setup =====
	if endpoint.TimeoutSeconds > 0 {
		// If timeout specified in config, use it
		client.Timeout = time.Duration(endpoint.TimeoutSeconds) * time.Second
	} else {
		// Otherwise use default timeout - 10 seconds
		client.Timeout = 10 * time.Second
	}

	return client, nil
}

// pollEndpoint - polls a single endpoint and updates metrics
// Parameters:
// - endpoint: Endpoint structure to poll
// - client: HTTP client for making the request
// - wg: WaitGroup for goroutine synchronization
func pollEndpoint(endpoint Endpoint, client *http.Client, wg *sync.WaitGroup) {
	// Automatically mark WaitGroup as done when exiting the function
	defer wg.Done()

	// Record poll start time
	start := time.Now()

	// Make GET request to endpoint
	resp, err := client.Get(endpoint.URL)

	// Calculate response time in seconds
	elapsed := time.Since(start).Seconds()

	// Create labels for this endpoint (used for all metrics)
	labels := prometheus.Labels{"endpoint": endpoint.Name, "url": endpoint.URL}

	// ===== Error handling =====
	if err != nil {
		// Log error
		log.Printf("error fetching %s (%s): %v", endpoint.Name, endpoint.URL, err)
		// Set metric: endpoint is down (0)
		endpointUp.With(labels).Set(0)
		// Record time taken for error
		endpointRespSeconds.With(labels).Set(elapsed)
		// Set response code to 0 (no response)
		endpointRespCode.With(labels).Set(0)
		return // Exit function
	}

	// ===== Successful response handling =====
	// Close response body when function exits
	defer resp.Body.Close()

	// Read and discard response body to avoid memory leaks
	// This is important for connection reuse in http.Client
	_, _ = io.Copy(io.Discard, resp.Body)

	// Check response status code
	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		// If status is successful (2xx or 3xx), set metric to 1 (endpoint is working)
		endpointUp.With(labels).Set(1)
	} else {
		// Otherwise set metric to 0 (endpoint is not working)
		endpointUp.With(labels).Set(0)
	}

	// Record response time
	endpointRespSeconds.With(labels).Set(elapsed)
	// Record received HTTP status code
	endpointRespCode.With(labels).Set(float64(resp.StatusCode))
}

// startPolling - starts background process for periodic polling of all endpoints
// Parameters:
// - cfg: pointer to Config structure with application configuration
// - textfilePath: path to .prom file for node_exporter (if empty - no file writing)
func startPolling(cfg *Config, textfilePath string) {
	// Set default poll interval - 15 seconds
	interval := 15 * time.Second

	// If interval specified in config, try to parse it
	if cfg.PollInterval != "" {
		// Parse interval string (e.g. "30s", "1m", "5m30s")
		d, err := time.ParseDuration(cfg.PollInterval)
		if err == nil {
			// If parsing successful, use loaded interval
			interval = d
		} else {
			// If parsing failed, log error and use default value
			log.Printf("invalid poll_interval %q, using default %s", cfg.PollInterval, interval)
		}
	}

	// ===== Pre-create HTTP clients =====
	// Create array of HTTP clients for each endpoint
	clients := make([]*http.Client, len(cfg.Endpoints))

	// Create configured HTTP client for each endpoint
	for i, endpoint := range cfg.Endpoints {
		// Build HTTP client for this endpoint
		client, err := buildHTTPClient(endpoint, *cfg)
		if err != nil {
			// If client creation failed, terminate application fatally
			log.Fatalf("failed to build http client for endpoint %s: %v", endpoint.Name, err)
		}

		// Save created client in array
		clients[i] = client
	}

	// ===== Start goroutine for periodic polling =====
	go func() {
		// Create ticker for periodic triggering
		ticker := time.NewTicker(interval)
		// Guarantee ticker stop when exiting function
		defer ticker.Stop()

		// ===== First immediate poll of all endpoints =====
		for i := range cfg.Endpoints {
			wg := &sync.WaitGroup{}
			wg.Add(1)
			// Start endpoint poll in separate goroutine
			go pollEndpoint(cfg.Endpoints[i], clients[i], wg)
			// Wait for poll completion before moving to next
			wg.Wait()
		}

		// After first poll, immediately write metrics to .prom (if enabled)
		if textfilePath != "" {
			if err := writeMetricsToTextfile(textfilePath); err != nil {
				log.Printf("failed to write metrics to %s: %v", textfilePath, err)
			}
		}

		// ===== Periodic polling by timer =====
		for range ticker.C {
			// Create WaitGroup for synchronizing all endpoints in this round
			var wg sync.WaitGroup

			// Start poll for each endpoint in separate goroutine
			for i := range cfg.Endpoints {
				// Add goroutine to WaitGroup
				wg.Add(1)
				// Start parallel poll
				go pollEndpoint(cfg.Endpoints[i], clients[i], &wg)
			}

			// Wait for completion of all polls in this round
			wg.Wait()

			// Update .prom file after each polling cycle
			if textfilePath != "" {
				if err := writeMetricsToTextfile(textfilePath); err != nil {
					log.Printf("failed to write metrics to %s: %v", textfilePath, err)
				}
			}
		}
	}()
}

// ============================================
// MAIN
// ============================================

// main - main application function
// Initializes configuration, starts endpoint polling and HTTP server for Prometheus
func main() {
	// ===== Command line flags definition =====
	var (
		// configPath - path to config file (default "config.yaml")
		configPath = flag.String("config", "config.yaml", "Path to config YAML")
		// listenAddr - address and port for HTTP server (default ":9090")
		listenAddr = flag.String("listen", ":9090", "Address to listen on for Prometheus (e.g. 0.0.0.0:9090)")
		// tlsCert - path to TLS certificate for /metrics endpoint (optional)
		tlsCert = flag.String("cert", "", "TLS certificate file for /metrics (optional)")
		// tlsKey - path to TLS private key for /metrics endpoint (optional)
		tlsKey = flag.String("key", "", "TLS key file for /metrics (optional)")
		// textfilePath - path to .prom file for node_exporter textfile collector
		textfilePath = flag.String("path-prom", "", "Path to .prom file for node_exporter (optional)")
	)

	// ===== Version flag =====
	flag.Func("version", version, func(s string) error {
		// Print version and return nil (flag processed)
		return nil
	})

	// Parse command line flags
	flag.Parse()

	// ===== Configuration loading =====
	// Load configuration from file
	cfg, err := loadConfig(*configPath)
	if err != nil {
		// If loading failed, print error and exit application
		log.Fatalf("failed to load config: %v", err)
	}

	// ===== Start periodic endpoint polling =====
	startPolling(cfg, *textfilePath)

	// ===== Register HTTP handlers =====
	// Register /metrics handler for Prometheus
	http.Handle("/metrics", promhttp.Handler())
	// Register root / handler for help output
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Exporter: /metrics\n"))
	})

	// ===== Start HTTP server =====
	// Log server startup information
	log.Printf("starting exporter on %s (tls: %v)", *listenAddr, *tlsCert != "" && *tlsKey != "")

	// Check if HTTPS server is needed
	if *tlsCert != "" && *tlsKey != "" {
		// Start HTTPS server with TLS
		if err := http.ListenAndServeTLS(*listenAddr, *tlsCert, *tlsKey, nil); err != nil {
			// If server failed to start, print error
			log.Fatalf("failed to start https server: %v", err)
		}
	} else {
		// Start plain HTTP server without TLS
		if err := http.ListenAndServe(*listenAddr, nil); err != nil {
			// If server failed to start, print error
			log.Fatalf("failed to start http server: %v", err)
		}
	}
}
