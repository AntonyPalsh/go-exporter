package main

import (
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

	"gopkg.in/yaml.v3"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var version string = "1.0.1"

// Config structures
type Config struct {
	PollInterval string     `yaml:"poll_interval"`
	Endpoints    []Endpoint `yaml:"endpoints"`
	ClientCert   string     `yaml:"client_cert"`
	ClientKey    string     `yaml:"client_key"`
	CA           string     `yaml:"ca"`
}

type Endpoint struct {
	Name               string `yaml:"name"`
	URL                string `yaml:"url"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
	TlsEnable          bool   `yaml:"TLS_enable"`
	TimeoutSeconds     int    `yaml:"timeout_seconds"`
}

var (
	endpointUp = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "exporter_endpoint_up",
			Help: "Whether the endpoint is up (1) or down (0)",
		},
		[]string{"endpoint", "url"},
	)

	endpointRespSeconds = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "exporter_endpoint_response_seconds",
			Help: "Last response time in seconds for the endpoint",
		},
		[]string{"endpoint", "url"},
	)

	endpointRespCode = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "exporter_endpoint_response_code",
			Help: "Response code HTTP for the endpoint",
		},
		[]string{"endpoint", "url"},
	)
)

func init() {
	prometheus.MustRegister(endpointUp)
	prometheus.MustRegister(endpointRespSeconds)
	prometheus.MustRegister(endpointRespCode)
}

func loadConfig(path string) (*Config, error) {
	// byteFile, err := ioutil.ReadFile(path)
	byteFile, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var config Config
	if err := yaml.Unmarshal(byteFile, &config); err != nil {
		return nil, err
	}
	return &config, nil
}

// buildHTTPClient creates an http.Client configured for the endpoint (TLS options, client cert, CA)
func buildHTTPClient(endpoint Endpoint, config Config) (*http.Client, error) {
	tlsConfig := &tls.Config{}
	// CA
	if config.CA != "" {
		// caBytes, err := ioutil.ReadFile(e.CA)
		caBytes, err := os.ReadFile(config.CA)
		if err != nil {
			return nil, fmt.Errorf("reading CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caBytes) {
			return nil, fmt.Errorf("failed to append CA certs from %s", config.CA)
		}
		tlsConfig.RootCAs = pool
	}

	if endpoint.TlsEnable {
		cert, err := tls.LoadX509KeyPair(config.ClientCert, config.ClientKey)
		if err != nil {
			return nil, fmt.Errorf("loading client cert/key: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	if endpoint.InsecureSkipVerify {
		tlsConfig.InsecureSkipVerify = true
	}

	transport := &http.Transport{TLSClientConfig: tlsConfig}
	client := &http.Client{Transport: transport}
	if endpoint.TimeoutSeconds > 0 {
		client.Timeout = time.Duration(endpoint.TimeoutSeconds) * time.Second
	} else {
		client.Timeout = 10 * time.Second
	}
	return client, nil
}

func pollEndpoint(endpoint Endpoint, client *http.Client, wg *sync.WaitGroup) {
	defer wg.Done()
	start := time.Now()
	resp, err := client.Get(endpoint.URL)
	elapsed := time.Since(start).Seconds()
	labels := prometheus.Labels{"endpoint": endpoint.Name, "url": endpoint.URL}
	if err != nil {
		log.Printf("error fetching %s (%s): %v", endpoint.Name, endpoint.URL, err)
		endpointUp.With(labels).Set(0)
		endpointRespSeconds.With(labels).Set(elapsed)
		endpointRespCode.With(labels).Set(0)
		return
	}
	defer resp.Body.Close()
	// Drain body (avoid leaks)
	// _, _ = io.Copy(ioutil.Discard, resp.Body)
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		endpointUp.With(labels).Set(1)
	} else {
		endpointUp.With(labels).Set(0)
	}
	endpointRespSeconds.With(labels).Set(elapsed)
	endpointRespCode.With(labels).Set(float64(resp.StatusCode))
}

func startPolling(cfg *Config) {
	interval := 15 * time.Second
	if cfg.PollInterval != "" {
		d, err := time.ParseDuration(cfg.PollInterval)
		if err == nil {
			interval = d
		} else {
			log.Printf("invalid poll_interval %q, using default %s", cfg.PollInterval, interval)
		}
	}

	// Pre-create clients for endpoints
	clients := make([]*http.Client, len(cfg.Endpoints))
	for i, endpoint := range cfg.Endpoints {
		config, err := buildHTTPClient(endpoint, *cfg)
		if err != nil {
			log.Fatalf("failed to build http client for endpoint %s: %v", endpoint.Name, err)
		}
		clients[i] = config
	}

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		// immediate first round
		for i := range cfg.Endpoints {
			wg := &sync.WaitGroup{}
			wg.Add(1)
			go pollEndpoint(cfg.Endpoints[i], clients[i], wg)
			wg.Wait()
		}
		for range ticker.C {
			var wg sync.WaitGroup
			for i := range cfg.Endpoints {
				wg.Add(1)
				go pollEndpoint(cfg.Endpoints[i], clients[i], &wg)
			}
			wg.Wait()
		}
	}()
}

func main() {
	var (
		configPath = flag.String("config", "config.yaml", "Path to config YAML")
		listenAddr = flag.String("listen", ":9090", "Address to listen on for Prometheus (e.g. 0.0.0.0:9090)")
		tlsCert    = flag.String("cert", "", "TLS certificate file for /metrics (optional)")
		tlsKey     = flag.String("key", "", "TLS key file for /metrics (optional)")
	)

	// Show version
	flag.Func("version", version, func(s string) error {
		return nil
	})

	flag.Parse()

	cfg, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	startPolling(cfg)

	http.Handle("/metrics", promhttp.Handler())
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Exporter: /metrics\n"))
	})

	log.Printf("starting exporter on %s (tls: %v)", *listenAddr, *tlsCert != "" && *tlsKey != "")
	if *tlsCert != "" && *tlsKey != "" {
		if err := http.ListenAndServeTLS(*listenAddr, *tlsCert, *tlsKey, nil); err != nil {
			log.Fatalf("failed to start https server: %v", err)
		}
	} else {
		if err := http.ListenAndServe(*listenAddr, nil); err != nil {
			log.Fatalf("failed to start http server: %v", err)
		}
	}
}
