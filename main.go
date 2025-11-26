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

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"gopkg.in/yaml.v3"
)

// version - переменная для хранения версии приложения
var version string = "1.0.1"

// ============================================
// СТРУКТУРЫ ДАННЫХ
// ============================================

// Config - структура для хранения конфигурации приложения
// Содержит интервал опроса, список эндпоинтов и параметры TLS
type Config struct {
	PollInterval string     `yaml:"poll_interval"` // Интервал между опросами в формате time.Duration (e.g. "10s", "1m")
	Endpoints    []Endpoint `yaml:"endpoints"`     // Список эндпоинтов для мониторинга
	ClientCert   string     `yaml:"client_cert"`   // Путь к сертификату клиента для mTLS
	ClientKey    string     `yaml:"client_key"`    // Путь к приватному ключу клиента для mTLS
	CA           string     `yaml:"ca"`            // Путь к файлу CA сертификата для проверки сервера
}

// Endpoint - структура для описания одного эндпоинта, который необходимо мониторить
type Endpoint struct {
	Name               string `yaml:"name"`                 // Человеческое имя эндпоинта для логов и метрик
	URL                string `yaml:"url"`                  // Полный URL эндпоинта (e.g. https://example.com/health)
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"` // Флаг для пропуска проверки SSL сертификата (небезопасно)
	TlsEnable          bool   `yaml:"TLS_enable"`           // Флаг для включения/отключения TLS
	TimeoutSeconds     int    `yaml:"timeout_seconds"`      // Timeout для HTTP запроса в секундах
}

// ============================================
// PROMETHEUS МЕТРИКИ
// ============================================

// endpointUp - метрика Prometheus (Gauge) для отслеживания статуса эндпоинта
// Значение 1 = эндпоинт работает, 0 = эндпоинт не доступен
// Метки: "endpoint" (имя) и "url" (адрес)
var endpointUp = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "exporter_endpoint_up",
		Help: "Whether the endpoint is up (1) or down (0)",
	},
	[]string{"endpoint", "url"},
)

// endpointRespSeconds - метрика Prometheus (Gauge) для отслеживания времени ответа эндпоинта
// Хранит время ответа в секундах (float64)
// Метки: "endpoint" (имя) и "url" (адрес)
var endpointRespSeconds = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "exporter_endpoint_response_seconds",
		Help: "Last response time in seconds for the endpoint",
	},
	[]string{"endpoint", "url"},
)

// endpointRespCode - метрика Prometheus (Gauge) для отслеживания HTTP кода ответа эндпоинта
// Хранит последний полученный HTTP статус код (200, 404, 500 и т.д.)
// Метки: "endpoint" (имя) и "url" (адрес)
var endpointRespCode = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "exporter_endpoint_response_code",
		Help: "Response code HTTP for the endpoint",
	},
	[]string{"endpoint", "url"},
)

// ============================================
// ИНИЦИАЛИЗАЦИЯ
// ============================================

// init - функция инициализации, вызывается автоматически перед main()
// Регистрирует все Prometheus метрики в глобальном реестре
func init() {
	prometheus.MustRegister(endpointUp)          // Регистрируем метрику статуса эндпоинта
	prometheus.MustRegister(endpointRespSeconds) // Регистрируем метрику времени ответа
	prometheus.MustRegister(endpointRespCode)    // Регистрируем метрику HTTP кода ответа
}

// ============================================
// ФУНКЦИИ
// ============================================

// loadConfig - загружает конфигурацию приложения из YAML файла
// Параметры:
//   - path: строка с путем до файла конфигурации
//
// Возвращает:
//   - указатель на структуру Config
//   - ошибку (если что-то пошло не так при чтении или парсинге)
func loadConfig(path string) (*Config, error) {
	// Читаем содержимое файла в байты
	byteFile, err := os.ReadFile(path)
	if err != nil {
		return nil, err // Возвращаем ошибку, если не можем прочитать файл
	}

	// Создаем пустую структуру Config
	var config Config

	// Парсим YAML из прочитанных байтов в структуру Config
	if err := yaml.Unmarshal(byteFile, &config); err != nil {
		return nil, err // Возвращаем ошибку, если парсинг YAML не удался
	}

	// Возвращаем успешно загруженную конфигурацию
	return &config, nil
}

// buildHTTPClient - создает и конфигурирует HTTP клиент для работы с конкретным эндпоинтом
// Параметры:
//   - endpoint: структура Endpoint с параметрами конкретного эндпоинта
//   - config: структура Config с глобальными параметрами (пути к сертификатам и ключам)
//
// Возвращает:
//   - указатель на http.Client, готовый к использованию
//   - ошибку (если не удалось загрузить сертификаты или ключи)
func buildHTTPClient(endpoint Endpoint, config Config) (*http.Client, error) {
	// Создаем новую TLS конфигурацию (изначально пустую)
	tlsConfig := &tls.Config{}

	// ===== Настройка CA сертификата для проверки сервера =====
	if config.CA != "" {
		// Читаем CA сертификат из файла
		caBytes, err := os.ReadFile(config.CA)
		if err != nil {
			return nil, fmt.Errorf("reading CA file: %w", err)
		}

		// Создаем новый пул сертификатов
		pool := x509.NewCertPool()

		// Добавляем CA сертификат в пул
		if !pool.AppendCertsFromPEM(caBytes) {
			return nil, fmt.Errorf("failed to append CA certs from %s", config.CA)
		}

		// Устанавливаем пул как корневой для проверки серверного сертификата
		tlsConfig.RootCAs = pool
	}

	// ===== Настройка клиентского сертификата (mTLS) =====
	if endpoint.TlsEnable {
		// Загружаем пару сертификат+ключ клиента
		cert, err := tls.LoadX509KeyPair(config.ClientCert, config.ClientKey)
		if err != nil {
			return nil, fmt.Errorf("loading client cert/key: %w", err)
		}

		// Добавляем клиентский сертификат в TLS конфигурацию
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	// ===== Настройка опции пропуска проверки SSL =====
	if endpoint.InsecureSkipVerify {
		// ВНИМАНИЕ: Небезопасная опция! Отключает проверку SSL сертификата сервера
		tlsConfig.InsecureSkipVerify = true
	}

	// ===== Создание HTTP клиента =====
	// Создаем транспорт с нашей TLS конфигурацией
	transport := &http.Transport{TLSClientConfig: tlsConfig}

	// Создаем HTTP клиент с этим транспортом
	client := &http.Client{Transport: transport}

	// ===== Настройка timeout =====
	if endpoint.TimeoutSeconds > 0 {
		// Если timeout задан в конфигурации, используем его
		client.Timeout = time.Duration(endpoint.TimeoutSeconds) * time.Second
	} else {
		// Иначе используем timeout по умолчанию - 10 секунд
		client.Timeout = 10 * time.Second
	}

	return client, nil
}

// pollEndpoint - опрашивает один эндпоинт и обновляет метрики
// Параметры:
//   - endpoint: структура Endpoint для опроса
//   - client: HTTP клиент для выполнения запроса
//   - wg: WaitGroup для синхронизации горутин
func pollEndpoint(endpoint Endpoint, client *http.Client, wg *sync.WaitGroup) {
	// Автоматически отметить WaitGroup как завершенный при выходе из функции
	defer wg.Done()

	// Запоминаем время начала опроса
	start := time.Now()

	// Выполняем GET запрос к эндпоинту
	resp, err := client.Get(endpoint.URL)

	// Вычисляем время ответа в секундах
	elapsed := time.Since(start).Seconds()

	// Создаем метки для этого эндпоинта (используются для всех метрик)
	labels := prometheus.Labels{"endpoint": endpoint.Name, "url": endpoint.URL}

	// ===== Обработка ошибок при запросе =====
	if err != nil {
		// Логируем ошибку
		log.Printf("error fetching %s (%s): %v", endpoint.Name, endpoint.URL, err)

		// Устанавливаем метрику: эндпоинт недоступен (0)
		endpointUp.With(labels).Set(0)

		// Записываем время, за которое произошла ошибка
		endpointRespSeconds.With(labels).Set(elapsed)

		// Устанавливаем код ответа в 0 (нет ответа)
		endpointRespCode.With(labels).Set(0)

		return // Выходим из функции
	}

	// ===== Обработка успешного ответа =====
	// Закрываем тело ответа после завершения функции
	defer resp.Body.Close()

	// Читаем и выбрасываем тело ответа, чтобы избежать утечек памяти
	// это важно для переиспользования соединения в http.Client
	_, _ = io.Copy(io.Discard, resp.Body)

	// Проверяем статус код ответа
	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		// Если статус успешный (2xx или 3xx), устанавливаем метрику в 1 (эндпоинт работает)
		endpointUp.With(labels).Set(1)
	} else {
		// Иначе устанавливаем метрику в 0 (эндпоинт не работает)
		endpointUp.With(labels).Set(0)
	}

	// Записываем время ответа
	endpointRespSeconds.With(labels).Set(elapsed)

	// Записываем полученный HTTP статус код
	endpointRespCode.With(labels).Set(float64(resp.StatusCode))
}

// startPolling - запускает фоновый процесс периодического опроса всех эндпоинтов
// Параметры:
//   - cfg: указатель на структуру Config с конфигурацией приложения
func startPolling(cfg *Config) {
	// Устанавливаем интервал опроса по умолчанию - 15 секунд
	interval := 15 * time.Second

	// Если в конфигурации задан интервал, пытаемся его распарсить
	if cfg.PollInterval != "" {
		// Парсим строку интервала (e.g. "30s", "1m", "5m30s")
		d, err := time.ParseDuration(cfg.PollInterval)
		if err == nil {
			// Если парсинг успешен, используем загруженный интервал
			interval = d
		} else {
			// Если парсинг не удался, логируем ошибку и используем значение по умолчанию
			log.Printf("invalid poll_interval %q, using default %s", cfg.PollInterval, interval)
		}
	}

	// ===== Предварительное создание HTTP клиентов =====
	// Создаем массив HTTP клиентов для каждого эндпоинта
	clients := make([]*http.Client, len(cfg.Endpoints))

	// Для каждого эндпоинта создаем настроенный HTTP клиент
	for i, endpoint := range cfg.Endpoints {
		// Строим HTTP клиент для этого эндпоинта
		config, err := buildHTTPClient(endpoint, *cfg)
		if err != nil {
			// Если создание клиента не удалось, аварийно завершаем приложение
			log.Fatalf("failed to build http client for endpoint %s: %v", endpoint.Name, err)
		}

		// Сохраняем созданный клиент в массиве
		clients[i] = config
	}

	// ===== Запуск горутины для периодического опроса =====
	go func() {
		// Создаем ticker для периодического срабатывания
		ticker := time.NewTicker(interval)

		// Гарантируем остановку ticker при выходе из функции
		defer ticker.Stop()

		// ===== Первый немедленный опрос всех эндпоинтов =====
		for i := range cfg.Endpoints {
			// Создаем WaitGroup для синхронизации этого раунда опроса
			wg := &sync.WaitGroup{}

			// Добавляем одну горутину в WaitGroup
			wg.Add(1)

			// Запускаем опрос эндпоинта в отдельной горутине
			go pollEndpoint(cfg.Endpoints[i], clients[i], wg)

			// Ждем завершения опроса перед переходом к следующему
			wg.Wait()
		}

		// ===== Периодический опрос по таймеру =====
		for range ticker.C {
			// Создаем WaitGroup для синхронизации всех эндпоинтов в этом раунде
			var wg sync.WaitGroup

			// Для каждого эндпоинта запускаем опрос в отдельной горутине
			for i := range cfg.Endpoints {
				// Добавляем горутину в WaitGroup
				wg.Add(1)

				// Запускаем опрос параллельно
				go pollEndpoint(cfg.Endpoints[i], clients[i], &wg)
			}

			// Ждем завершения всех опросов в этом раунде
			wg.Wait()
		}
	}()
}

// ============================================
// MAIN
// ============================================

// main - главная функция приложения
// Инициализирует конфигурацию, запускает опрос эндпоинтов и HTTP сервер для Prometheus
func main() {
	// ===== Определение флагов команднной строки =====
	var (
		// configPath - путь до файла конфигурации (по умолчанию "config.yaml")
		configPath = flag.String("config", "config.yaml", "Path to config YAML")

		// listenAddr - адрес и порт для запуска HTTP сервера (по умолчанию ":9090")
		listenAddr = flag.String("listen", ":9090", "Address to listen on for Prometheus (e.g. 0.0.0.0:9090)")

		// tlsCert - путь до TLS сертификата для /metrics эндпоинта (опционально)
		tlsCert = flag.String("cert", "", "TLS certificate file for /metrics (optional)")

		// tlsKey - путь до приватного ключа TLS для /metrics эндпоинта (опционально)
		tlsKey = flag.String("key", "", "TLS key file for /metrics (optional)")
	)

	// ===== Флаг для показа версии =====
	flag.Func("version", version, func(s string) error {
		// Выводим версию и возвращаем nil (флаг обработан)
		return nil
	})

	// Парсим флаги команднной строки
	flag.Parse()

	// ===== Загрузка конфигурации =====
	// Загружаем конфигурацию из файла
	cfg, err := loadConfig(*configPath)
	if err != nil {
		// Если загрузка не удалась, выводим ошибку и завершаем приложение
		log.Fatalf("failed to load config: %v", err)
	}

	// ===== Запуск периодического опроса эндпоинтов =====
	startPolling(cfg)

	// ===== Регистрация HTTP обработчиков =====
	// Регистрируем /metrics обработчик для Prometheus
	http.Handle("/metrics", promhttp.Handler())

	// Регистрируем корневой / обработчик для вывода справки
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Exporter: /metrics\n"))
	})

	// ===== Запуск HTTP сервера =====
	// Логируем информацию о запуске сервера
	log.Printf("starting exporter on %s (tls: %v)", *listenAddr, *tlsCert != "" && *tlsKey != "")

	// Проверяем, нужно ли запускать HTTPS сервер
	if *tlsCert != "" && *tlsKey != "" {
		// Запускаем HTTPS сервер с TLS
		if err := http.ListenAndServeTLS(*listenAddr, *tlsCert, *tlsKey, nil); err != nil {
			// Если сервер не удалось запустить, выводим ошибку
			log.Fatalf("failed to start https server: %v", err)
		}
	} else {
		// Запускаем обычный HTTP сервер без TLS
		if err := http.ListenAndServe(*listenAddr, nil); err != nil {
			// Если сервер не удалось запустить, выводим ошибку
			log.Fatalf("failed to start http server: %v", err)
		}
	}
}
