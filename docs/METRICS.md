# Prometheus Metrics

MetaFuse Catalog API supports optional Prometheus metrics for monitoring and observability.

## Enabling Metrics

Metrics are **opt-in** and disabled by default. To enable metrics, build and run the API server with the `metrics` feature:

```bash
# Build with metrics
cargo build --features metrics -p metafuse-catalog-api

# Run with metrics
cargo run --features metrics -p metafuse-catalog-api
```

When the metrics feature is enabled, the `/metrics` endpoint becomes available.

## Available Metrics

### HTTP Request Metrics

**`http_requests_total`** (Counter)
- Total number of HTTP requests
- Labels: `method`, `path`, `status`
- Example: `http_requests_total{method="GET",path="/api/v1/datasets",status="200"} 42`

**`http_request_duration_seconds`** (Histogram)
- HTTP request latency distribution in seconds
- Labels: `method`, `path`
- Buckets: 1ms, 5ms, 10ms, 25ms, 50ms, 100ms, 250ms, 500ms, 1s, 2.5s, 5s, 10s
- Example: `http_request_duration_seconds_bucket{method="GET",path="/api/v1/datasets",le="0.1"} 40`

### Catalog Operation Metrics

**`catalog_operations_total`** (Counter)
- Total number of catalog operations
- Labels: `operation`, `status`
- Operations tracked: `list_datasets`, `get_dataset`, `search_datasets`
- Example: `catalog_operations_total{operation="list_datasets",status="success"} 15`

**`catalog_datasets_total`** (Gauge)
- Total number of datasets in the catalog
- No labels
- Example: `catalog_datasets_total 127`

## Usage Examples

### Query the metrics endpoint

```bash
curl http://localhost:8080/metrics
```

### Sample Prometheus output

```prometheus
# HELP http_requests_total Total number of HTTP requests
# TYPE http_requests_total counter
http_requests_total{method="GET",path="/api/v1/datasets",status="200"} 150
http_requests_total{method="GET",path="/api/v1/datasets/:name",status="200"} 45
http_requests_total{method="GET",path="/api/v1/datasets/:name",status="404"} 2
http_requests_total{method="GET",path="/api/v1/search",status="200"} 30
http_requests_total{method="GET",path="/health",status="200"} 500

# HELP http_request_duration_seconds HTTP request latency in seconds
# TYPE http_request_duration_seconds histogram
http_request_duration_seconds_bucket{method="GET",path="/api/v1/datasets",le="0.01"} 120
http_request_duration_seconds_bucket{method="GET",path="/api/v1/datasets",le="0.05"} 145
http_request_duration_seconds_bucket{method="GET",path="/api/v1/datasets",le="0.1"} 150
http_request_duration_seconds_sum{method="GET",path="/api/v1/datasets"} 3.25
http_request_duration_seconds_count{method="GET",path="/api/v1/datasets"} 150

# HELP catalog_operations_total Total number of catalog operations
# TYPE catalog_operations_total counter
catalog_operations_total{operation="list_datasets",status="success"} 150
catalog_operations_total{operation="get_dataset",status="success"} 45
catalog_operations_total{operation="search_datasets",status="success"} 30

# HELP catalog_datasets_total Total number of datasets in the catalog
# TYPE catalog_datasets_total gauge
catalog_datasets_total 127
```

## Prometheus Configuration

### Basic scrape configuration

Add the following to your `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'metafuse-catalog-api'
    scrape_interval: 15s
    static_configs:
      - targets: ['localhost:8080']
```

### Docker Compose example

```yaml
version: '3.8'
services:
  metafuse-api:
    build:
      context: .
      args:
        CARGO_FEATURES: metrics
    ports:
      - "8080:8080"
    environment:
      METAFUSE_CATALOG_PATH: /data/catalog.db
    volumes:
      - metafuse-data:/data

  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus-data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'

  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
    volumes:
      - grafana-data:/var/lib/grafana
    depends_on:
      - prometheus

volumes:
  metafuse-data:
  prometheus-data:
  grafana-data:
```

## Grafana Dashboard

### Sample queries for Grafana

**Request rate (req/sec)**
```promql
rate(http_requests_total[5m])
```

**Request latency p95**
```promql
histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))
```

**Request latency p99**
```promql
histogram_quantile(0.99, rate(http_request_duration_seconds_bucket[5m]))
```

**Error rate**
```promql
rate(http_requests_total{status=~"5.."}[5m])
```

**Catalog operation rate**
```promql
rate(catalog_operations_total[5m])
```

**Total datasets**
```promql
catalog_datasets_total
```

### Example Grafana panels

1. **Requests per Second** (Graph)
   - Query: `rate(http_requests_total[5m])`
   - Legend: `{{method}} {{path}} {{status}}`

2. **Request Latency** (Graph)
   - Query: `histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))`
   - Legend: `p95 {{path}}`

3. **Total Datasets** (Stat)
   - Query: `catalog_datasets_total`

4. **Catalog Operations** (Graph)
   - Query: `rate(catalog_operations_total[5m])`
   - Legend: `{{operation}}`

## Security Considerations

### Production deployment

The `/metrics` endpoint exposes operational metadata about your API. In production:

1. **Restrict access**: Use network policies or reverse proxy rules to limit access to the `/metrics` endpoint
2. **Authentication**: Consider placing the API behind a reverse proxy (e.g., nginx) with authentication for `/metrics`
3. **Rate limiting**: Configure Prometheus scrape intervals appropriately (default: 15s)
4. **Monitoring**: Set up alerting rules for anomalies in request rates or error rates

### Example nginx configuration

```nginx
server {
    listen 80;
    server_name metafuse-api.example.com;

    # Public API endpoints
    location /api/ {
        proxy_pass http://localhost:8080;
    }

    location /health {
        proxy_pass http://localhost:8080;
    }

    # Metrics endpoint - restricted to internal network
    location /metrics {
        allow 10.0.0.0/8;  # Internal network
        deny all;
        proxy_pass http://localhost:8080;
    }
}
```

## Performance Impact

The metrics feature has minimal performance overhead:

- **Memory**: ~100 KB for metric storage (varies with cardinality)
- **CPU**: <1% overhead for metric collection
- **Latency**: ~10-50 microseconds per request

These numbers are based on benchmarks with the SQLite backend under typical load.

## Troubleshooting

### Metrics endpoint returns 404

Ensure you built and ran the API server with the `metrics` feature enabled:

```bash
cargo run --features metrics -p metafuse-catalog-api
```

### High cardinality warnings

If you see warnings about high cardinality in Prometheus, it may be due to:

- Too many unique paths (e.g., dataset names in the URL path)
- MetaFuse uses matched paths (e.g., `/api/v1/datasets/:name`) to avoid this issue

### Missing metrics after restart

Prometheus metrics are **in-memory only** and reset on API server restart. Historical data is preserved in Prometheus' time-series database.

## Further Reading

- [Prometheus Documentation](https://prometheus.io/docs/)
- [Grafana Documentation](https://grafana.com/docs/)
- [PromQL Query Language](https://prometheus.io/docs/prometheus/latest/querying/basics/)
- [Prometheus Best Practices](https://prometheus.io/docs/practices/naming/)
