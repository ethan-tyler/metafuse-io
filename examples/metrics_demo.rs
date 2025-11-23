//! Metrics demonstration
//!
//! This example shows how to use the MetaFuse API with Prometheus metrics enabled.
//!
//! Run the API server with metrics:
//! ```sh
//! cargo run --features metrics -p metafuse-catalog-api
//! ```
//!
//! Then visit http://localhost:8080/metrics to see the Prometheus metrics.
//!
//! This example emits some sample datasets and then queries the metrics endpoint.

use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    println!("=== MetaFuse Metrics Demo ===\n");

    println!("1. Start the API server with metrics enabled:");
    println!("   cargo run --features metrics -p metafuse-catalog-api\n");

    println!("2. Emit some sample datasets:");
    println!("   cargo run -p metafuse-catalog-cli -- emit sample_dataset data.parquet parquet\n");

    println!("3. Make some API calls:");
    println!("   curl http://localhost:8080/api/v1/datasets");
    println!("   curl http://localhost:8080/api/v1/datasets/sample_dataset");
    println!("   curl 'http://localhost:8080/api/v1/search?q=sample'\n");

    println!("4. View Prometheus metrics:");
    println!("   curl http://localhost:8080/metrics\n");

    println!("Expected metrics:");
    println!("  - http_requests_total{{method,path,status}}");
    println!("  - http_request_duration_seconds{{method,path}}");
    println!("  - catalog_operations_total{{operation,status}}");
    println!("  - catalog_datasets_total\n");

    println!("5. Optional: Configure Prometheus to scrape the /metrics endpoint");
    println!("   Add to prometheus.yml:");
    println!("   scrape_configs:");
    println!("     - job_name: 'metafuse'");
    println!("       static_configs:");
    println!("         - targets: ['localhost:8080']");

    Ok(())
}
