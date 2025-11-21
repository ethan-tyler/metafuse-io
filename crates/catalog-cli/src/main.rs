//! MetaFuse Catalog CLI
//!
//! Command-line interface for exploring and managing the MetaFuse catalog.

use clap::{Parser, Subcommand};
use metafuse_catalog_core::validation;
use metafuse_catalog_storage::backend_from_uri;

#[derive(Parser)]
#[command(name = "metafuse")]
#[command(version, about = "MetaFuse catalog CLI", long_about = None)]
struct Cli {
    /// Path to the catalog database
    #[arg(short, long, default_value = "metafuse_catalog.db", global = true)]
    catalog: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new catalog
    Init {
        /// Overwrite existing catalog if it exists
        #[arg(short, long)]
        force: bool,
    },

    /// List datasets in the catalog
    List {
        /// Filter by tenant
        #[arg(short, long)]
        tenant: Option<String>,

        /// Filter by domain
        #[arg(short, long)]
        domain: Option<String>,

        /// Show detailed information
        #[arg(short = 'v', long)]
        verbose: bool,
    },

    /// Show detailed information about a dataset
    Show {
        /// Name of the dataset
        name: String,

        /// Show lineage graph
        #[arg(short, long)]
        lineage: bool,
    },

    /// Search datasets
    Search {
        /// Search query
        query: String,
    },

    /// Show catalog statistics
    Stats,
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Init { force } => init_catalog(&cli.catalog, force),
        Commands::List {
            tenant,
            domain,
            verbose,
        } => list_datasets(&cli.catalog, tenant, domain, verbose),
        Commands::Show { name, lineage } => show_dataset(&cli.catalog, &name, lineage),
        Commands::Search { query } => search_datasets(&cli.catalog, &query),
        Commands::Stats => show_stats(&cli.catalog),
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

fn init_catalog(path: &str, force: bool) -> Result<(), Box<dyn std::error::Error>> {
    let backend = backend_from_uri(path)?;

    if backend.exists()? {
        if !force {
            return Err(format!(
                "Catalog already exists at '{}'. Use --force to overwrite.",
                path
            )
            .into());
        }
        println!("Removing existing catalog at '{}'", path);
        std::fs::remove_file(path)?;
    }

    backend.initialize()?;
    println!("Initialized catalog at '{}'", path);

    Ok(())
}

fn list_datasets(
    path: &str,
    tenant: Option<String>,
    domain: Option<String>,
    verbose: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let backend = backend_from_uri(path)?;
    let conn = backend.get_connection()?;

    let mut query = String::from(
        "SELECT name, path, format, description, tenant, domain, owner, last_updated, row_count, size_bytes FROM datasets WHERE 1=1",
    );

    let mut params: Vec<String> = Vec::new();

    if let Some(ref t) = tenant {
        query.push_str(" AND tenant = ?");
        params.push(t.clone());
    }

    if let Some(ref d) = domain {
        query.push_str(" AND domain = ?");
        params.push(d.clone());
    }

    query.push_str(" ORDER BY last_updated DESC");

    let mut stmt = conn.prepare(&query)?;

    let param_refs: Vec<&dyn rusqlite::ToSql> =
        params.iter().map(|p| p as &dyn rusqlite::ToSql).collect();

    let datasets = stmt.query_map(param_refs.as_slice(), |row| {
        Ok((
            row.get::<_, String>(0)?,          // name
            row.get::<_, String>(1)?,          // path
            row.get::<_, String>(2)?,          // format
            row.get::<_, Option<String>>(3)?,  // description
            row.get::<_, Option<String>>(4)?,  // tenant
            row.get::<_, Option<String>>(5)?,  // domain
            row.get::<_, Option<String>>(6)?,  // owner
            row.get::<_, String>(7)?,          // last_updated
            row.get::<_, Option<i64>>(8)?,     // row_count
            row.get::<_, Option<i64>>(9)?,     // size_bytes
            row.get::<_, Option<String>>(10)?, // partition keys JSON
        ))
    })?;

    println!("Datasets:");
    println!();

    for dataset in datasets {
        let (
            name,
            path,
            format,
            description,
            tenant,
            domain,
            owner,
            last_updated,
            row_count,
            size_bytes,
            partition_keys_json,
        ) = dataset?;

        if verbose {
            println!("  Name: {}", name);
            println!("  Path: {}", path);
            println!("  Format: {}", format);
            if let Some(desc) = description {
                println!("  Description: {}", desc);
            }
            if let Some(t) = tenant {
                println!("  Tenant: {}", t);
            }
            if let Some(d) = domain {
                println!("  Domain: {}", d);
            }
            if let Some(o) = owner {
                println!("  Owner: {}", o);
            }
            println!("  Last Updated: {}", last_updated);
            if let Some(rc) = row_count {
                println!("  Rows: {}", format_number(rc));
            }
            if let Some(sb) = size_bytes {
                println!("  Size: {}", format_bytes(sb));
            }
            if let Some(pk_json) = partition_keys_json {
                if let Ok(keys) = serde_json::from_str::<Vec<String>>(&pk_json) {
                    if !keys.is_empty() {
                        println!("  Partitions: {}", keys.join(", "));
                    }
                }
            }
            println!();
        } else {
            print!("  {} ({})", name, format);
            if let Some(d) = domain {
                print!(" [{}]", d);
            }
            println!();
        }
    }

    Ok(())
}

fn show_dataset(
    path: &str,
    name: &str,
    show_lineage: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let backend = backend_from_uri(path)?;
    let conn = backend.get_connection()?;

    // Get dataset info
    let dataset: Result<_, rusqlite::Error> = conn.query_row(
        "SELECT name, path, format, description, tenant, domain, owner, created_at, last_updated, row_count, size_bytes, partition_keys FROM datasets WHERE name = ?1",
        [name],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, Option<String>>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, String>(8)?,
                row.get::<_, Option<i64>>(9)?,
                row.get::<_, Option<i64>>(10)?,
                row.get::<_, Option<String>>(11)?,
            ))
        },
    );

    let (
        name,
        path,
        format,
        description,
        tenant,
        domain,
        owner,
        created_at,
        last_updated,
        row_count,
        size_bytes,
        partition_keys_json,
    ) = dataset?;

    println!("Dataset: {}", name);
    println!("Path: {}", path);
    println!("Format: {}", format);
    if let Some(desc) = description {
        println!("Description: {}", desc);
    }
    if let Some(t) = tenant {
        println!("Tenant: {}", t);
    }
    if let Some(d) = domain {
        println!("Domain: {}", d);
    }
    if let Some(o) = owner {
        println!("Owner: {}", o);
    }
    println!("Created: {}", created_at);
    println!("Last Updated: {}", last_updated);
    if let Some(rc) = row_count {
        println!("Rows: {}", format_number(rc));
    }
    if let Some(sb) = size_bytes {
        println!("Size: {}", format_bytes(sb));
    }
    if let Some(pk_json) = partition_keys_json {
        if let Ok(keys) = serde_json::from_str::<Vec<String>>(&pk_json) {
            if !keys.is_empty() {
                println!("Partitions: {}", keys.join(", "));
            }
        }
    }

    // Get fields
    let dataset_id: i64 =
        conn.query_row("SELECT id FROM datasets WHERE name = ?1", [&name], |row| {
            row.get(0)
        })?;

    println!("\nFields:");
    let mut stmt =
        conn.prepare("SELECT name, data_type, nullable FROM fields WHERE dataset_id = ?1")?;
    let fields = stmt.query_map([dataset_id], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, i32>(2)?,
        ))
    })?;

    for field in fields.flatten() {
        let (field_name, data_type, nullable) = field;
        let null_str = if nullable != 0 {
            "nullable"
        } else {
            "not null"
        };
        println!("  {} ({}, {})", field_name, data_type, null_str);
    }

    // Get tags
    let mut stmt = conn.prepare("SELECT tag FROM tags WHERE dataset_id = ?1")?;
    let tags: Vec<String> = stmt
        .query_map([dataset_id], |row| row.get(0))?
        .collect::<Result<Vec<_>, _>>()?;

    if !tags.is_empty() {
        println!("\nTags: {}", tags.join(", "));
    }

    if show_lineage {
        // Get upstream datasets
        let mut stmt = conn.prepare(
            "SELECT d.name FROM lineage l JOIN datasets d ON l.upstream_dataset_id = d.id WHERE l.downstream_dataset_id = ?1",
        )?;
        let upstream: Vec<String> = stmt
            .query_map([dataset_id], |row| row.get(0))?
            .collect::<Result<Vec<_>, _>>()?;

        if !upstream.is_empty() {
            println!("\nUpstream datasets:");
            for u in upstream {
                println!("  <- {}", u);
            }
        }

        // Get downstream datasets
        let mut stmt = conn.prepare(
            "SELECT d.name FROM lineage l JOIN datasets d ON l.downstream_dataset_id = d.id WHERE l.upstream_dataset_id = ?1",
        )?;
        let downstream: Vec<String> = stmt
            .query_map([dataset_id], |row| row.get(0))?
            .collect::<Result<Vec<_>, _>>()?;

        if !downstream.is_empty() {
            println!("\nDownstream datasets:");
            for d in downstream {
                println!("  -> {}", d);
            }
        }
    }

    Ok(())
}

fn search_datasets(path: &str, query: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Sanitize FTS query to prevent injection and validate length
    let sanitized_query = validation::sanitize_fts_query(query)?;

    let backend = backend_from_uri(path)?;
    let conn = backend.get_connection()?;

    let mut stmt = conn.prepare(
        r#"
        SELECT d.name, d.path, d.format, d.domain
        FROM datasets d
        JOIN dataset_search s ON d.name = s.dataset_name
        WHERE dataset_search MATCH ?1
        ORDER BY bm25(dataset_search)
        "#,
    )?;

    let results = stmt.query_map([&sanitized_query], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, Option<String>>(3)?,
        ))
    })?;

    println!("Search results for '{}':", query);
    println!();

    for result in results {
        let (name, path, format, domain) = result?;
        print!("  {} ({}) - {}", name, format, path);
        if let Some(d) = domain {
            print!(" [{}]", d);
        }
        println!();
    }

    Ok(())
}

fn show_stats(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let backend = backend_from_uri(path)?;
    let conn = backend.get_connection()?;

    let dataset_count: i64 =
        conn.query_row("SELECT COUNT(*) FROM datasets", [], |row| row.get(0))?;
    let field_count: i64 = conn.query_row("SELECT COUNT(*) FROM fields", [], |row| row.get(0))?;
    let lineage_count: i64 =
        conn.query_row("SELECT COUNT(*) FROM lineage", [], |row| row.get(0))?;
    let tag_count: i64 = conn.query_row("SELECT COUNT(*) FROM tags", [], |row| row.get(0))?;

    println!("Catalog Statistics:");
    println!("  Datasets: {}", format_number(dataset_count));
    println!("  Fields: {}", format_number(field_count));
    println!("  Lineage edges: {}", format_number(lineage_count));
    println!("  Tags: {}", format_number(tag_count));

    // Most common formats
    let mut stmt = conn.prepare(
        "SELECT format, COUNT(*) as count FROM datasets GROUP BY format ORDER BY count DESC LIMIT 5",
    )?;
    let formats = stmt.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
    })?;

    println!("\nTop formats:");
    for format in formats {
        let (format_name, count) = format?;
        println!("  {}: {}", format_name, count);
    }

    // Most common domains
    let mut stmt = conn.prepare(
        "SELECT domain, COUNT(*) as count FROM datasets WHERE domain IS NOT NULL GROUP BY domain ORDER BY count DESC LIMIT 5",
    )?;
    let domains = stmt.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
    })?;

    let domain_list: Vec<_> = domains.collect::<Result<Vec<_>, _>>()?;
    if !domain_list.is_empty() {
        println!("\nTop domains:");
        for (domain_name, count) in domain_list {
            println!("  {}: {}", domain_name, count);
        }
    }

    Ok(())
}

fn format_number(n: i64) -> String {
    let negative = n.is_negative();
    let mut digits = n.abs().to_string();
    let mut parts = Vec::new();

    while digits.len() > 3 {
        let chunk = digits.split_off(digits.len() - 3);
        parts.push(chunk);
    }
    parts.push(digits);
    parts.reverse();

    let mut formatted = parts.join(",");
    if negative {
        formatted.insert(0, '-');
    }
    formatted
}

fn format_bytes(bytes: i64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit_idx = 0;

    while size >= 1024.0 && unit_idx < UNITS.len() - 1 {
        size /= 1024.0;
        unit_idx += 1;
    }

    format!("{:.2} {}", size, UNITS[unit_idx])
}
