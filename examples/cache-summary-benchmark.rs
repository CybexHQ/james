//! Separate processes make allocation high-water marks comparable. Usage:
//! cache-summary-benchmark seed|legacy|count DATABASE [rows] [manifest_MiB]
use anyhow::{Result, bail};
use serde_json::json;
use std::time::Instant;
use tiaris_nest::db;

fn rss(field: &str) -> Option<u64> {
    std::fs::read_to_string("/proc/self/status")
        .ok()?
        .lines()
        .find(|line| line.starts_with(field))?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = std::env::args().collect::<Vec<_>>();
    if args.len() < 3 {
        bail!("usage: cache-summary-benchmark seed|legacy|count DATABASE [rows] [manifest_MiB]");
    }
    let pool = db::connect_with_url(&format!("sqlite://{}?mode=rwc", args[2])).await?;
    db::migrate(&pool).await?;
    if args[1] == "seed" {
        let rows: usize = args.get(3).map(|s| s.parse()).transpose()?.unwrap_or(10);
        let size: usize = args.get(4).map(|s| s.parse()).transpose()?.unwrap_or(16);
        if rows > 100 || size > 23 {
            bail!("fixture exceeds bound");
        }
        if db::count_cache_artifacts(&pool).await? != 0 {
            bail!("seed requires a new empty fixture database");
        }
        let metadata = serde_json::to_string(&json!({"fixture": "x".repeat(size * 1024 * 1024)}))?;
        for id in 0..rows {
            sqlx::query("INSERT INTO nest_cache_artifacts (artifact_type,hash,path,created_at,updated_at,cache_metadata) VALUES ('nixos_closure', ?, '/fixture', datetime('now'),datetime('now'),?)")
                .bind(format!("{id:064x}")).bind(&metadata).execute(&pool).await?;
        }
    } else {
        let before = rss("VmRSS:");
        let mut timings = Vec::new();
        let mut count = 0;
        for _ in 0..10 {
            let at = Instant::now();
            count = match args[1].as_str() {
                "legacy" => db::list_cache_artifacts(&pool).await?.len(),
                "count" => db::count_cache_artifacts(&pool).await? as usize,
                _ => bail!("unknown benchmark mode"),
            };
            timings.push(at.elapsed().as_secs_f64());
        }
        println!(
            "{}",
            json!({"mode":args[1],"artifacts":count,"seconds":timings,
            "rss_before_kib":before,"rss_after_kib":rss("VmRSS:"),"peak_rss_kib":rss("VmHWM:")})
        );
    }
    pool.close().await;
    Ok(())
}
