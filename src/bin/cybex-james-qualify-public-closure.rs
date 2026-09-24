//! Release-job-only qualification of the signed public closure transport.
use anyhow::{Context, Result, ensure};
use clap::Parser;
use cybex_james::appliance::{
    closure, nixos,
    release_v3::{self, NixosRelease},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::Read,
    path::PathBuf,
};
use uuid::Uuid;

#[derive(Parser)]
struct Cli {
    #[arg(long)]
    manifest: PathBuf,
    #[arg(long)]
    trusted_public_key: PathBuf,
    #[arg(long)]
    source: String,
    #[arg(long)]
    tag: String,
    #[arg(long)]
    output: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Cli::parse();
    let mut body = Vec::new();
    File::open(&args.manifest)
        .context("open candidate release manifest")?
        .take(1024 * 1024 + 1)
        .read_to_end(&mut body)?;
    ensure!(
        body.len() <= 1024 * 1024,
        "candidate release manifest exceeds limit"
    );
    let manifest: Value = release_v3::strict_json(&body)?;
    let release: NixosRelease = serde_json::from_value(
        manifest
            .get("appliance_release_v1")
            .context("missing NixOS release")?
            .clone(),
    )?;
    let key = release.verify_file(&args.trusted_public_key)?;
    ensure!(
        manifest.get("version").and_then(Value::as_str) == Some(release.release_id.as_str())
            && args.tag == format!("v{}", release.release_id)
            && args.source == release.source_revision,
        "public closure qualification identity differs from signed release"
    );

    let archive = args
        .output
        .with_extension(format!("{}.closure", Uuid::new_v4()));
    let result = async {
        nixos::download(&release, &release.system_closure.url, &archive, false).await?;
        let mut file = File::open(&archive)?;
        closure::verify_archive(&mut file, &release, &key, None)?;
        let receipt = json!({
            "schema": "cybex.james.public-closure-qualification.v1",
            "ok": true,
            "source_revision": args.source,
            "tag": args.tag,
            "release_version": release.release_id,
            "manifest_sha256": hex::encode(Sha256::digest(&body)),
            "closure_url": release.system_closure.url,
            "closure_sha256": release.system_closure.sha256,
            "closure_size_bytes": release.system_closure.size_bytes,
            "archive_verified": true,
        });
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&args.output)?;
        serde_json::to_writer(&mut output, &receipt)?;
        Ok::<(), anyhow::Error>(())
    }
    .await;
    let _ = fs::remove_file(&archive);
    result
}
