//! Real Nix publication and repair in a private local store. No daemon state,
//! signing keys, services or VMs on the host are changed.
use std::{
    fs,
    io::Write,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};
use tiaris_nest::{cache::seeds, config::AppConfig};

struct Directory(PathBuf);
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn output(command: &mut Command) -> String {
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

fn local_nix(nix: &str, root: &Path, args: &[&str]) -> Command {
    let mut command = Command::new(nix);
    command
        .args(["--extra-experimental-features", "nix-command", "--store"])
        .arg(format!("local?root={}", root.display()))
        .args(args);
    command
}

/// Register an input-addressed fixture with Nix's own database import format.
/// An add-file path is content-addressed and Nix legitimately trusts it even
/// without signatures; that would make the negative signature check vacuous.
fn input_addressed_path(nix: &str, root: &Path, path: &str, bytes: &[u8]) {
    fs::create_dir_all(root).unwrap();
    let input = root.join("input");
    fs::write(&input, bytes).unwrap();
    let added = output(&mut local_nix(
        nix,
        root,
        &["store", "add-file", input.to_str().unwrap()],
    ));
    let nix_store = Path::new(nix).with_file_name("nix-store");
    let store = format!("local?root={}", root.display());
    let dump = output(Command::new(&nix_store).args(["--store", &store, "--dump-db"]));
    fs::copy(input, root.join(path.trim_start_matches('/'))).unwrap();
    let mut register = Command::new(&nix_store)
        .args(["--store", &store, "--load-db"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    register
        .stdin
        .take()
        .unwrap()
        .write_all((dump.replace(&added, path) + "\n").as_bytes())
        .unwrap();
    let result = register.wait_with_output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}

#[test]
#[ignore = "requires Nix local stores and real signed substitution"]
fn real_nix_self_substitution_obeys_priority_and_requires_the_cache_signature() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let nix = std::env::var("TIARIS_TEST_NIX").unwrap_or_else(|_| "nix".into());
    let nix = output(Command::new("sh").args(["-c", "command -v \"$1\"", "sh", &nix]));
    let dir = Directory(
        std::env::temp_dir().join(format!("nest-self-cache-nix-{}", uuid::Uuid::new_v4())),
    );
    fs::create_dir_all(&dir.0).unwrap();
    let secret = output(&mut local_nix(
        &nix,
        &dir.0.join("source"),
        &["key", "generate-secret", "--key-name", "tiaris-nest-cache"],
    ));
    let raw = STANDARD.decode(secret.split_once(':').unwrap().1).unwrap();
    let public = format!("tiaris-nest-cache:{}", STANDARD.encode(&raw[32..]));
    let key = dir.0.join("cache-key");
    fs::write(&key, secret).unwrap();
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
    let path = format!("/nix/store/{}-nightly-self-cache", "1".repeat(32));
    let mut urls = Vec::new();
    for (name, bytes, priority) in [
        ("self", b"from own export".as_slice(), 10),
        ("fallback", b"from fallback".as_slice(), 30),
    ] {
        let source = dir.0.join(name);
        input_addressed_path(&nix, &source, &path, bytes);
        let cache = dir.0.join(format!("{name}-cache"));
        let destination = format!("file://{}?secret-key={}", cache.display(), key.display());
        output(&mut local_nix(
            &nix,
            &source,
            &["copy", "--to", &destination, &path],
        ));
        urls.push(format!("file://{}?priority={priority}", cache.display()));
    }
    // Deliberately list the fallback first: Nix uses priority, not list order.
    let substituters = format!("{} {}", urls[1], urls[0]);
    let nix_store = Path::new(&nix).with_file_name("nix-store");
    let realise = |root: &Path, trust: &str| {
        Command::new(&nix_store)
            .args([
                "--store",
                &format!("local?root={}", root.display()),
                "--realise",
                &path,
                "--option",
                "substituters",
                &substituters,
                "--option",
                "trusted-public-keys",
                trust,
                "--option",
                "require-sigs",
                "true",
                "--max-jobs",
                "0",
            ])
            .output()
            .unwrap()
    };
    let untrusted = dir.0.join("untrusted");
    let refused = realise(&untrusted, "");
    assert!(
        !refused.status.success(),
        "unsigned input-addressed substitution was accepted"
    );
    assert!(!untrusted.join(path.trim_start_matches('/')).exists());
    let trusted = dir.0.join("trusted");
    let accepted = realise(&trusted, &public);
    assert!(
        accepted.status.success(),
        "{}",
        String::from_utf8_lossy(&accepted.stderr)
    );
    assert_eq!(
        fs::read(trusted.join(path.trim_start_matches('/'))).unwrap(),
        b"from own export"
    );
}

#[tokio::test]
#[ignore = "requires Nix with local stores and zstd cache support"]
async fn real_nix_seed_publication_authentication_and_damaged_nar_repair() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let nix = std::env::var("TIARIS_TEST_NIX").unwrap_or_else(|_| "nix".into());
    let dir =
        Directory(std::env::temp_dir().join(format!("nest-seed-nix-{}", uuid::Uuid::new_v4())));
    fs::create_dir_all(&dir.0).unwrap();
    let store = format!("local?root={}", dir.0.join("store").display());
    let real_nix = |args: &[&str]| {
        let mut command = Command::new(&nix);
        command.args([
            "--extra-experimental-features",
            "nix-command",
            "--store",
            &store,
        ]);
        command.args(args);
        output(&mut command)
    };
    let input = dir.0.join("input");
    fs::write(&input, b"nightly workstation cache seed\n").unwrap();
    let seed = real_nix(&[
        "store",
        "add-file",
        "--name",
        "nightly-seed",
        input.to_str().unwrap(),
    ]);
    let release_secret = real_nix(&[
        "key",
        "generate-secret",
        "--key-name",
        "tiaris-nest-appliance-1",
    ]);
    let release_key = dir.0.join("release-key");
    fs::write(&release_key, &release_secret).unwrap();
    fs::set_permissions(&release_key, fs::Permissions::from_mode(0o600)).unwrap();
    // Nix secrets encode the Ed25519 seed followed by its public key.
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let raw = STANDARD
        .decode(release_secret.split_once(':').unwrap().1)
        .unwrap();
    let wrapper = dir.0.join("nix-wrapper");
    let nix_path = output(Command::new("sh").args(["-c", "command -v \"$1\"", "sh", &nix]));
    fs::write(&wrapper, format!(
        "#!/bin/sh\nset -eu\nif [ \"${{1-}}\" = --store ]; then shift; shift; fi\nexec '{}' --extra-experimental-features nix-command --store '{}' \"$@\"\n",
        nix_path.replace('\'', "'\\''"), store.replace('\'', "'\\''")
    )).unwrap();
    fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o700)).unwrap();
    let mut config = AppConfig::default();
    config.paths.data_dir = dir.0.join("data");
    config.cache.root_dir = dir.0.join("cache");
    config.cache.seed_manifest_path = dir.0.join("seeds.json");
    config.cache.private_key_path = dir.0.join("keys/cache-private.pem");
    config.cache.public_key_path = dir.0.join("keys/cache-public.pem");
    config.update.trusted_public_key = STANDARD.encode(&raw[32..]);
    config.build.nix_binary = wrapper.display().to_string();
    fs::write(
        &config.cache.seed_manifest_path,
        serde_json::json!({
            "schema":"tiaris.nest.workstation-cache-seeds.v1", "store_paths":[seed]
        })
        .to_string(),
    )
    .unwrap();

    let unsigned = seeds::publish(&config).await.unwrap();
    assert_eq!(unsigned.unauthenticated, 1);
    assert_eq!(unsigned.published, 0);
    real_nix(&[
        "store",
        "sign",
        "--key-file",
        release_key.to_str().unwrap(),
        &seed,
    ]);
    let first = seeds::publish(&config).await.unwrap();
    assert_eq!(first.published, 1, "{first:?}");
    assert_eq!(seeds::publish(&config).await.unwrap().already_published, 1);
    let nar = fs::read_dir(config.cache.root_dir.join("nar"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    for same_size in [false, true] {
        let good = fs::read(&nar).unwrap();
        let damaged = if same_size {
            vec![b'x'; good.len()]
        } else {
            b"damaged cached NAR".to_vec()
        };
        fs::write(&nar, damaged).unwrap();
        // One pass may quarantine metadata that made Nix think this path was
        // already present. The next pass must replace the bad bytes as well.
        let first_repair = seeds::publish(&config).await.unwrap();
        let repaired = seeds::publish(&config).await.unwrap();
        assert_eq!(
            repaired.failed, 0,
            "first={first_repair:?}; next={repaired:?}"
        );
        assert_eq!(repaired.published + repaired.already_published, 1);
        assert_eq!(fs::read(&nar).unwrap(), good);
    }
}
