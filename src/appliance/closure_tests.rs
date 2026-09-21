use super::*;
use ed25519_dalek::{Signer, SigningKey};
use std::io::Cursor;
use uuid::Uuid;

fn token(bytes: &[u8], out: &mut Vec<u8>) {
    out.extend((bytes.len() as u64).to_le_bytes());
    out.extend(bytes);
    out.resize(out.len() + (8 - bytes.len() % 8) % 8, 0);
}
fn nar(kind: &str, contents: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for t in [b"nix-archive-1".as_slice(), b"(", b"type", kind.as_bytes()] {
        token(t, &mut out)
    }
    if kind == "regular" {
        token(b"contents", &mut out);
        token(contents, &mut out)
    }
    token(b")", &mut out);
    out
}
struct Fixture {
    key: SigningKey,
    release: NixosRelease,
    members: Vec<(String, Vec<u8>)>,
}
impl Fixture {
    fn new() -> Self {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../protocol/fixtures/james-appliance-v3.json"
        ))
        .unwrap();
        let mut release: NixosRelease =
            serde_json::from_value(fixture["appliance_release"].clone()).unwrap();
        // Public deterministic test key only; never a signing authority.
        let key = SigningKey::from_bytes(&[7; 32]);
        let top = "/nix/store/00000000000000000000000000000000-system";
        let source = "/nix/store/11111111111111111111111111111111-source.tar";
        release.system_toplevel = top.into();
        let source_bytes = b"bounded corresponding source fixture";
        let mut rows = Vec::new();
        let mut infos = Vec::new();
        let mut payloads = Vec::new();
        for (path, body, refs) in [
            (top, nar("directory", b""), vec![source.into()]),
            (source, nar("regular", source_bytes), vec![]),
        ] {
            let hash = &store_path(path).unwrap()[..32];
            let compressed = zstd::stream::encode_all(Cursor::new(&body), 3).unwrap();
            let entry = StorePath {
                path: path.into(),
                nar_hash: nix_hash(&Sha256::digest(&body)),
                nar_size: body.len() as u64,
                references: refs,
                narinfo: format!("{hash}.narinfo"),
            };
            let name = format!("nar/{hash}.nar.zst");
            let fingerprint = format!(
                "1;{};{};{};{}",
                entry.path,
                entry.nar_hash,
                entry.nar_size,
                entry.references.join(",")
            );
            let signature = STANDARD.encode(key.sign(fingerprint.as_bytes()).to_bytes());
            let info = format!(
                "StorePath: {}\nURL: {name}\nCompression: zstd\nFileHash: {}\nFileSize: {}\nNarHash: {}\nNarSize: {}\nReferences: {}\nSig: cybex-james-appliance-1:{signature}\n",
                entry.path,
                nix_hash(&Sha256::digest(&compressed)),
                compressed.len(),
                entry.nar_hash,
                entry.nar_size,
                entry
                    .references
                    .iter()
                    .map(|p| store_path(p).unwrap())
                    .collect::<Vec<_>>()
                    .join(" ")
            );
            infos.push((entry.narinfo.clone(), info.into_bytes()));
            payloads.push((name, compressed));
            rows.push(entry);
        }
        let manifest = ClosureManifest {
            schema: "cybex.james.system-closure.v1".into(),
            release_id: release.release_id.clone(),
            base_os: release.base_os.clone(),
            base_os_version: release.base_os_version.clone(),
            source_revision: release.source_revision.clone(),
            manage_source_revision: release.manage_source_revision.clone(),
            nixpkgs_revision: release.nixpkgs_revision.clone(),
            system_toplevel: top.into(),
            required_system_versions: release.required_system_versions.clone(),
            sqlite_migrations_sha256: release.sqlite_migrations_sha256.clone(),
            nix_signing_public_key: format!(
                "cybex-james-appliance-1:{}",
                STANDARD.encode(key.verifying_key().as_bytes())
            ),
            manage_source: ManageSource {
                revision: release.manage_source_revision.clone(),
                sha256: hex::encode(Sha256::digest(source_bytes)),
                size_bytes: source_bytes.len() as u64,
                store_path: source.into(),
            },
            microcode_versions: BTreeMap::from([
                ("amd".into(), "1".into()),
                ("intel".into(), "1".into()),
            ]),
            total_nar_bytes: rows.iter().map(|r| r.nar_size).sum(),
            store_paths: rows,
        };
        let mut bytes = serde_json::to_vec(&super::super::canonical_json(
            serde_json::to_value(manifest).unwrap(),
        ))
        .unwrap();
        bytes.push(b'\n');
        let mut members = vec![
            ("manifest.json".into(), bytes),
            ("nix-cache-info".into(), b"StoreDir: /nix/store\n".to_vec()),
        ];
        members.extend(infos);
        members.push(("nar/".into(), vec![]));
        members.extend(payloads);
        Self {
            key,
            release,
            members,
        }
    }
    fn archive(&mut self, modify: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
        let mut tar = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar);
            for (name, bytes) in &self.members {
                let mut header = tar::Header::new_ustar();
                header.set_path(name).unwrap();
                header.set_size(bytes.len() as u64);
                header.set_uid(0);
                header.set_gid(0);
                header.set_mode(if name == "nar/" { 0o755 } else { 0o644 });
                header.set_mtime(0);
                header.set_entry_type(if name == "nar/" {
                    tar::EntryType::Directory
                } else {
                    tar::EntryType::Regular
                });
                header.set_cksum();
                builder.append(&header, &bytes[..]).unwrap();
            }
            builder.finish().unwrap();
        }
        modify(&mut tar);
        let bytes = zstd::stream::encode_all(Cursor::new(tar), 3).unwrap();
        self.bind(&bytes);
        bytes
    }
    fn bind(&mut self, bytes: &[u8]) {
        self.release.system_closure.size_bytes = bytes.len() as u64;
        self.release.system_closure.sha256 = hex::encode(Sha256::digest(bytes));
        self.release.signature = STANDARD.encode(
            self.key
                .sign(&self.release.signature_message().unwrap())
                .to_bytes(),
        );
    }
    fn verify(&self, bytes: &[u8]) -> Result<ClosureManifest> {
        let dir = std::env::temp_dir().join(format!("james-closure-test-{}", Uuid::new_v4()));
        fs::create_dir(&dir)?;
        let path = dir.join("closure.tar.zst");
        fs::write(&path, bytes)?;
        let mut file = File::open(path)?;
        let result = verify_archive(&mut file, &self.release, &self.key.verifying_key(), None);
        fs::remove_dir_all(dir)?;
        result
    }
}
#[test]
fn authenticates_entire_signed_closure_and_inner_source_bytes() {
    let mut f = Fixture::new();
    let bytes = f.archive(|_| {});
    let result = f.verify(&bytes).unwrap();
    assert_eq!(result.store_paths.len(), 2);
}
#[test]
#[ignore = "cross-language release gate requires Python 3 and zstd"]
fn python_packer_archive_verifies_and_extracts_in_rust() {
    let mut fixture = Fixture::new();
    let root = std::env::temp_dir().join(format!("james-packer-test-{}", Uuid::new_v4()));
    fs::create_dir(&root).unwrap();
    let cache = root.join("cache");
    fs::create_dir(&cache).unwrap();
    fs::create_dir(cache.join("nar")).unwrap();
    for (name, bytes) in &fixture.members {
        if name != "nar/" {
            fs::write(cache.join(name), bytes).unwrap();
        }
    }
    let packed = root.join("packed.tar.zst");
    let status = std::process::Command::new("python3")
        .args(["-B", "-c", "import runpy,sys; from pathlib import Path; runpy.run_path(sys.argv[1])['pack'](Path(sys.argv[2]),Path(sys.argv[3]))"])
        .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/tools/pack-system-closure.py"))
        .arg(&cache)
        .arg(&packed)
        .status()
        .unwrap();
    assert!(status.success());
    let bytes = fs::read(&packed).unwrap();
    fixture.bind(&bytes);
    let extracted = root.join("verified");
    let verified = verify_archive(
        &mut File::open(&packed).unwrap(),
        &fixture.release,
        &fixture.key.verifying_key(),
        Some(&extracted),
    );
    fs::remove_dir_all(root).unwrap();
    assert_eq!(verified.unwrap().store_paths.len(), 2);
}
#[test]
fn rejects_inner_signature_even_under_authentic_outer_signature() {
    let mut f = Fixture::new();
    let (_, bytes) = f
        .members
        .iter_mut()
        .find(|(n, _)| n.ends_with(".narinfo"))
        .unwrap();
    let text = String::from_utf8(bytes.clone()).unwrap();
    let sig =
        text.find("Sig: cybex-james-appliance-1:").unwrap() + "Sig: cybex-james-appliance-1:".len();
    bytes[sig] = if bytes[sig] == b'A' { b'B' } else { b'A' };
    let bytes = f.archive(|_| {});
    assert!(f.verify(&bytes).is_err());
}
#[test]
fn rejects_duplicate_member_before_import() {
    let mut f = Fixture::new();
    f.members.insert(2, f.members[1].clone());
    let bytes = f.archive(|_| {});
    assert!(f.verify(&bytes).is_err());
}
#[test]
fn rejects_manifest_source_hash_not_matching_nar() {
    let mut f = Fixture::new();
    let value: &mut Vec<u8> = &mut f.members[0].1;
    let mut manifest: serde_json::Value = serde_json::from_slice(value).unwrap();
    manifest["manage_source"]["sha256"] = serde_json::Value::String("0".repeat(64));
    *value = serde_json::to_vec(&super::super::canonical_json(manifest)).unwrap();
    value.push(b'\n');
    let bytes = f.archive(|_| {});
    assert!(f.verify(&bytes).is_err());
}
#[test]
fn rejects_trailing_compressed_frame_and_tar_data() {
    let mut f = Fixture::new();
    let mut bytes = f.archive(|_| {});
    bytes.extend(zstd::stream::encode_all(Cursor::new(b"extra"), 3).unwrap());
    f.bind(&bytes);
    assert!(f.verify(&bytes).is_err());
    let mut f = Fixture::new();
    let bytes = f.archive(|tar| tar.extend(b"untrusted"));
    assert!(f.verify(&bytes).is_err());
}
#[test]
fn rejects_outer_archive_truncation() {
    let mut f = Fixture::new();
    let mut bytes = f.archive(|_| {});
    bytes.pop();
    f.bind(&bytes);
    assert!(f.verify(&bytes).is_err());
}
#[test]
fn rejects_nested_nar_payload_with_valid_size_and_outer_hash() {
    let mut f = Fixture::new();
    f.members.last_mut().unwrap().1[5] ^= 0x80;
    let bytes = f.archive(|_| {});
    assert!(f.verify(&bytes).is_err());
}
