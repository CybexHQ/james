//! USB installer stick support: the stick protocol's response bodies and the
//! stick image this Nest serves.
//!
//! The stick is a small boot program for computers that cannot network-boot
//! (Tiaris `docs/design/usb-installer.md`). It reaches this Nest over a USB
//! Ethernet adapter, built-in Ethernet or Wi-Fi and asks for exactly what iPXE
//! would load: the same selection rules, the same signed boot session, the
//! same runtime. It then starts that runtime with `kexec`.
//!
//! The organization-neutral image is built from Tiaris source with the
//! appliance and ships in its signed system closure. When serving it, the Nest
//! replaces one fixed 4 KiB placeholder with `tiaris/site.json`: this Nest's
//! public boot URL, device ID and organization slug, none of them secret.

use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use axum::{
    body::Body,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{pin::Pin, task::Poll};
use tokio::io::{AsyncRead, AsyncReadExt, ReadBuf};
use tokio_util::io::ReaderStream;

use crate::{
    config::AppConfig,
    netboot::{ActiveRuntimeIdentity, BootSessionLaunch, ComponentDescriptors},
};

/// Advertised to Manage (only when Manage accepts it) while this Nest serves
/// the stick image.
pub const CAPABILITY: &str = "usb_installer_v1";
pub const PROTOCOL_SCHEMA: &str = "tiaris.nest.usb-installer.v1";
/// The oldest stick protocol this Nest still answers. A stick reports its
/// protocol as `User-Agent: tiaris-usb-installer/<protocol> ...`; an older
/// one gets `410` and tells the administrator to download a new stick.
pub const MINIMUM_STICK_PROTOCOL: u32 = 1;
const STICK_USER_AGENT_PREFIX: &str = "tiaris-usb-installer/";

pub const IMAGE_METADATA_SCHEMA: &str = "tiaris.usb-installer.image.v1";
pub const SITE_SCHEMA: &str = "tiaris.usb-installer.site.v1";
pub const IMAGE_FILE_NAME: &str = "tiaris-usb-installer.img";
pub const IMAGE_METADATA_FILE_NAME: &str = "tiaris-usb-installer.json";
const DEFAULT_IMAGE_DIR: &str = "/usr/share/tiaris-nest/usb-installer";
const IMAGE_DIR_ENV: &str = "TIARIS_NEST_USB_INSTALLER_DIR";
const MAX_IMAGE_METADATA_BYTES: u64 = 16 * 1024;
const MAX_IMAGE_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const SITE_BYTES: u64 = 4096;
const STREAM_CHUNK_BYTES: usize = 256 * 1024;

pub const ERROR_INVALID_REQUEST: &str = "invalid_request";
pub const ERROR_OUTDATED_STICK: &str = "usb_installer_outdated";
pub const ERROR_PROFILE_UNAVAILABLE: &str = "profile_unavailable";
pub const ERROR_RUNTIME_UNAVAILABLE: &str = "runtime_unavailable";
pub const ERROR_SESSION_UNAVAILABLE: &str = "session_unavailable";
pub const ERROR_INTERNAL: &str = "internal_error";

pub const NOTICE_KNOWN_COMPUTER: &str = "known_computer";
pub const NOTICE_ADAPTER_OF_ANOTHER_COMPUTER: &str = "adapter_of_another_computer";

/// The existing `tiaris.nest.kexec.v1` launch plus the identity of the runtime
/// it starts, so the stick can verify the kernel and initrd it downloads.
#[derive(Clone, Debug, Serialize)]
pub struct UsbLaunch {
    #[serde(flatten)]
    pub session: BootSessionLaunch,
    pub runtime_version: String,
    pub components: ComponentDescriptors,
}

impl UsbLaunch {
    pub fn new(session: BootSessionLaunch, runtime: ActiveRuntimeIdentity) -> Self {
        Self {
            session,
            runtime_version: runtime.runtime_version,
            components: runtime.components,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct UsbMenuProfile {
    pub id: i64,
    pub name: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum UsbBootAction {
    Launch {
        launch: Box<UsbLaunch>,
    },
    Menu {
        notice: Option<&'static str>,
        profiles: Vec<UsbMenuProfile>,
    },
}

#[derive(Clone, Debug, Serialize)]
pub struct UsbBootResponse {
    pub schema: &'static str,
    #[serde(flatten)]
    pub action: UsbBootAction,
}

#[derive(Clone, Debug, Serialize)]
pub struct UsbRuntimeResponse {
    pub schema: &'static str,
    pub runtime: ActiveRuntimeIdentity,
}

#[derive(Clone, Debug, Serialize)]
pub struct UsbErrorResponse {
    pub schema: &'static str,
    pub error: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub minimum_stick_protocol: Option<u32>,
}

pub fn json_response<T: Serialize>(status: StatusCode, body: &T) -> Response {
    (
        status,
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, "no-store, max-age=0"),
            (header::PRAGMA, "no-cache"),
        ],
        axum::Json(body),
    )
        .into_response()
}

pub fn error_response(status: StatusCode, error: &'static str) -> Response {
    json_response(
        status,
        &UsbErrorResponse {
            schema: PROTOCOL_SCHEMA,
            error,
            minimum_stick_protocol: (error == ERROR_OUTDATED_STICK)
                .then_some(MINIMUM_STICK_PROTOCOL),
        },
    )
}

/// The stick protocol a request's `User-Agent` reports, when it comes from a
/// stick. Other clients (a curl check, a browser) report none.
pub fn stick_protocol(headers: &HeaderMap) -> Option<u32> {
    let agent = headers.get(header::USER_AGENT)?.to_str().ok()?;
    let rest = agent.strip_prefix(STICK_USER_AGENT_PREFIX)?;
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    if digits.is_empty() || digits.len() > 6 {
        return None;
    }
    digits.parse().ok()
}

/// `410` for a stick whose protocol this Nest no longer answers.
pub fn reject_outdated_stick(headers: &HeaderMap) -> Option<Response> {
    let protocol = stick_protocol(headers)?;
    (protocol < MINIMUM_STICK_PROTOCOL)
        .then(|| error_response(StatusCode::GONE, ERROR_OUTDATED_STICK))
}

/// What the build records about the generic image (written next to it).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ImageMetadata {
    pub schema: String,
    pub protocol: u32,
    pub source_revision: String,
    pub image: String,
    pub size_bytes: u64,
    pub sha256: String,
    pub site_offset: u64,
    pub site_size: u64,
    pub site_placeholder_sha256: String,
}

impl ImageMetadata {
    pub fn validate(&self) -> Result<()> {
        if self.schema != IMAGE_METADATA_SCHEMA {
            bail!("USB installer image metadata schema is unsupported");
        }
        if self.protocol < MINIMUM_STICK_PROTOCOL {
            bail!("USB installer image protocol is older than this Nest supports");
        }
        if self.image != IMAGE_FILE_NAME {
            bail!("USB installer image name is unexpected");
        }
        if self.size_bytes == 0 || self.size_bytes > MAX_IMAGE_BYTES {
            bail!("USB installer image size is outside its bound");
        }
        if self.site_size != SITE_BYTES
            || self
                .site_offset
                .checked_add(self.site_size)
                .is_none_or(|end| end > self.size_bytes)
            || self.site_offset % 512 != 0
        {
            bail!("USB installer site placeholder is outside the image");
        }
        for (label, value) in [
            ("image", self.sha256.as_str()),
            ("placeholder", self.site_placeholder_sha256.as_str()),
        ] {
            if value.len() != 64
                || !value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                bail!("USB installer {label} digest is invalid");
            }
        }
        if self.source_revision.is_empty()
            || self.source_revision.len() > 64
            || !self
                .source_revision
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'.')
        {
            bail!("USB installer source revision is invalid");
        }
        Ok(())
    }
}

/// `tiaris/site.json`: which Nest a stick belongs to.
#[derive(Clone, Debug, Serialize)]
pub struct SiteConfig {
    pub schema: &'static str,
    pub nest_url: String,
    pub nest_device_id: String,
    pub organization_slug: String,
}

/// The site file exactly `size` bytes long: JSON, spaces, and a newline.
pub fn render_site(site: &SiteConfig, size: u64) -> Result<Vec<u8>> {
    let mut body = serde_json::to_vec(site).context("serialize USB installer site")?;
    let size = usize::try_from(size).context("site size overflow")?;
    if body.len() + 1 > size {
        bail!("USB installer site does not fit its placeholder");
    }
    body.resize(size - 1, b' ');
    body.push(b'\n');
    Ok(body)
}

pub fn image_dir() -> PathBuf {
    std::env::var_os(IMAGE_DIR_ENV)
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .unwrap_or_else(|| PathBuf::from(DEFAULT_IMAGE_DIR))
}

fn open_regular_no_follow(path: &Path) -> Result<File> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .with_context(|| format!("open {}", path.display()))?;
    if !file.metadata()?.is_file() {
        bail!("{} is not a regular file", path.display());
    }
    Ok(file)
}

pub fn load_metadata(dir: &Path) -> Result<ImageMetadata> {
    let mut file = open_regular_no_follow(&dir.join(IMAGE_METADATA_FILE_NAME))?;
    if file.metadata()?.len() > MAX_IMAGE_METADATA_BYTES {
        bail!("USB installer image metadata exceeds its bound");
    }
    let mut body = Vec::new();
    file.by_ref()
        .take(MAX_IMAGE_METADATA_BYTES + 1)
        .read_to_end(&mut body)?;
    let metadata: ImageMetadata =
        serde_json::from_slice(&body).context("parse USB installer image metadata")?;
    metadata.validate()?;
    Ok(metadata)
}

/// The image is present and its placeholder intact: the Nest can serve it.
/// Hashing 4 KiB per request keeps a damaged or foreign image from being
/// personalized; the read-only store path carries the rest of its identity.
pub fn open_image(dir: &Path) -> Result<(ImageMetadata, File)> {
    let metadata = load_metadata(dir)?;
    let mut file = open_regular_no_follow(&dir.join(IMAGE_FILE_NAME))?;
    if file.metadata()?.len() != metadata.size_bytes {
        bail!("USB installer image size differs from its metadata");
    }
    let mut placeholder = vec![0_u8; usize::try_from(metadata.site_size)?];
    file.seek(SeekFrom::Start(metadata.site_offset))?;
    file.read_exact(&mut placeholder)?;
    if hex::encode(Sha256::digest(&placeholder)) != metadata.site_placeholder_sha256 {
        bail!("USB installer site placeholder does not match its metadata");
    }
    file.seek(SeekFrom::Start(0))?;
    Ok((metadata, file))
}

pub fn image_available() -> bool {
    open_image(&image_dir()).is_ok()
}

pub fn site_for(config: &AppConfig) -> Result<SiteConfig> {
    let identity = crate::manage::nest_boot_identity(config)?;
    let organization_slug = config.manage.organization_slug.trim().to_string();
    if organization_slug.is_empty() {
        bail!("this Nest has no organization yet");
    }
    Ok(SiteConfig {
        schema: SITE_SCHEMA,
        nest_url: config.public_base_url().to_string(),
        nest_device_id: identity.device_id,
        organization_slug,
    })
}

/// Streams `file` with the placeholder window replaced by `site`.
pub fn personalized_stream(file: File, metadata: &ImageMetadata, site: Vec<u8>) -> Result<Body> {
    if u64::try_from(site.len())? != metadata.site_size {
        bail!("personalized site has the wrong size");
    }
    let reader = PersonalizedReader {
        inner: tokio::fs::File::from_std(file),
        position: 0,
        window_offset: metadata.site_offset,
        window: site,
    };
    let stream = ReaderStream::with_capacity(reader.take(metadata.size_bytes), STREAM_CHUNK_BYTES);
    Ok(Body::from_stream(stream))
}

struct PersonalizedReader {
    inner: tokio::fs::File,
    position: u64,
    window_offset: u64,
    window: Vec<u8>,
}

impl AsyncRead for PersonalizedReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buffer.filled().len();
        let this = &mut *self;
        match Pin::new(&mut this.inner).poll_read(context, buffer) {
            Poll::Ready(Ok(())) => {
                let filled = &mut buffer.filled_mut()[before..];
                overlay_window(filled, this.position, this.window_offset, &this.window);
                this.position += filled.len() as u64;
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

/// Copies the part of `window` (placed at `window_offset` in the image) that
/// overlaps `chunk` (placed at `chunk_offset`).
fn overlay_window(chunk: &mut [u8], chunk_offset: u64, window_offset: u64, window: &[u8]) {
    let chunk_end = chunk_offset + chunk.len() as u64;
    let window_end = window_offset + window.len() as u64;
    let start = chunk_offset.max(window_offset);
    let end = chunk_end.min(window_end);
    if start >= end {
        return;
    }
    let length = (end - start) as usize;
    let into = (start - chunk_offset) as usize;
    let from = (start - window_offset) as usize;
    chunk[into..into + length].copy_from_slice(&window[from..from + length]);
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;
    use std::io::Write;

    fn headers_with_agent(agent: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(header::USER_AGENT, HeaderValue::from_str(agent).unwrap());
        headers
    }

    #[test]
    fn stick_protocol_is_read_from_the_user_agent() {
        assert_eq!(
            stick_protocol(&headers_with_agent("tiaris-usb-installer/1 (abc123)")),
            Some(1)
        );
        assert_eq!(
            stick_protocol(&headers_with_agent("tiaris-usb-installer/12")),
            Some(12)
        );
        assert_eq!(stick_protocol(&headers_with_agent("curl/8.0")), None);
        assert_eq!(
            stick_protocol(&headers_with_agent("tiaris-usb-installer/x")),
            None
        );
        assert_eq!(stick_protocol(&HeaderMap::new()), None);
    }

    #[test]
    fn only_a_stick_older_than_the_minimum_is_rejected() {
        assert!(reject_outdated_stick(&headers_with_agent("tiaris-usb-installer/1")).is_none());
        assert!(reject_outdated_stick(&headers_with_agent("curl/8.0")).is_none());
        let rejected = reject_outdated_stick(&headers_with_agent("tiaris-usb-installer/0"))
            .expect("protocol 0 is outdated");
        assert_eq!(rejected.status(), StatusCode::GONE);
    }

    #[test]
    fn site_fills_its_placeholder_exactly() {
        let site = SiteConfig {
            schema: SITE_SCHEMA,
            nest_url: "http://10.0.0.5".to_string(),
            nest_device_id: "nest-1".to_string(),
            organization_slug: "greenfield".to_string(),
        };
        let body = render_site(&site, SITE_BYTES).unwrap();
        assert_eq!(body.len() as u64, SITE_BYTES);
        assert_eq!(body.last(), Some(&b'\n'));
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["schema"], SITE_SCHEMA);
        assert_eq!(parsed["nest_url"], "http://10.0.0.5");
        assert_eq!(parsed["nest_device_id"], "nest-1");
        assert_eq!(parsed["organization_slug"], "greenfield");
        assert!(render_site(&site, 16).is_err());
    }

    #[test]
    fn overlay_replaces_only_the_overlapping_bytes() {
        let window = b"WXYZ";
        let mut chunk = *b"abcdefgh";
        overlay_window(&mut chunk, 100, 106, window);
        assert_eq!(&chunk, b"abcdefWX");
        let mut chunk = *b"abcdefgh";
        overlay_window(&mut chunk, 108, 106, window);
        assert_eq!(&chunk, b"YZcdefgh");
        let mut chunk = *b"abcdefgh";
        overlay_window(&mut chunk, 0, 106, window);
        assert_eq!(&chunk, b"abcdefgh");
        let mut chunk = *b"ab";
        overlay_window(&mut chunk, 107, 106, window);
        assert_eq!(&chunk, b"XY");
    }

    fn write_image(dir: &Path, placeholder: &[u8]) -> ImageMetadata {
        let mut image = vec![0x5a_u8; 8192];
        image[1024..1024 + placeholder.len()].copy_from_slice(placeholder);
        std::fs::File::create(dir.join(IMAGE_FILE_NAME))
            .unwrap()
            .write_all(&image)
            .unwrap();
        let metadata = ImageMetadata {
            schema: IMAGE_METADATA_SCHEMA.to_string(),
            protocol: 1,
            source_revision: "0123456789abcdef0123456789abcdef01234567".to_string(),
            image: IMAGE_FILE_NAME.to_string(),
            size_bytes: image.len() as u64,
            sha256: hex::encode(Sha256::digest(&image)),
            site_offset: 1024,
            site_size: SITE_BYTES,
            site_placeholder_sha256: hex::encode(Sha256::digest(vec![b' '; 4096])),
        };
        std::fs::write(
            dir.join(IMAGE_METADATA_FILE_NAME),
            serde_json::to_vec(&metadata).unwrap(),
        )
        .unwrap();
        metadata
    }

    fn temporary_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "tiaris-nest-usb-installer-{label}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[tokio::test]
    async fn image_is_served_with_the_site_in_its_placeholder() {
        let dir = temporary_dir("serve");
        let metadata = write_image(&dir, &[b' '; 4096]);
        let (loaded, file) = open_image(&dir).unwrap();
        assert_eq!(loaded, metadata);
        let site = render_site(
            &SiteConfig {
                schema: SITE_SCHEMA,
                nest_url: "http://10.0.0.5".to_string(),
                nest_device_id: "nest-1".to_string(),
                organization_slug: "greenfield".to_string(),
            },
            SITE_BYTES,
        )
        .unwrap();
        let body = personalized_stream(file, &loaded, site.clone()).unwrap();
        let bytes = axum::body::to_bytes(body, 1024 * 1024).await.unwrap();
        assert_eq!(bytes.len(), 8192);
        assert_eq!(&bytes[1024..1024 + 4096], site.as_slice());
        assert!(bytes[..1024].iter().all(|byte| *byte == 0x5a));
        assert!(bytes[1024 + 4096..].iter().all(|byte| *byte == 0x5a));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_damaged_placeholder_or_bad_metadata_is_not_served() {
        let dir = temporary_dir("damaged");
        write_image(&dir, &[b'x'; 4096]);
        assert!(open_image(&dir).is_err());
        std::fs::remove_dir_all(&dir).unwrap();

        let base = ImageMetadata {
            schema: IMAGE_METADATA_SCHEMA.to_string(),
            protocol: 1,
            source_revision: "abc".to_string(),
            image: IMAGE_FILE_NAME.to_string(),
            size_bytes: 8192,
            sha256: "a".repeat(64),
            site_offset: 1024,
            site_size: SITE_BYTES,
            site_placeholder_sha256: "b".repeat(64),
        };
        assert!(base.validate().is_ok());
        for broken in [
            ImageMetadata {
                site_offset: 6144,
                ..base.clone()
            },
            ImageMetadata {
                site_offset: 1000,
                ..base.clone()
            },
            ImageMetadata {
                site_size: 512,
                ..base.clone()
            },
            ImageMetadata {
                protocol: 0,
                ..base.clone()
            },
            ImageMetadata {
                image: "../x".to_string(),
                ..base.clone()
            },
            ImageMetadata {
                sha256: "A".repeat(64),
                ..base.clone()
            },
            ImageMetadata {
                source_revision: "a b".to_string(),
                ..base.clone()
            },
        ] {
            assert!(broken.validate().is_err(), "{broken:?}");
        }
    }

    #[test]
    fn missing_image_directory_is_unavailable() {
        assert!(open_image(Path::new("/nonexistent/tiaris-usb-installer")).is_err());
    }
}
