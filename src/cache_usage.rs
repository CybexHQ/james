//! Coalesced disk walks. Local writes invalidate the estimate, including failed
//! exports; a one-minute reconciliation catches changes from other processes.
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant},
};

type Entry = Arc<tokio::sync::Mutex<Option<(Instant, u64)>>>;
static ENTRIES: OnceLock<Mutex<HashMap<PathBuf, Entry>>> = OnceLock::new();
const RECONCILE: Duration = Duration::from_secs(60);

pub(crate) async fn measure(root: &Path) -> u64 {
    let entry = {
        let mut entries = ENTRIES
            .get_or_init(Default::default)
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if entries.len() >= 16 && !entries.contains_key(root) {
            entries.clear();
        }
        entries.entry(root.to_path_buf()).or_default().clone()
    };
    let mut value = entry.lock().await;
    if let Some((at, bytes)) = *value {
        if at.elapsed() < RECONCILE {
            return bytes;
        }
    }
    let root = root.to_owned();
    let bytes = tokio::task::spawn_blocking(move || crate::cache::measure_cache_disk_usage(&root))
        .await
        .unwrap_or(0);
    *value = Some((Instant::now(), bytes));
    bytes
}

pub(crate) struct Mutation(PathBuf);
impl Mutation {
    pub(crate) fn new(root: &Path) -> Self {
        Self(root.to_owned())
    }
}
impl Drop for Mutation {
    fn drop(&mut self) {
        if let Some(entries) = ENTRIES.get() {
            entries
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&self.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn writes_invalidate_coalesced_scan() {
        let root = std::env::temp_dir().join(format!("nest-usage-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("nar"), [0; 1024]).unwrap();
        assert_eq!(measure(&root).await, 1024);
        std::fs::write(root.join("nar"), [0; 2048]).unwrap();
        assert_eq!(measure(&root).await, 1024);
        drop(Mutation::new(&root));
        assert_eq!(measure(&root).await, 2048);
        std::fs::remove_dir_all(&root).unwrap();
        drop(Mutation::new(&root));
        assert_eq!(measure(&root).await, 0);
    }
}
