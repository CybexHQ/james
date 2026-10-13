//! Retry only idempotent build/cache publication after SQLite's bounded busy wait.
use std::{
    future::Future,
    time::{Duration, Instant},
};

const MAX_ATTEMPTS: usize = 8;
const RETRY_DELAY: Duration = Duration::from_millis(100);
// A settings qualification build later saw the write lock held for about 55
// seconds, longer than eight attempts. Only a completed build's result and
// cache record wait this long: losing them means rebuilding the closure.
const OUTCOME_BUDGET: Duration = Duration::from_secs(5 * 60);

pub(super) async fn publish<T, F, Fut>(operation: &'static str, write: F) -> Result<T, sqlx::Error>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, sqlx::Error>>,
{
    // A native first build exposed a 31-second durable WAL fsync. Keep the
    // existing five-second SQLite wait and yield between at most eight attempts.
    // Do not replay the build/export, a transaction, or a non-busy error.
    retry(operation, |attempt, _| attempt < MAX_ATTEMPTS, write).await
}

pub(super) async fn publish_outcome<T, F, Fut>(
    operation: &'static str,
    write: F,
) -> Result<T, sqlx::Error>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, sqlx::Error>>,
{
    publish_within(operation, OUTCOME_BUDGET, write).await
}

async fn publish_within<T, F, Fut>(
    operation: &'static str,
    budget: Duration,
    write: F,
) -> Result<T, sqlx::Error>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, sqlx::Error>>,
{
    retry(operation, |_, elapsed| elapsed < budget, write).await
}

async fn retry<T, F, Fut>(
    operation: &'static str,
    mut again: impl FnMut(usize, Duration) -> bool,
    mut write: F,
) -> Result<T, sqlx::Error>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, sqlx::Error>>,
{
    let started = Instant::now();
    let mut attempt = 0;
    loop {
        attempt += 1;
        match write().await {
            Err(error) if is_busy(&error) && again(attempt, started.elapsed()) => {
                tracing::warn!(
                    operation,
                    attempt,
                    elapsed_seconds = started.elapsed().as_secs(),
                    "SQLite publication busy; retrying the same statement"
                );
                tokio::time::sleep(RETRY_DELAY).await;
            }
            result => return result,
        }
    }
}

fn is_busy(error: &sqlx::Error) -> bool {
    matches!(error, sqlx::Error::Database(error) if error.code().as_deref() == Some("5"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions};
    use std::sync::atomic::{AtomicUsize, Ordering};

    async fn probe_pool(root: &std::path::Path) -> SqlitePool {
        let options = SqliteConnectOptions::new()
            .filename(root.join("state.sqlite"))
            .create_if_missing(true)
            .busy_timeout(Duration::from_millis(10));
        let pool = SqlitePoolOptions::new()
            .max_connections(2)
            .connect_with(options)
            .await
            .unwrap();
        sqlx::query("CREATE TABLE probe(value INTEGER)")
            .execute(&pool)
            .await
            .unwrap();
        pool
    }

    #[tokio::test]
    async fn permanent_busy_stops_and_preserves_sqlite_error() {
        let root = std::env::temp_dir().join(format!("nest-busy-limit-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let pool = probe_pool(&root).await;
        let mut writer = pool.begin().await.unwrap();
        sqlx::query("INSERT INTO probe VALUES (1)")
            .execute(&mut *writer)
            .await
            .unwrap();
        let attempts = AtomicUsize::new(0);
        let result = publish("bounded-regression", || {
            attempts.fetch_add(1, Ordering::SeqCst);
            sqlx::query("INSERT INTO probe VALUES (2)").execute(&pool)
        })
        .await;
        assert_eq!(attempts.load(Ordering::SeqCst), MAX_ATTEMPTS);
        assert!(is_busy(&result.unwrap_err()));
        let started = Instant::now();
        let result = publish_within(
            "bounded-outcome-regression",
            Duration::from_millis(300),
            || sqlx::query("INSERT INTO probe VALUES (3)").execute(&pool),
        )
        .await;
        assert!(is_busy(&result.unwrap_err()));
        assert!(started.elapsed() < Duration::from_secs(5));
        writer.rollback().await.unwrap();
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM probe")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 0);
        pool.close().await;
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn outcome_outlasts_a_writer_longer_than_the_attempt_budget() {
        let root = std::env::temp_dir().join(format!("nest-busy-outcome-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let pool = probe_pool(&root).await;
        let mut writer = pool.begin().await.unwrap();
        sqlx::query("INSERT INTO probe VALUES (1)")
            .execute(&mut *writer)
            .await
            .unwrap();
        // Hold the lock for three times the eight-attempt budget, as the
        // 55-second qualification stall did against the five-second busy timeout.
        let hold = Duration::from_millis(3 * MAX_ATTEMPTS as u64 * 110);
        let (published, released) = tokio::join!(
            publish_within("outcome-regression", Duration::from_secs(30), || {
                sqlx::query("INSERT INTO probe VALUES (2)").execute(&pool)
            }),
            async {
                tokio::time::sleep(hold).await;
                writer.commit().await
            }
        );
        released.unwrap();
        published.expect("a completed build's outcome survives a long writer");
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM probe")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 2);
        pool.close().await;
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn non_busy_error_is_never_retried() {
        let attempts = AtomicUsize::new(0);
        let error = publish_outcome("non-busy-regression", || {
            attempts.fetch_add(1, Ordering::SeqCst);
            std::future::ready(Err::<(), _>(sqlx::Error::Protocol(
                "original failure".into(),
            )))
        })
        .await
        .unwrap_err();
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        assert!(error.to_string().contains("original failure"));
    }
}
