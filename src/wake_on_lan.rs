use std::net::Ipv4Addr;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, SqlitePool};
use tokio::net::UdpSocket;

use crate::{error::AppResult, models::normalize_mac};

pub const CAPABILITY: &str = "wake_on_lan_v1";
const MAX_REQUESTS: usize = 100;
const MAX_REPORTS: i64 = 500;
const MAGIC_PACKET_PORTS: [u16; 2] = [9, 7];

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedWakeRequest {
    pub request_id: String,
    pub mac: String,
}

#[derive(Clone, Debug, FromRow, Serialize)]
pub struct WakeReport {
    pub request_id: String,
    pub mac: String,
    pub state: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub error_code: String,
}

fn magic_packet(mac: &str) -> Option<[u8; 102]> {
    let normalized = normalize_mac(mac).ok()?;
    let octets = normalized
        .split(':')
        .map(|value| u8::from_str_radix(value, 16).ok())
        .collect::<Option<Vec<_>>>()?;
    let mac: [u8; 6] = octets.try_into().ok()?;
    let mut packet = [0u8; 102];
    packet[..6].fill(0xff);
    for chunk in packet[6..].chunks_exact_mut(6) {
        chunk.copy_from_slice(&mac);
    }
    Some(packet)
}

async fn send_magic_packet(mac: &str) -> std::io::Result<()> {
    let packet = magic_packet(mac).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid MAC address")
    })?;
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await?;
    socket.set_broadcast(true)?;
    // Multiple packets and both conventional discard ports improve firmware
    // compatibility without turning a single reviewed request into an
    // unbounded wake storm.
    for _ in 0..3 {
        for port in MAGIC_PACKET_PORTS {
            socket.send_to(&packet, (Ipv4Addr::BROADCAST, port)).await?;
        }
    }
    Ok(())
}

pub async fn apply_requests(pool: &SqlitePool, requests: &[ManagedWakeRequest]) -> AppResult<()> {
    for request in requests.iter().take(MAX_REQUESTS) {
        let request_id = request.request_id.trim();
        if request_id.is_empty() || request_id.len() > 64 {
            continue;
        }
        let normalized = normalize_mac(&request.mac);
        let existing: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM wake_on_lan_receipts WHERE request_id = ?)",
        )
        .bind(request_id)
        .fetch_one(pool)
        .await?;
        if existing {
            continue;
        }
        let now = Utc::now().to_rfc3339();
        let (mac, state, error_code) = match normalized {
            Ok(mac) => match send_magic_packet(&mac).await {
                Ok(()) => (mac, "sent", ""),
                Err(_) => (mac, "failed", "broadcast_unavailable"),
            },
            Err(_) => (
                request.mac.trim().to_ascii_lowercase(),
                "failed",
                "invalid_mac",
            ),
        };
        sqlx::query(
            r#"INSERT INTO wake_on_lan_receipts
                 (request_id, mac, state, error_code, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?)
               ON CONFLICT(request_id) DO NOTHING"#,
        )
        .bind(request_id)
        .bind(mac)
        .bind(state)
        .bind(error_code)
        .bind(&now)
        .bind(&now)
        .execute(pool)
        .await?;
    }
    Ok(())
}

pub async fn report(pool: &SqlitePool) -> AppResult<Vec<WakeReport>> {
    Ok(sqlx::query_as::<_, WakeReport>(
        r#"SELECT request_id, mac, state, error_code
           FROM wake_on_lan_receipts
           ORDER BY updated_at, request_id
           LIMIT ?"#,
    )
    .bind(MAX_REPORTS)
    .fetch_all(pool)
    .await?)
}

pub async fn acknowledge(pool: &SqlitePool, request_ids: &[String]) -> AppResult<()> {
    for request_id in request_ids.iter().take(MAX_REPORTS as usize) {
        sqlx::query("DELETE FROM wake_on_lan_receipts WHERE request_id = ?")
            .bind(request_id)
            .execute(pool)
            .await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magic_packet_contains_six_ff_bytes_and_sixteen_macs() {
        let packet = magic_packet("52:54:00:aa:bb:01").expect("valid packet");
        assert_eq!(&packet[..6], &[0xff; 6]);
        for chunk in packet[6..].chunks_exact(6) {
            assert_eq!(chunk, &[0x52, 0x54, 0x00, 0xaa, 0xbb, 0x01]);
        }
    }

    #[test]
    fn magic_packet_rejects_invalid_mac() {
        assert!(magic_packet("not-a-mac").is_none());
    }

    #[tokio::test]
    async fn invalid_requests_are_durable_idempotent_and_acknowledged() {
        let pool = crate::db::connect_with_url("sqlite::memory:")
            .await
            .unwrap();
        crate::db::migrate(&pool).await.unwrap();
        let request = ManagedWakeRequest {
            request_id: "4c20e5ca-a7ae-4b27-8ce6-dff50192ed21".into(),
            mac: "invalid".into(),
        };
        apply_requests(&pool, std::slice::from_ref(&request))
            .await
            .unwrap();
        apply_requests(&pool, &[request]).await.unwrap();
        let reports = report(&pool).await.unwrap();
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].state, "failed");
        assert_eq!(reports[0].error_code, "invalid_mac");
        acknowledge(&pool, &[reports[0].request_id.clone()])
            .await
            .unwrap();
        assert!(report(&pool).await.unwrap().is_empty());
    }
}
