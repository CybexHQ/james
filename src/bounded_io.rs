//! Bounds are enforced before framing/parsing, including streams without EOF.
use std::io;

use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};

pub(crate) enum Frame {
    Line(String),
    Oversized,
    InvalidEncoding,
}

pub(crate) struct Lines<R> {
    reader: BufReader<R>,
    pending: Vec<u8>,
    limit: usize,
    discarding: bool,
}

impl<R: AsyncRead + Unpin> Lines<R> {
    pub(crate) fn new(reader: R, limit: usize) -> Self {
        Self {
            reader: BufReader::new(reader),
            pending: Vec::with_capacity(limit.min(8192)),
            limit,
            discarding: false,
        }
    }

    /// Cancel-safe. An oversized frame emits only a fixed marker, then drains
    /// through the next newline. Never expose a suffix that may contain a secret.
    pub(crate) async fn next(&mut self) -> io::Result<Option<Frame>> {
        loop {
            let bytes = self.reader.fill_buf().await?;
            if bytes.is_empty() {
                return if self.pending.is_empty() || self.discarding {
                    Ok(None)
                } else {
                    self.finish().map(Some)
                };
            }
            let end = bytes.iter().position(|byte| *byte == b'\n');
            let len = end.unwrap_or(bytes.len());
            let consumed = len + usize::from(end.is_some());
            if self.discarding {
                self.reader.consume(consumed);
                if end.is_some() {
                    self.discarding = false;
                }
                continue;
            }
            if self.pending.len().saturating_add(len) > self.limit {
                self.pending.clear();
                self.discarding = end.is_none();
                self.reader.consume(consumed);
                return Ok(Some(Frame::Oversized));
            }
            self.pending.extend_from_slice(&bytes[..len]);
            self.reader.consume(consumed);
            if end.is_some() {
                return self.finish().map(Some);
            }
        }
    }

    fn finish(&mut self) -> io::Result<Frame> {
        if self.pending.last() == Some(&b'\r') {
            self.pending.pop();
        }
        let frame = match std::str::from_utf8(&self.pending) {
            Ok(line) => Frame::Line(line.to_owned()),
            Err(_) => Frame::InvalidEncoding,
        };
        self.pending.clear();
        Ok(frame)
    }
}

pub(crate) async fn response_bytes(
    mut response: reqwest::Response,
    limit: usize,
) -> anyhow::Result<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|len| len > limit as u64)
    {
        anyhow::bail!("response exceeds the {limit} byte limit");
    }
    let mut body = Vec::with_capacity(limit.min(8192));
    while let Some(chunk) = response.chunk().await? {
        if chunk.len() > limit.saturating_sub(body.len()) {
            anyhow::bail!("response exceeds the {limit} byte limit");
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{
        io::AsyncWriteExt,
        time::{Duration, timeout},
    };

    #[tokio::test]
    async fn malformed_utf8_is_redacted_without_losing_subsequent_progress() {
        let input = b"secret-\xff\nnormal\n";
        let mut lines = Lines::new(&input[..], 64);
        assert!(matches!(
            lines.next().await.unwrap(),
            Some(Frame::InvalidEncoding)
        ));
        assert!(matches!(lines.next().await.unwrap(), Some(Frame::Line(s)) if s == "normal"));
    }

    #[tokio::test]
    async fn unfinished_line_is_bounded_and_cancellation_recovers() {
        let (mut writer, reader) = tokio::io::duplex(4096);
        let producer = tokio::spawn(async move {
            for _ in 0..8192 {
                writer.write_all(&[b'x'; 8192]).await.unwrap();
            }
            writer.write_all(b"secret-tail\nok\n").await.unwrap();
        });
        let mut lines = Lines::new(reader, 65536);
        assert!(matches!(
            lines.next().await.unwrap(),
            Some(Frame::Oversized)
        ));
        assert!(lines.pending.capacity() <= 65536);
        assert!(matches!(lines.next().await.unwrap(), Some(Frame::Line(s)) if s == "ok"));
        producer.await.unwrap();
        assert!(lines.next().await.unwrap().is_none());

        let (mut writer, reader) = tokio::io::duplex(64);
        let mut lines = Lines::new(reader, 16);
        writer.write_all(b"part").await.unwrap();
        assert!(
            timeout(Duration::from_millis(10), lines.next())
                .await
                .is_err()
        );
        writer.write_all(b"ial\r\n").await.unwrap();
        assert!(matches!(lines.next().await.unwrap(), Some(Frame::Line(s)) if s == "partial"));
    }

    #[tokio::test]
    async fn exact_limit_eof_and_oversized_json() {
        let input = b"1234\n12345\n@nix {\"msg\":\"long secret\"}\nOK";
        let mut lines = Lines::new(&input[..], 4);
        assert!(matches!(lines.next().await.unwrap(), Some(Frame::Line(s)) if s == "1234"));
        assert!(matches!(
            lines.next().await.unwrap(),
            Some(Frame::Oversized)
        ));
        assert!(matches!(
            lines.next().await.unwrap(),
            Some(Frame::Oversized)
        ));
        assert!(matches!(lines.next().await.unwrap(), Some(Frame::Line(s)) if s == "OK"));
        assert!(lines.next().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn http_chunked_overflow_stops_before_eof_and_slow_body_times_out() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut socket, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    use tokio::io::AsyncReadExt;
                    let mut request = [0; 4096];
                    let count = socket.read(&mut request).await.unwrap();
                    assert!(count > 0);
                    socket
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nabcde\r\n",
                        )
                        .await
                        .unwrap();
                    tokio::time::sleep(Duration::from_secs(5)).await;
                });
            }
        });
        let client = reqwest::Client::new();
        let response = client.get(&url).send().await.unwrap();
        assert!(
            timeout(Duration::from_secs(1), response_bytes(response, 4))
                .await
                .unwrap()
                .unwrap_err()
                .to_string()
                .contains("byte limit")
        );
        let response = client
            .get(&url)
            .timeout(Duration::from_millis(100))
            .send()
            .await
            .unwrap();
        assert!(response_bytes(response, 8).await.is_err());
        server.await.unwrap();
    }
}
