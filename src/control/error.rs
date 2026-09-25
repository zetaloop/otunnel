use bytes::BytesMut;
use futures_util::StreamExt;

use crate::net::{ErrorInfo, Response};

#[derive(Debug)]
pub struct StatusError {
    pub status: u16,
    operation: &'static str,
    pub(super) info: ErrorInfo,
}

impl StatusError {
    pub(super) fn new(status: u16, operation: &'static str) -> Self {
        Self {
            status,
            operation,
            info: ErrorInfo::default(),
        }
    }

    pub(super) async fn read(mut response: Response, operation: &'static str) -> Self {
        let mut error = Self::new(response.status.as_u16(), operation);
        let mut body = BytesMut::new();
        while let Some(chunk) = response.body.next().await {
            match chunk {
                Ok(chunk) => body.extend_from_slice(&chunk[..chunk.len().min(65536 - body.len())]),
                Err(cause) => {
                    error.info.message = format!("read error body: {cause}");
                    return error;
                }
            }
        }
        error.info = ErrorInfo::parse(&body);
        error
    }

    pub fn code(&self) -> &str {
        &self.info.code
    }

    pub fn kind(&self) -> &str {
        &self.info.kind
    }

    pub fn message(&self) -> &str {
        &self.info.message
    }

    pub fn mitigation(&self) -> &str {
        &self.info.mitigation
    }

    pub fn detail(&self) -> String {
        self.info.detail()
    }
}

impl std::fmt::Display for StatusError {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            output,
            "tunnel {} returned HTTP {}",
            self.operation, self.status
        )?;
        let detail = self.detail();
        if !detail.is_empty() {
            write!(output, ": {detail}")?;
        }
        Ok(())
    }
}

impl std::error::Error for StatusError {}
