use std::{io, path::PathBuf, time::Duration};

use anyhow::{Context, Result};
use axum::extract::connect_info::Connected;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use tokio::net::TcpListener;
use url::Url;

use crate::{config::Health, net::Io};

pub(crate) fn loopback_address(value: &str) -> bool {
    let host = if let Some(value) = value.strip_prefix('[') {
        value.split_once(']').map_or(value, |(host, _)| host)
    } else if value
        .as_bytes()
        .iter()
        .filter(|byte| **byte == b':')
        .count()
        == 1
    {
        value.split_once(':').map_or(value, |(host, _)| host)
    } else {
        value
    };
    host == "localhost"
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

#[derive(Clone, Debug)]
pub(crate) struct Peer {
    pub remote: String,
    pub local: String,
}
impl Connected<axum::serve::IncomingStream<'_, Listener>> for Peer {
    fn connect_info(stream: axum::serve::IncomingStream<'_, Listener>) -> Self {
        stream.remote_addr().clone()
    }
}

pub(crate) enum Listener {
    Tcp(TcpListener),
    Local(Local),
}
impl Listener {
    pub async fn bind(config: &Health) -> Result<(Self, String)> {
        if let Some(socket) = &config.unix_socket {
            let path = std::path::absolute(socket)?;
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let url = format!(
                "http+unix://{}",
                URL_SAFE_NO_PAD.encode(path.to_string_lossy().as_bytes())
            );
            return Ok((Self::Local(Local::bind(path)?), url));
        }
        let address = config.listen_addr.clone();
        let address = if address.starts_with(':') {
            format!("0.0.0.0{address}")
        } else {
            address
        };
        let listener = TcpListener::bind(&address)
            .await
            .with_context(|| format!("bind health listener {address}"))?;
        let bound = listener.local_addr()?;
        let host = address
            .rsplit_once(':')
            .map(|(host, _)| host)
            .unwrap_or("")
            .trim_matches(['[', ']']);
        let host = if host.is_empty()
            || host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_unspecified())
        {
            "localhost"
        } else {
            host
        };
        let mut url = Url::parse("http://localhost")?;
        url.set_host(Some(host))?;
        url.set_port(Some(bound.port()))
            .map_err(|_| anyhow::anyhow!("invalid health port"))?;
        Ok((
            Self::Tcp(listener),
            url.as_str().trim_end_matches('/').to_owned(),
        ))
    }
}

impl axum::serve::Listener for Listener {
    type Io = Box<dyn Io>;
    type Addr = Peer;
    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let result: io::Result<(Self::Io, Self::Addr)> = match self {
                Self::Tcp(listener) => {
                    TcpListener::accept(listener)
                        .await
                        .and_then(|(stream, remote)| {
                            let peer = Peer {
                                remote: remote.to_string(),
                                local: stream.local_addr()?.to_string(),
                            };
                            Ok((Box::new(stream) as Box<dyn Io>, peer))
                        })
                }
                Self::Local(listener) => listener.accept().await.map(|stream| {
                    (
                        stream,
                        Peer {
                            remote: "local".into(),
                            local: "local".into(),
                        },
                    )
                }),
            };
            match result {
                Ok(connection) => return connection,
                Err(error) => {
                    tracing::warn!(%error, "health listener could not accept a connection");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }
    fn local_addr(&self) -> io::Result<Peer> {
        let local = match self {
            Self::Tcp(listener) => listener.local_addr()?.to_string(),
            Self::Local(listener) => listener.path.display().to_string(),
        };
        Ok(Peer {
            remote: local.clone(),
            local,
        })
    }
}

pub(crate) struct Local {
    path: PathBuf,
    #[cfg(unix)]
    listener: Option<tokio::net::UnixListener>,
    #[cfg(windows)]
    listener: Option<async_io::Async<socket2::Socket>>,
}
impl Local {
    #[cfg(unix)]
    fn bind(path: PathBuf) -> io::Result<Self> {
        Ok(Self {
            listener: Some(tokio::net::UnixListener::bind(&path)?),
            path,
        })
    }
    #[cfg(windows)]
    fn bind(path: PathBuf) -> io::Result<Self> {
        let listener = socket2::Socket::new(socket2::Domain::UNIX, socket2::Type::STREAM, None)?;
        listener.bind(&socket2::SockAddr::unix(&path)?)?;
        listener.listen(128)?;
        Ok(Self {
            path,
            listener: Some(async_io::Async::new(listener)?),
        })
    }
    #[cfg(unix)]
    async fn accept(&self) -> io::Result<Box<dyn Io>> {
        Ok(Box::new(
            self.listener
                .as_ref()
                .expect("bound socket")
                .accept()
                .await?
                .0,
        ))
    }
    #[cfg(windows)]
    async fn accept(&self) -> io::Result<Box<dyn Io>> {
        let (socket, _) = self
            .listener
            .as_ref()
            .expect("bound socket")
            .read_with(|listener| listener.accept())
            .await?;
        Ok(Box::new(crate::net::Socket(async_io::Async::new(socket)?)))
    }
}
impl Drop for Local {
    fn drop(&mut self) {
        drop(self.listener.take());
        if let Err(error) = std::fs::remove_file(&self.path)
            && error.kind() != io::ErrorKind::NotFound
        {
            tracing::warn!(%error, "could not remove health socket");
        }
    }
}
