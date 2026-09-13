use std::{
    io,
    path::{Path, PathBuf},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use anyhow::{Result, bail};
use bytes::{Bytes, BytesMut};
use futures_util::{StreamExt, TryStreamExt, future::BoxFuture, stream::BoxStream};
use http::{HeaderMap, HeaderValue, Method, StatusCode, Uri};
use http_body_util::{BodyExt, Full};
use hyper::rt::{Read, ReadBufCursor, Write};
use hyper_util::{
    client::legacy::{
        Client,
        connect::{Connected, Connection},
    },
    rt::{TokioExecutor, TokioIo},
};
use rustls::{
    ClientConfig, RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName},
};
use tokio::io::{AsyncRead, AsyncWrite};
use tower_service::Service;
use url::Url;

use crate::config::pem;

pub trait Io: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> Io for T {}

#[derive(Default)]
pub struct Options<'a> {
    pub proxy: Option<&'a str>,
    pub socket: Option<&'a str>,
    pub ca_bundle: Option<&'a str>,
    pub client_cert: Option<&'a str>,
    pub client_key: Option<&'a str>,
}

#[derive(Clone)]
pub struct Http {
    client: reqwest::Client,
    public: reqwest::Client,
    origin: Url,
    proxy: Arc<crate::proxy::Proxy>,
    local: Option<Client<Connector, Full<Bytes>>>,
}

pub struct Response {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: BoxStream<'static, Result<Bytes>>,
}
impl Response {
    pub async fn bytes(self) -> Result<Bytes> {
        Ok(self
            .body
            .try_fold(BytesMut::new(), |mut buffer, chunk| async move {
                buffer.extend_from_slice(&chunk);
                Ok(buffer)
            })
            .await?
            .freeze())
    }
}

impl Http {
    pub fn new(origin: Url, options: Options<'_>) -> Result<Self> {
        let certificates = options.ca_bundle.map(pem).transpose()?;
        let proxy = Arc::new(crate::proxy::Proxy::new(options.proxy)?);
        let builder = || -> Result<reqwest::ClientBuilder> {
            let route = proxy.clone();
            let mut builder = reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .retry(reqwest::retry::never())
                .no_proxy()
                .proxy(reqwest::Proxy::custom(move |url| {
                    route.select(url).ok().flatten().cloned()
                }));
            if let Some(certs) = &certificates {
                for certificate in reqwest::Certificate::from_pem_bundle(certs)? {
                    builder = builder.add_root_certificate(certificate);
                }
            }
            Ok(builder)
        };
        let public = builder()?.build()?;
        let mut scoped = builder()?;
        let identity = match (options.client_cert, options.client_key) {
            (Some(cert), Some(key)) => Some((pem(cert)?, pem(key)?)),
            (None, None) => None,
            _ => bail!("client_cert and client_key must be configured together"),
        };
        if let Some((cert, key)) = &identity {
            let mut combined = cert.clone();
            combined.push(b'\n');
            combined.extend_from_slice(key);
            scoped = scoped.identity(reqwest::Identity::from_pem(&combined)?);
        }
        let client = scoped.build()?;
        let local = if let Some(socket) = options.socket {
            let mut roots = RootCertStore::empty();
            let native = rustls_native_certs::load_native_certs();
            roots.add_parsable_certificates(native.certs);
            if let Some(certs) = &certificates {
                for certificate in rustls_pemfile::certs(&mut certs.as_slice()) {
                    roots.add(certificate?)?;
                }
            }
            let builder = ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::aws_lc_rs::default_provider(),
            ))
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots);
            let tls = if let Some((cert, key)) = identity {
                let certs: Vec<CertificateDer<'static>> =
                    rustls_pemfile::certs(&mut cert.as_slice()).collect::<io::Result<_>>()?;
                let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key.as_slice())?
                    .ok_or_else(|| anyhow::anyhow!("client_key contains no private key"))?;
                builder.with_client_auth_cert(certs, key)?
            } else {
                builder.with_no_client_auth()
            };
            let connector = Connector {
                path: crate::config::path(socket)?,
                tls: Arc::new(tls),
            };
            Some(Client::builder(TokioExecutor::new()).build(connector))
        } else {
            None
        };
        Ok(Self {
            client,
            public,
            origin,
            proxy,
            local,
        })
    }

    pub(crate) fn proxied(&self, url: &Url) -> Result<bool> {
        if self.local.is_some() && url.origin() == self.origin.origin() {
            return Ok(false);
        }
        Ok(self.proxy.select(url)?.is_some())
    }

    pub async fn send(
        &self,
        method: Method,
        url: &Url,
        mut headers: HeaderMap,
        body: Bytes,
    ) -> Result<Response> {
        headers
            .entry("user-agent")
            .or_insert(HeaderValue::from_static(concat!(
                "otunnel/",
                env!("CARGO_PKG_VERSION")
            )));
        if url.origin() == self.origin.origin()
            && let Some(client) = &self.local
        {
            let mut request = http::Request::builder().method(method).uri(url.as_str());
            *request.headers_mut().expect("new request has headers") = headers;
            let response = client.request(request.body(Full::new(body))?).await?;
            let (parts, body) = response.into_parts();
            return Ok(Response {
                status: parts.status,
                headers: parts.headers,
                body: body.into_data_stream().map_err(anyhow::Error::from).boxed(),
            });
        }
        self.proxy.select(url)?;
        let client = if url.origin() == self.origin.origin() {
            &self.client
        } else {
            &self.public
        };
        let response = client
            .request(method, url.clone())
            .headers(headers)
            .body(body)
            .send()
            .await?;
        Ok(Response {
            status: response.status(),
            headers: response.headers().clone(),
            body: response.bytes_stream().map_err(anyhow::Error::from).boxed(),
        })
    }

    pub async fn follow(
        &self,
        mut method: Method,
        mut url: Url,
        mut headers: HeaderMap,
        mut body: Bytes,
        redirects: usize,
    ) -> Result<Response> {
        for attempt in 0..=redirects {
            let response = self
                .send(method.clone(), &url, headers.clone(), body.clone())
                .await?;
            let Some(location) = response
                .headers
                .get("location")
                .filter(|_| response.status.is_redirection())
            else {
                return Ok(response);
            };
            if attempt == redirects {
                return Ok(response);
            }
            let next = url.join(location.to_str()?)?;
            if next.origin() != url.origin() {
                headers.clear();
            }
            if response.status == StatusCode::SEE_OTHER
                || (method == Method::POST
                    && matches!(
                        response.status,
                        StatusCode::MOVED_PERMANENTLY | StatusCode::FOUND
                    ))
            {
                method = Method::GET;
                body = Bytes::new();
                headers.remove("content-type");
                headers.remove("content-length");
            }
            url = next;
        }
        unreachable!()
    }
}

#[derive(Clone)]
struct Connector {
    path: PathBuf,
    tls: Arc<ClientConfig>,
}
impl Service<Uri> for Connector {
    type Response = LocalIo;
    type Error = io::Error;
    type Future = BoxFuture<'static, io::Result<LocalIo>>;
    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn call(&mut self, uri: Uri) -> Self::Future {
        let path = self.path.clone();
        let tls = self.tls.clone();
        Box::pin(async move {
            let stream = connect(&path).await?;
            let stream: Box<dyn Io> = if uri.scheme_str() == Some("https") {
                let host = ServerName::try_from(uri.host().unwrap_or("localhost").to_owned())
                    .map_err(io::Error::other)?;
                Box::new(
                    tokio_rustls::TlsConnector::from(tls)
                        .connect(host, stream)
                        .await?,
                )
            } else {
                stream
            };
            Ok(LocalIo(TokioIo::new(stream)))
        })
    }
}

struct LocalIo(TokioIo<Box<dyn Io>>);
impl Connection for LocalIo {
    fn connected(&self) -> Connected {
        Connected::new()
    }
}
impl Read for LocalIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}
impl Write for LocalIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

#[cfg(unix)]
pub async fn connect(path: &Path) -> io::Result<Box<dyn Io>> {
    Ok(Box::new(tokio::net::UnixStream::connect(path).await?))
}

#[cfg(windows)]
pub(crate) struct Socket(pub async_io::Async<socket2::Socket>);

#[cfg(windows)]
impl AsyncRead for Socket {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        use tokio_util::compat::FuturesAsyncReadCompatExt;
        Pin::new(&mut (&self.0).compat()).poll_read(cx, buffer)
    }
}

#[cfg(windows)]
impl AsyncWrite for Socket {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        use tokio_util::compat::FuturesAsyncWriteCompatExt;
        Pin::new(&mut (&self.0).compat_write()).poll_write(cx, buffer)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        use tokio_util::compat::FuturesAsyncWriteCompatExt;
        Pin::new(&mut (&self.0).compat_write()).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(self.0.get_ref().shutdown(std::net::Shutdown::Write))
    }
}

#[cfg(windows)]
pub async fn connect(path: &Path) -> io::Result<Box<dyn Io>> {
    use async_io::Async;
    use socket2::{Domain, SockAddr, Type};

    let socket = Async::new(socket2::Socket::new(Domain::UNIX, Type::STREAM, None)?)?;
    match socket.get_ref().connect(&SockAddr::unix(path)?) {
        Ok(()) => (),
        Err(error)
            if error.kind() == io::ErrorKind::WouldBlock
                || matches!(error.raw_os_error(), Some(10035..=10037)) =>
        {
            socket.writable().await?;
            if let Some(error) = socket.get_ref().take_error()? {
                return Err(error);
            }
        }
        Err(error) => return Err(error),
    }
    Ok(Box::new(Socket(socket)))
}

pub fn connecting(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause.downcast_ref::<io::Error>().is_some_and(|error| {
            matches!(
                error.kind(),
                io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound
            )
        }) || cause
            .downcast_ref::<reqwest::Error>()
            .is_some_and(reqwest::Error::is_connect)
    })
}
