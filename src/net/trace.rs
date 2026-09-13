use std::fmt::Write;

use bytes::Bytes;
use futures_util::StreamExt;
use http::{HeaderMap, Method, Version};
use url::{Position, Url};

use super::Response;

pub(super) struct Trace {
    component: &'static str,
    url: String,
}
impl Trace {
    pub fn request(
        component: Option<&'static str>,
        method: &Method,
        url: &Url,
        headers: &HeaderMap,
        body: &Bytes,
    ) -> Option<Self> {
        let component = component.filter(|_| tracing::enabled!(tracing::Level::DEBUG))?;
        let mut dump = format!(
            "{method} {} HTTP/1.1\r\n",
            &url[Position::BeforePath..Position::AfterQuery]
        );
        if !headers.contains_key("host") {
            writeln!(
                dump,
                "Host: {}\r",
                &url[Position::BeforeHost..Position::AfterPort]
            )
            .expect("string write");
        }
        if !headers.contains_key("content-length")
            && (!body.is_empty() || matches!(*method, Method::POST | Method::PUT))
        {
            writeln!(dump, "Content-Length: {}\r", body.len()).expect("string write");
        }
        append_headers(&mut dump, headers);
        dump.push_str(&String::from_utf8_lossy(body));
        tracing::debug!(component, %dump, "raw http request");
        Some(Self {
            component,
            url: url.to_string(),
        })
    }

    pub fn response(self, mut response: Response, version: Version) -> Response {
        let mut dump = format!("{version:?} {}\r\n", response.status);
        append_headers(&mut dump, &response.headers);
        tracing::debug!(component = self.component, url = %self.url, %dump, "raw http response");
        response.body = response
            .body
            .inspect(move |chunk| match chunk {
                Ok(chunk) => tracing::debug!(component = self.component, url = %self.url,
                    dump = %String::from_utf8_lossy(chunk), "raw http response body"),
                Err(error) => tracing::debug!(component = self.component, url = %self.url,
                    %error, "raw http response interrupted"),
            })
            .boxed();
        response
    }
}

fn append_headers(dump: &mut String, headers: &HeaderMap) {
    for (name, value) in headers {
        writeln!(
            dump,
            "{}: {}\r",
            crate::harpoon::headers::canonical(name.as_str()),
            String::from_utf8_lossy(value.as_bytes())
        )
        .expect("string write");
    }
    dump.push_str("\r\n");
}
