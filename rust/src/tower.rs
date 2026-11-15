//! Draco as a tower Layer: axum (`Router::layer`), hyper services, tonic's HTTP side. It answers
//! first; the app only sees what it lets through.

use crate::adapt::{self, Parts, MAX_BODY};
use crate::gatekeeper::{Answer, Gatekeeper};
use bytes::Bytes;
use http::header::{HeaderValue, CONTENT_LENGTH};
use http::{Request, Response, StatusCode};
use http_body::Body;
use http_body_util::BodyExt;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

/// The visitor's connection address as a request extension, for stacks without axum's ConnectInfo.
#[derive(Clone, Copy, Debug)]
pub struct RemoteAddr(pub SocketAddr);

/// `Router::new()...layer(DracoLayer::new(gate))`. With axum, serve with
/// `into_make_service_with_connect_info::<SocketAddr>()` so Draco sees the visitor's address.
#[derive(Clone)]
pub struct DracoLayer {
    gate: Arc<Gatekeeper>,
}

impl DracoLayer {
    pub fn new(gate: Arc<Gatekeeper>) -> Self {
        DracoLayer { gate }
    }

    pub fn gatekeeper(&self) -> &Arc<Gatekeeper> {
        &self.gate
    }
}

impl<S> tower_layer::Layer<S> for DracoLayer {
    type Service = DracoService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        DracoService { inner, gate: self.gate.clone() }
    }
}

/// The service the layer makes.
#[derive(Clone)]
pub struct DracoService<S> {
    inner: S,
    gate: Arc<Gatekeeper>,
}

fn header(h: &http::HeaderMap, name: &str) -> String {
    h.get(name).and_then(|v| v.to_str().ok()).unwrap_or("").to_string()
}

fn remote(ext: &http::Extensions) -> String {
    #[cfg(feature = "axum")]
    if let Some(c) = ext.get::<axum::extract::ConnectInfo<SocketAddr>>() {
        return c.0.ip().to_string();
    }
    ext.get::<RemoteAddr>().map(|r| r.0.ip().to_string()).unwrap_or_default()
}

fn render<B: From<String>>(gate: &Gatekeeper, a: &Answer) -> Response<B> {
    let r = gate.render(a);
    let mut res = Response::new(B::from(r.body));
    *res.status_mut() = StatusCode::from_u16(r.status).unwrap_or(StatusCode::FORBIDDEN);
    for (k, v) in r.headers {
        if let Ok(v) = HeaderValue::from_str(&v) {
            res.headers_mut().insert(k, v);
        }
    }
    res
}

impl<S, ReqBody, ResBody> tower_service::Service<Request<ReqBody>> for DracoService<S>
where
    S: tower_service::Service<Request<ReqBody>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    ReqBody: Body<Data = Bytes> + From<Bytes> + Send + 'static,
    ReqBody::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    ResBody: From<String> + Send + 'static,
{
    type Response = Response<ResBody>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let gate = self.gate.clone();
        Box::pin(async move {
            let (parts, body) = req.into_parts();
            let h = &parts.headers;
            let p = Parts {
                method: parts.method.as_str().to_string(),
                raw_path: parts.uri.path().to_string(),
                raw_query: parts.uri.query().unwrap_or("").to_string(),
                content_type: header(h, "content-type"),
                user_agent: header(h, "user-agent"),
                accept: header(h, "accept"),
                cf_connecting_ip: header(h, "cf-connecting-ip"),
                cf_ipcountry: header(h, "cf-ipcountry"),
                forwarded_for: h.get_all("x-forwarded-for").iter().filter_map(|v| v.to_str().ok()).map(String::from).collect(),
                requested_with: header(h, "x-requested-with"),
                remote_addr: remote(&parts.extensions),
            };
            let length = h.get(CONTENT_LENGTH).and_then(|v| v.to_str().ok()).and_then(|v| v.trim().parse::<u64>().ok());
            // A small form or JSON body is read once and handed on unchanged.
            let (body, read) = if adapt::wants_body(&p.method, &p.content_type, length) {
                match http_body_util::Limited::new(body, MAX_BODY as usize).collect().await {
                    Ok(c) => {
                        let b = c.to_bytes();
                        (ReqBody::from(b.clone()), Some(b))
                    }
                    Err(_) => (ReqBody::from(Bytes::new()), None),
                }
            } else {
                (body, None)
            };
            let https = parts.uri.scheme_str() == Some("https");
            let dreq = adapt::request(p, read.as_deref());
            // If Draco itself fails, the request goes through.
            let answer = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| gate.decide(&dreq))).unwrap_or(None);
            if let Some(a) = answer {
                return Ok(render(&gate, &a));
            }
            let mut res = inner.call(Request::from_parts(parts, body)).await?;
            // After the app answered: its own headers always win.
            for (k, v) in gate.security_headers(https) {
                if !res.headers().contains_key(k) {
                    res.headers_mut().insert(k, HeaderValue::from_static(v));
                }
            }
            Ok(res)
        })
    }
}
