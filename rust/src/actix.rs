//! Draco as actix-web middleware: `App::new().wrap(DracoMiddleware::new(gate))`. It answers first;
//! the app only sees what it lets through.

use crate::adapt::{self, Parts, MAX_BODY};
use crate::gatekeeper::Gatekeeper;
use actix_web::body::{EitherBody, MessageBody};
use actix_web::dev::{forward_ready, Payload, Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::http::header::{HeaderName, HeaderValue};
use actix_web::http::StatusCode;
use actix_web::web::{Bytes, BytesMut};
use actix_web::{Error, HttpResponse};
use futures_util::future::{ready, LocalBoxFuture, Ready};
use futures_util::StreamExt;
use std::rc::Rc;
use std::sync::Arc;

/// The middleware factory.
#[derive(Clone)]
pub struct DracoMiddleware {
    gate: Arc<Gatekeeper>,
}

impl DracoMiddleware {
    pub fn new(gate: Arc<Gatekeeper>) -> Self {
        DracoMiddleware { gate }
    }

    pub fn gatekeeper(&self) -> &Arc<Gatekeeper> {
        &self.gate
    }
}

impl<S, B> Transform<S, ServiceRequest> for DracoMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type InitError = ();
    type Transform = DracoActixService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(DracoActixService { service: Rc::new(service), gate: self.gate.clone() }))
    }
}

/// The service the middleware makes.
pub struct DracoActixService<S> {
    service: Rc<S>,
    gate: Arc<Gatekeeper>,
}

fn header(req: &ServiceRequest, name: &str) -> String {
    req.headers().get(name).and_then(|v| v.to_str().ok()).unwrap_or("").to_string()
}

fn payload(buf: Bytes) -> Payload {
    let (_, mut pl) = actix_http::h1::Payload::create(true);
    pl.unread_data(buf);
    Payload::from(pl)
}

impl<S, B> Service<ServiceRequest> for DracoActixService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, mut req: ServiceRequest) -> Self::Future {
        let svc = self.service.clone();
        let gate = self.gate.clone();
        Box::pin(async move {
            let p = Parts {
                method: req.method().as_str().to_string(),
                raw_path: req.uri().path().to_string(),
                raw_query: req.uri().query().unwrap_or("").to_string(),
                content_type: header(&req, "content-type"),
                user_agent: header(&req, "user-agent"),
                accept: header(&req, "accept"),
                cf_connecting_ip: header(&req, "cf-connecting-ip"),
                cf_ipcountry: header(&req, "cf-ipcountry"),
                forwarded_for: req.headers().get_all("x-forwarded-for").filter_map(|v| v.to_str().ok()).map(String::from).collect(),
                requested_with: header(&req, "x-requested-with"),
                remote_addr: req.peer_addr().map(|a| a.ip().to_string()).unwrap_or_default(),
            };
            let length = header(&req, "content-length").trim().parse::<u64>().ok();
            let mut read = None;
            // A small form or JSON body is read once and handed on unchanged.
            if adapt::wants_body(&p.method, &p.content_type, length) {
                let mut stream = req.parts_mut().1.take();
                let mut buf = BytesMut::new();
                while let Some(chunk) = stream.next().await {
                    let chunk = chunk?;
                    buf.extend_from_slice(&chunk);
                    if buf.len() as u64 > MAX_BODY {
                        break;
                    }
                }
                let bytes = buf.freeze();
                req.set_payload(payload(bytes.clone()));
                read = Some(bytes);
            }
            let https = req.app_config().secure();
            let dreq = adapt::request(p, read.as_deref());
            // If Draco itself fails, the request goes through.
            let answer = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| gate.decide(&dreq))).unwrap_or(None);
            if let Some(a) = answer {
                let r = gate.render(&a);
                let mut res = HttpResponse::build(StatusCode::from_u16(r.status).unwrap_or(StatusCode::FORBIDDEN));
                for (k, v) in r.headers {
                    res.insert_header((k, v));
                }
                return Ok(req.into_response(res.body(r.body)).map_into_right_body());
            }
            let mut res = svc.call(req).await?;
            // After the app answered: its own headers always win.
            for (k, v) in gate.security_headers(https) {
                let name = HeaderName::from_static(k);
                if !res.headers().contains_key(&name) {
                    res.headers_mut().insert(name, HeaderValue::from_static(v));
                }
            }
            Ok(res.map_into_left_body())
        })
    }
}
