//! What the framework adapters share: which bodies to read, and how a request becomes a [`Request`].

use crate::gatekeeper::Request;
use crate::{json, net, util, waf};

/// Forms and JSON bodies up to 64 KB are inspected.
pub const MAX_BODY: u64 = 65_536;

/// Whether the body should be read (only with a known, small length).
pub fn wants_body(method: &str, content_type: &str, length: Option<u64>) -> bool {
    let kind = content_type.to_ascii_lowercase();
    matches!(method, "POST" | "PUT" | "PATCH")
        && length.is_some_and(|l| l <= MAX_BODY)
        && (kind.contains("json") || kind.contains("x-www-form-urlencoded"))
}

/// The plain values of a request, as any framework gives them.
#[derive(Default)]
pub struct Parts {
    pub method: String,
    /// The raw (still encoded) path.
    pub raw_path: String,
    /// The raw query string, without "?".
    pub raw_query: String,
    pub content_type: String,
    pub user_agent: String,
    pub accept: String,
    pub cf_connecting_ip: String,
    pub cf_ipcountry: String,
    /// Every X-Forwarded-For header.
    pub forwarded_for: Vec<String>,
    pub requested_with: String,
    pub remote_addr: String,
}

/// The request Draco inspects, with the body when it was read.
pub fn request(p: Parts, body: Option<&[u8]>) -> Request {
    let mut params = waf::flatten_fields(&util::parse_query(&p.raw_query), 200);
    let mut form = Vec::new();
    if let Some(body) = body {
        let text = String::from_utf8_lossy(body);
        if p.content_type.to_ascii_lowercase().contains("json") {
            match json::parse(&text) {
                Ok(v) => {
                    params.extend(waf::flatten_json(&v, 200));
                    if let json::Value::Obj(m) = &v {
                        form = m
                            .iter()
                            .filter_map(|(k, x)| if let json::Value::Str(s) = x { Some((k.clone(), s.clone())) } else { None })
                            .collect();
                    }
                }
                Err(_) => params.push(text.into_owned()),
            }
        } else {
            let fields = util::parse_query(&text);
            params.extend(waf::flatten_fields(&fields, 200));
            form = util::last_values(&fields);
        }
    }
    let unmapped = net::unmap(p.remote_addr.trim()).to_string();
    // Cloudflare's country header, only when the connection really comes from Cloudflare.
    let country = if net::is_ip(&unmapped) && net::contains(net::CLOUDFLARE, &unmapped) { p.cf_ipcountry } else { String::new() };
    Request {
        method: p.method.to_ascii_uppercase(),
        path: util::decode(&p.raw_path, false),
        query: util::decode(&p.raw_query, true),
        params,
        user_agent: p.user_agent,
        remote_addr: p.remote_addr,
        cf_connecting_ip: p.cf_connecting_ip,
        forwarded_for: p.forwarded_for.join(", "),
        country,
        accept: p.accept,
        ajax: p.requested_with.eq_ignore_ascii_case("XMLHttpRequest"),
        form,
    }
}
