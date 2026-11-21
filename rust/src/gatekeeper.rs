//! Decides, in the same order as every edition: block list, country, signatures, pace.

use crate::blocks::Blocks;
use crate::crowdsec::CrowdSec;
use crate::geo::GeoFile;
use crate::options::Options;
use crate::review::{self, ReviewRequest};
use crate::store::{Clock, Event, MemoryStore, Store};
use crate::{json, net, waf};
use std::collections::hash_map::RandomState;
use std::collections::HashMap;
use std::hash::{BuildHasher, Hasher};
use std::sync::{Arc, RwLock};

pub const VERSION: &str = "0.1.35";

/// Sensitive path endings, besides any POST.
pub const SENSITIVE_PATHS: &[&str] = &[
    "/wp-login.php",
    "/login",
    "/register",
    "/signup",
    "/user/login",
    "/user/register",
    "/admin",
    "/auth/login",
    "/api/auth/local",
    "/api/auth/local/register",
    "/admin/login",
    "/accounts/login/",
    "/accounts/signup/",
    "/token",
    "/auth/token",
    "/Identity/Account/Login",
    "/Identity/Account/Register",
    "/Account/Login",
    "/Account/Register",
    "/j_security_check",
    "/oauth2/token",
    "/protocol/openid-connect/token",
];

pub const DEFAULT_TEXTS: &[(&str, &str)] = &[
    ("title", "Request blocked"),
    ("text", "This request was blocked by the site's security. If you think this is a mistake, contact the site owner."),
    ("too_many", "Too many pages in a short time. Please wait a moment and try again."),
    (
        "text_with_review",
        "This request was blocked by the site's security. If you think this is a mistake, tell the site owner what you were doing:",
    ),
    ("review_email", "Your e-mail"),
    ("review_message", "What were you doing?"),
    ("review_button", "Ask for a review"),
    ("review_sent_title", "Request sent"),
    ("review_sent_text", "Thank you. The owner of the site will look at it and, if it was a mistake, let you through."),
];

const CRAWLERS: &[(&str, &[&str])] = &[
    ("googlebot", &["googlebot.com", "google.com", "googleusercontent.com"]),
    ("google-inspectiontool", &["googlebot.com", "google.com", "googleusercontent.com"]),
    ("googleother", &["googlebot.com", "google.com", "googleusercontent.com"]),
    ("adsbot-google", &["googlebot.com", "google.com", "googleusercontent.com"]),
    ("mediapartners-google", &["googlebot.com", "google.com", "googleusercontent.com"]),
    ("bingbot", &["search.msn.com"]),
    ("msnbot", &["search.msn.com"]),
    ("adidxbot", &["search.msn.com"]),
    ("applebot", &["applebot.apple.com"]),
    ("yandex", &["yandex.ru", "yandex.net", "yandex.com"]),
];

/// One visitor request in plain values, whatever the framework.
#[derive(Debug, Clone)]
pub struct Request {
    pub method: String,
    /// The decoded path.
    pub path: String,
    /// The decoded query string.
    pub query: String,
    /// Decoded query and body values (and keys), for the firewall only.
    pub params: Vec<String>,
    pub user_agent: String,
    /// The connection's own address.
    pub remote_addr: String,
    pub cf_connecting_ip: String,
    /// X-Forwarded-For, every header joined with ", ".
    pub forwarded_for: String,
    /// Cloudflare's CF-IPCountry, only when the connection comes from Cloudflare.
    pub country: String,
    pub accept: String,
    /// X-Requested-With: XMLHttpRequest.
    pub ajax: bool,
    /// The text fields of a posted form, for the review form.
    pub form: Vec<(String, String)>,
}

impl Default for Request {
    fn default() -> Self {
        Request {
            method: "GET".into(),
            path: "/".into(),
            query: String::new(),
            params: Vec::new(),
            user_agent: String::new(),
            remote_addr: String::new(),
            cf_connecting_ip: String::new(),
            forwarded_for: String::new(),
            country: String::new(),
            accept: String::new(),
            ajax: false,
            form: Vec::new(),
        }
    }
}

/// What stops a request: 403 (a rule), 429 (the pace) or 200 (the review thanks page).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    pub status: u16,
    /// The rule, for the evidence only (the page never shows it).
    pub why: String,
    /// Seconds for Retry-After (429).
    pub retry: u32,
    /// The review form of the 403 page, or "".
    pub form: String,
}

impl Answer {
    fn new(status: u16, why: &str) -> Self {
        Answer { status, why: why.into(), retry: 0, form: String::new() }
    }
}

/// A rendered answer.
#[derive(Debug, Clone)]
pub struct Rendered {
    pub status: u16,
    pub headers: Vec<(&'static str, String)>,
    pub body: String,
}

/// Proves search engines through the reverse DNS.
pub trait Resolver: Send + Sync {
    /// The names of an address.
    fn reverse(&self, ip: &str) -> std::io::Result<Vec<String>>;
    /// The addresses of a name.
    fn forward(&self, host: &str) -> std::io::Result<Vec<String>>;
}

/// The system's resolver (feature "dns").
#[cfg(feature = "dns")]
pub struct SystemResolver;

#[cfg(feature = "dns")]
impl Resolver for SystemResolver {
    fn reverse(&self, ip: &str) -> std::io::Result<Vec<String>> {
        let addr: std::net::IpAddr = ip.parse().map_err(std::io::Error::other)?;
        dns_lookup::lookup_addr(&addr).map(|n| vec![n])
    }

    fn forward(&self, host: &str) -> std::io::Result<Vec<String>> {
        dns_lookup::lookup_host(host).map(|a| a.into_iter().map(|x| x.to_string()).collect())
    }
}

type Callback<T> = Arc<dyn Fn(&T) + Send + Sync>;

/// The decisions. Share one per app (it is cheap to clone through an `Arc`).
pub struct Gatekeeper {
    options: Options,
    store: Arc<dyn Store>,
    blocks: Blocks,
    texts: HashMap<String, String>,
    trusted: Vec<String>,
    admins: Vec<String>,
    crowdsec: Option<Arc<CrowdSec>>,
    resolver: RwLock<Option<Arc<dyn Resolver>>>,
    geo: RwLock<Option<Arc<GeoFile>>>,
    on_event: RwLock<Option<Callback<Event>>>,
    on_review: RwLock<Option<Callback<ReviewRequest>>>,
    now: Clock,
}

fn remote(remote_addr: &str) -> String {
    let ip = net::unmap(remote_addr.trim());
    if net::is_ip(ip) {
        ip.to_string()
    } else {
        "0.0.0.0".into()
    }
}

fn two_letters(s: &str) -> bool {
    s.len() == 2 && s.bytes().all(|b| b.is_ascii_uppercase())
}

impl Gatekeeper {
    /// With the counters and the block list in this process.
    pub fn new(options: Options) -> Self {
        Self::build(options, None, Arc::new(crate::util::now))
    }

    /// With a shared store (e.g. on Redis).
    pub fn with_store(options: Options, store: Arc<dyn Store>) -> Self {
        Self::build(options, Some(store), Arc::new(crate::util::now))
    }

    /// With its own clock in Unix seconds (for tests); `store` None = in memory with that clock.
    pub fn with_clock(options: Options, store: Option<Arc<dyn Store>>, now: Clock) -> Self {
        Self::build(options, store, now)
    }

    fn build(options: Options, store: Option<Arc<dyn Store>>, now: Clock) -> Self {
        let store: Arc<dyn Store> = store.unwrap_or_else(|| Arc::new(MemoryStore::with_clock(now.clone())));
        let mut texts: HashMap<String, String> = DEFAULT_TEXTS.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        texts.extend(options.texts.clone());
        let trusted = net::parse(&options.trusted_proxies);
        let admins: Vec<String> = options.admin_ips.iter().map(|i| i.trim().to_string()).filter(|i| !i.is_empty()).collect();
        let geo = (!options.geo.file.is_empty()).then(|| GeoFile::new(&options.geo.file, true));
        let crowdsec = (!options.crowdsec_url.is_empty() && !options.crowdsec_api_key.is_empty())
            .then(|| Arc::new(CrowdSec::new(&options.crowdsec_url, &options.crowdsec_api_key, store.clone(), admins.clone(), now.clone())));
        #[cfg(feature = "dns")]
        let resolver: Option<Arc<dyn Resolver>> = Some(Arc::new(SystemResolver));
        #[cfg(not(feature = "dns"))]
        let resolver: Option<Arc<dyn Resolver>> = None;
        let g = Gatekeeper {
            blocks: Blocks::new(store.clone()),
            store,
            texts,
            trusted,
            admins,
            crowdsec,
            resolver: RwLock::new(resolver),
            geo: RwLock::new(geo),
            on_event: RwLock::new(None),
            on_review: RwLock::new(None),
            now,
            options,
        };
        if g.options.log_events {
            g.log_to_stderr();
        }
        g
    }

    pub fn options(&self) -> &Options {
        &self.options
    }
    pub fn store(&self) -> &Arc<dyn Store> {
        &self.store
    }
    pub fn blocks(&self) -> &Blocks {
        &self.blocks
    }
    pub fn texts(&self) -> &HashMap<String, String> {
        &self.texts
    }
    /// The CrowdSec bridge, when it is configured.
    pub fn crowdsec(&self) -> Option<&Arc<CrowdSec>> {
        self.crowdsec.as_ref()
    }
    pub fn now(&self) -> f64 {
        (self.now)()
    }
    /// None turns the search-engine proof off (search engines are then paced like anyone).
    pub fn set_resolver(&self, r: Option<Arc<dyn Resolver>>) {
        *self.resolver.write().unwrap_or_else(|e| e.into_inner()) = r;
    }
    pub fn set_geo(&self, g: Option<Arc<GeoFile>>) {
        *self.geo.write().unwrap_or_else(|e| e.into_inner()) = g;
    }
    pub fn on_event(&self, f: impl Fn(&Event) + Send + Sync + 'static) {
        *self.on_event.write().unwrap_or_else(|e| e.into_inner()) = Some(Arc::new(f));
    }
    pub fn on_review(&self, f: impl Fn(&ReviewRequest) + Send + Sync + 'static) {
        *self.on_review.write().unwrap_or_else(|e| e.into_inner()) = Some(Arc::new(f));
    }

    /// Writes every line of evidence and review request as a JSON line on standard error.
    pub fn log_to_stderr(&self) {
        self.on_event(|e| {
            eprintln!("{}", json::write(&json::Value::Obj(vec![("draco".into(), "event".into()), ("event".into(), e.to_json())])))
        });
        self.on_review(|r| {
            let v = json::Value::Obj(vec![
                ("time".into(), r.time.into()),
                ("ip".into(), r.ip.as_str().into()),
                ("rule".into(), r.rule.as_str().into()),
                ("email".into(), r.email.as_str().into()),
                ("message".into(), r.message.as_str().into()),
                ("userAgent".into(), r.user_agent.as_str().into()),
            ]);
            eprintln!("{}", json::write(&json::Value::Obj(vec![("draco".into(), "review".into()), ("review".into(), v)])));
        });
    }

    fn proxies(&self) -> Vec<String> {
        if self.trusted.is_empty() {
            net::LOCAL_PROXIES.iter().map(|s| s.to_string()).collect()
        } else {
            self.trusted.clone()
        }
    }

    /// The visitor's address: the connection's own, unless a proxy header is chosen AND the connection
    /// comes from a trusted proxy. X-Forwarded-For is read from the right.
    pub fn ip(&self, r: &Request) -> String {
        let mut addr = remote(&r.remote_addr);
        match self.options.proxy.as_str() {
            "cf" => {
                let cf = r.cf_connecting_ip.trim();
                if !cf.is_empty() && (net::contains(net::CLOUDFLARE, &addr) || net::contains(&self.trusted, &addr)) && net::is_ip(cf) {
                    return cf.to_string();
                }
            }
            "xff" => {
                let proxies = self.proxies();
                if r.forwarded_for.trim().is_empty() || !net::contains(&proxies, &addr) {
                    return addr;
                }
                for hop in r.forwarded_for.split(',').rev() {
                    let hop = hop.trim();
                    if !net::is_ip(hop) {
                        return addr;
                    }
                    if !net::contains(&proxies, hop) {
                        return hop.to_string();
                    }
                    addr = hop.to_string();
                }
            }
            _ => {}
        }
        addr
    }

    fn reviewing(&self) -> bool {
        self.options.review_secret.len() >= 16
    }

    /// The answer that stops the request, or None to let it through.
    pub fn decide(&self, r: &Request) -> Option<Answer> {
        let mut a = self.rules(r)?;
        if a.status == 403 && self.reviewing() {
            a.form = review::form(&self.options.review_secret, &self.ip(r), &a.why, self.now(), &self.texts);
        }
        Some(a)
    }

    fn rules(&self, r: &Request) -> Option<Answer> {
        if let Some(c) = &self.crowdsec {
            c.maybe_sync();
        }
        let c = &self.options;
        let ip = self.ip(r);
        for p in &c.except {
            let prefix = format!("/{}", p.trim_start_matches('/'));
            if prefix != "/" && r.path.starts_with(&prefix) {
                return None;
            }
        }
        let field = |k: &str| r.form.iter().rev().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
        if self.reviewing() && r.method == "POST" && field(review::FIELD) == Some("1") {
            if let Some(req) = review::accept(&*self.store, &c.review_secret, &ip, &r.user_agent, &r.form, self.now()) {
                let rule = if req.rule.is_empty() { "blocked" } else { &req.rule };
                self.log(r, &ip, "review", "pending", &[format!("review_{rule}")], &req.message, Some(&req.email));
                if let Some(cb) = self.on_review.read().unwrap_or_else(|e| e.into_inner()).clone() {
                    cb(&req);
                }
            }
            // The same answer either way, so a script learns nothing.
            return Some(Answer::new(200, "review"));
        }
        if self.admins.contains(&ip) {
            return None;
        }
        let waf_mode = if c.waf.is_empty() { "log" } else { c.waf.as_str() };
        if waf_mode != "off" {
            if self.is_sensitive(r) && self.blocks.is_blocked(&ip, self.now()) {
                return Some(Answer::new(403, "blocked"));
            }
            let country = self.refused_country(r, &ip);
            if !country.is_empty() {
                let blocking = c.geo.action == "block";
                self.log(
                    r,
                    &ip,
                    "waf:geo",
                    if blocking { "bot" } else { "doubtful" },
                    &["waf_geo".into()],
                    &format!("{country} {}", r.path),
                    None,
                );
                if blocking {
                    return Some(Answer::new(403, "geo"));
                }
            }
            if let Some(rule) = waf::inspect(&r.path, &r.query, &r.params, &r.user_agent) {
                self.record(r, &ip, rule, waf_mode == "block");
                if waf_mode == "block" {
                    return Some(Answer::new(403, rule));
                }
            }
        }
        if !c.pace.is_empty() && c.pace != "off" && wants_page(r) {
            let t = self.now();
            let minute = (t as i64) / 60;
            let ip_hits = self.store.bump(&format!("draco:rl:i:{ip}:{minute}"), 120);
            let net_hits = self.store.bump(&format!("draco:rl:n:{}:{minute}", net::network(&ip)), 120);
            let (ip_limit, net_limit) = (limit(c.rate_ip, 120), limit(c.rate_net, 600));
            let over = if ip_hits > ip_limit {
                "ip"
            } else if net_hits > net_limit {
                "net"
            } else {
                ""
            };
            if !over.is_empty() && !self.verified_crawler(&ip, &r.user_agent) {
                let block = c.pace == "block";
                if ip_hits == ip_limit + 1 || net_hits == net_limit + 1 {
                    let reason = format!("anticopy_{over}_{}", if block { "block" } else { "log" });
                    self.log(r, &ip, &format!("anticopy:{over}"), "doubtful", &[reason], &r.path, None);
                }
                if block {
                    return Some(Answer {
                        status: 429,
                        why: "pace".into(),
                        retry: (60 - (t as i64 % 60)).max(1) as u32,
                        form: String::new(),
                    });
                }
            }
        }
        None
    }

    fn is_sensitive(&self, r: &Request) -> bool {
        if r.method == "POST" {
            return true;
        }
        if self.options.sensitive.is_empty() {
            SENSITIVE_PATHS.iter().any(|e| r.path.ends_with(e))
        } else {
            self.options.sensitive.iter().any(|e| !e.is_empty() && r.path.ends_with(e.as_str()))
        }
    }

    fn refused_country(&self, r: &Request, ip: &str) -> String {
        let g = &self.options.geo;
        let list: Vec<String> = g.countries.iter().map(|x| x.trim().to_ascii_uppercase()).filter(|x| two_letters(x)).collect();
        if g.mode.is_empty() || g.mode == "off" || list.is_empty() {
            return String::new();
        }
        if g.scope != "site" && !self.is_sensitive(r) {
            return String::new();
        }
        let mut country = r.country.to_ascii_uppercase();
        if !two_letters(&country) {
            if let Some(file) = self.geo.read().unwrap_or_else(|e| e.into_inner()).clone() {
                country = file.country(ip).unwrap_or_default();
            }
        }
        // Unknown, Tor ("T1") or anonymous ("XX"): not refused for its country.
        if !two_letters(&country) || country == "XX" || country == "T1" {
            return String::new();
        }
        let listed = list.contains(&country);
        if (g.mode == "block" && !listed) || (g.mode == "allow" && listed) {
            return String::new();
        }
        if self.verified_crawler(ip, &r.user_agent) {
            String::new()
        } else {
            country
        }
    }

    fn record(&self, r: &Request, ip: &str, rule: &str, blocking: bool) {
        let detail = if r.query.is_empty() { r.path.clone() } else { format!("{}?{}", r.path, r.query) };
        self.log(r, ip, &format!("waf:{rule}"), if blocking { "bot" } else { "doubtful" }, &[format!("waf_{rule}")], &detail, None);
        if !blocking {
            return;
        }
        let hits = self.store.bump(&format!("draco:waf:{ip}"), 600);
        // An address read from a header nobody vouches for is never blocked: it could be anybody's.
        let vouched = ip == remote(&r.remote_addr) || !self.options.proxy.is_empty();
        if hits >= 5 && vouched && !self.blocks.is_blocked(ip, self.now()) {
            self.blocks.add(ip, 7, &format!("Firewall: {hits} attacks in 10 minutes"), true, self.now());
        }
    }

    /// A search engine proved by its reverse DNS and the forward lookup back; cached a day.
    pub fn verified_crawler(&self, ip: &str, user_agent: &str) -> bool {
        let ua = user_agent.to_lowercase();
        let Some((token, domains)) = CRAWLERS.iter().find(|(t, _)| ua.contains(t)) else {
            return false;
        };
        let Some(res) = self.resolver.read().unwrap_or_else(|e| e.into_inner()).clone() else {
            return false;
        };
        let key = format!("draco:crawler:{ip}:{token}");
        match self.store.get(&key).as_deref() {
            Some("y") => return true,
            Some("n") => return false,
            _ => {}
        }
        let ok = resolves_back(&*res, ip, domains);
        self.store.set(&key, if ok { "y" } else { "n" }, 86_400);
        ok
    }

    #[allow(clippy::too_many_arguments)]
    fn log(&self, r: &Request, ip: &str, endpoint: &str, verdict: &str, reasons: &[String], detail: &str, email: Option<&str>) {
        let Some(cb) = self.on_event.read().unwrap_or_else(|e| e.into_inner()).clone() else {
            return;
        };
        let max = if endpoint == "review" { 500 } else { 200 };
        cb(&Event {
            time: self.now() as i64,
            ip: ip.into(),
            remote: remote(&r.remote_addr),
            endpoint: endpoint.into(),
            verdict: verdict.into(),
            reasons: reasons.to_vec(),
            user_agent: r.user_agent.chars().take(255).collect(),
            detail: detail.chars().take(max).collect(),
            email: email.map(String::from),
        });
    }

    /// Security headers to add, unless the application already set them.
    pub fn security_headers(&self, https: bool) -> Vec<(&'static str, &'static str)> {
        let mut o = Vec::new();
        if self.options.headers {
            o.push(("x-content-type-options", "nosniff"));
            o.push(("x-frame-options", "SAMEORIGIN"));
            o.push(("referrer-policy", "strict-origin-when-cross-origin"));
            o.push(("permissions-policy", "camera=(), microphone=(), geolocation=(), interest-cohort=()"));
        }
        if https && self.options.hsts {
            o.push(("strict-transport-security", "max-age=15552000"));
        }
        o
    }

    /// The status, headers and body of an answer.
    pub fn render(&self, a: &Answer) -> Rendered {
        let t = |k: &str| self.texts.get(k).cloned().unwrap_or_default();
        if a.status == 429 {
            return Rendered {
                status: 429,
                headers: vec![
                    ("retry-after", a.retry.to_string()),
                    ("content-type", "text/plain; charset=UTF-8".into()),
                    ("cache-control", "no-store".into()),
                    ("x-robots-tag", "noindex".into()),
                ],
                body: t("too_many"),
            };
        }
        let headers = vec![
            ("content-type", "text/html; charset=UTF-8".to_string()),
            ("cache-control", "no-store".into()),
            ("x-robots-tag", "noindex, nofollow".into()),
        ];
        if a.status == 200 {
            return Rendered { status: 200, headers, body: page(&t("review_sent_title"), &t("review_sent_text"), "") };
        }
        let body = if a.form.is_empty() { page(&t("title"), &t("text"), "") } else { page(&t("title"), &t("text_with_review"), &a.form) };
        Rendered { status: 403, headers, body }
    }
}

fn limit(v: u32, fallback: i64) -> i64 {
    if v >= 10 {
        v as i64
    } else {
        fallback
    }
}

fn wants_page(r: &Request) -> bool {
    let accept = r.accept.to_lowercase();
    (r.method == "GET" || r.method == "HEAD") && (accept.is_empty() || accept.contains("text/html")) && !r.ajax
}

fn resolves_back(res: &dyn Resolver, ip: &str, domains: &[&str]) -> bool {
    let Some(want) = net::to_bytes(ip) else {
        return false;
    };
    let Ok(names) = res.reverse(ip) else {
        return false;
    };
    for name in names.iter().take(3) {
        let h = name.trim().to_lowercase();
        let h = h.trim_end_matches('.');
        if !domains.iter().any(|d| h == *d || h.ends_with(&format!(".{d}"))) {
            continue;
        }
        if let Ok(addrs) = res.forward(h) {
            if addrs.iter().any(|a| net::to_bytes(a).as_deref() == Some(want.as_slice())) {
                return true;
            }
        }
    }
    false
}

/// The 403 page: it never says which rule matched; the reference ties it to the evidence.
pub fn page(title: &str, text: &str, extra: &str) -> String {
    let mut h = RandomState::new().build_hasher();
    h.write_u128(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0));
    let reference = format!("{:010x}", h.finish() & 0xff_ffff_ffff);
    format!(
        "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><meta name=\"robots\" content=\"noindex,nofollow\">\
<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>403</title>\
<style>body{{font:16px/1.5 system-ui,sans-serif;background:#f4f5f7;color:#1d2327;display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0;padding:20px;box-sizing:border-box}}main{{background:#fff;border-radius:12px;padding:32px;max-width:440px;width:100%;box-shadow:0 2px 12px rgba(0,0,0,.08);text-align:center}}form{{text-align:left;margin-top:20px}}label{{display:block;font-size:14px;margin:10px 0 4px}}input,textarea{{width:100%;box-sizing:border-box;padding:8px;border:1px solid #c3c4c7;border-radius:6px;font:inherit}}button{{margin-top:12px;padding:9px 16px;border:0;border-radius:6px;background:#2271b1;color:#fff;font:inherit;cursor:pointer}}.hp{{position:absolute;left:-9999px}}</style></head><body><main>\
<h1 style=\"font-size:20px\">{}</h1><p>{}</p>{extra}<p style=\"color:#64748b;font-size:13px\">Ref. {reference}</p></main></body></html>",
        review::html(title),
        review::html(text),
    )
}
