//! Draco in real servers: axum on tokio (the tower layer, configured in code) and actix-web (the
//! middleware, configured from DRACO_INSOMNIS_* variables). Real sockets, real HTTP.

use draco_insomnis::{DracoLayer, DracoMiddleware, Gatekeeper, Options, VERSION};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

const UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0 Safari/537.36";
const ATTACK: &str = "/search?q=1%27%20union%20select%20password%20from%20users--%20";
const FORM: &str = "application/x-www-form-urlencoded";
const SECRET: &str = "owner-secret-0123456789";

struct Res {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

impl Res {
    fn all(&self, name: &str) -> Vec<&str> {
        self.headers.iter().filter(|(k, _)| k == name).map(|(_, v)| v.as_str()).collect()
    }
}

fn dechunk(mut b: &[u8]) -> Vec<u8> {
    let mut o = Vec::new();
    loop {
        let Some(end) = b.windows(2).position(|w| w == b"\r\n") else { return o };
        let size = usize::from_str_radix(String::from_utf8_lossy(&b[..end]).split(';').next().unwrap_or("0").trim(), 16).unwrap_or(0);
        if size == 0 {
            return o;
        }
        o.extend_from_slice(&b[end + 2..end + 2 + size]);
        b = &b[end + 4 + size..];
    }
}

fn send(addr: SocketAddr, method: &str, path: &str, kind: Option<&str>, body: &str) -> Res {
    let mut s = TcpStream::connect(addr).expect("connect");
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\nUser-Agent: {UA}\r\nConnection: close\r\n");
    if let Some(t) = kind {
        req += &format!("Content-Type: {t}\r\n");
    }
    if method != "GET" {
        req += &format!("Content-Length: {}\r\n", body.len());
    }
    req += "\r\n";
    req += body;
    s.write_all(req.as_bytes()).expect("write");
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).expect("read");
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap_or(raw.len());
    let head = String::from_utf8_lossy(&raw[..split]).into_owned();
    let mut lines = head.split("\r\n");
    let status = lines.next().unwrap_or("").split(' ').nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    let headers: Vec<(String, String)> =
        lines.filter_map(|l| l.split_once(':')).map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string())).collect();
    let rest = raw.get(split + 4..).unwrap_or(&[]);
    let chunked = headers.iter().any(|(k, v)| k == "transfer-encoding" && v.contains("chunked"));
    let body = String::from_utf8_lossy(&if chunked { dechunk(rest) } else { rest.to_vec() }).into_owned();
    Res { status, headers, body }
}

fn enc(s: &str) -> String {
    s.bytes().map(|b| if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") }).collect()
}

fn form(fields: &[(String, String)]) -> String {
    fields.iter().map(|(k, v)| format!("{}={}", enc(k), enc(v))).collect::<Vec<_>>().join("&")
}

fn f(pairs: &[(&str, &str)]) -> String {
    form(&pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect::<Vec<_>>())
}

fn axum_server(gate: Arc<Gatekeeper>) -> SocketAddr {
    use axum::routing::{get, post};
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    l.set_nonblocking(true).unwrap();
    std::thread::spawn(move || {
        tokio::runtime::Runtime::new().unwrap().block_on(async move {
            let app = axum::Router::new()
                .route("/", get(|| async { "page" }))
                .route("/own", get(|| async { ([("x-frame-options", "DENY")], "own") }))
                .route("/search", get(|| async { "results" }).post(|| async { "results" }))
                .route("/echo", post(|f: axum::Form<HashMap<String, String>>| async move { format!("name={}", f.0.get("name").cloned().unwrap_or_default()) }))
                .route("/json", post(|b: String| async move { format!("json={b}") }))
                .layer(DracoLayer::new(gate));
            let listener = tokio::net::TcpListener::from_std(l).unwrap();
            axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await.unwrap();
        });
    });
    addr
}

fn actix_server(gate: Arc<Gatekeeper>) -> SocketAddr {
    use actix_web::{web, App, HttpResponse, HttpServer};
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    std::thread::spawn(move || {
        actix_web::rt::System::new().block_on(async move {
            HttpServer::new(move || {
                App::new()
                    .wrap(DracoMiddleware::new(gate.clone()))
                    .route("/", web::get().to(|| async { "page" }))
                    .route("/own", web::get().to(|| async { HttpResponse::Ok().insert_header(("x-frame-options", "DENY")).body("own") }))
                    .route("/search", web::get().to(|| async { "results" }))
                    .route("/search", web::post().to(|| async { "results" }))
                    .route(
                        "/echo",
                        web::post().to(|f: web::Form<HashMap<String, String>>| async move { format!("name={}", f.get("name").cloned().unwrap_or_default()) }),
                    )
                    .route("/json", web::post().to(|b: String| async move { format!("json={b}") }))
            })
            .workers(1)
            .listen(l)
            .unwrap()
            .run()
            .await
            .unwrap();
        });
    });
    addr
}

fn main() {
    let mut fails = 0;
    let mut check = |name: String, ok: bool| {
        println!("{} - {name}", if ok { "ok  " } else { "FAIL" });
        if !ok {
            fails += 1;
        }
    };
    for name in ["axum (tower layer)", "actix-web (middleware)"] {
        let asked: Arc<Mutex<Vec<String>>> = Arc::default();
        let options = if name.starts_with("axum") {
            Options { waf: "block".into(), headers: true, review_secret: SECRET.into(), ..Options::default() }
        } else {
            // As from the environment: DRACO_INSOMNIS_WAF=block and so on.
            Options::from_env_vars([("DRACO_INSOMNIS_WAF", "block"), ("DRACO_INSOMNIS_HEADERS", "1"), ("DRACO_INSOMNIS_REVIEW_SECRET", SECRET), ("PROXY", "xff")])
        };
        let gate = Arc::new(Gatekeeper::new(options));
        gate.set_resolver(None);
        let a = asked.clone();
        gate.on_review(move |r| a.lock().unwrap().push(r.email.clone()));
        let addr = if name.starts_with("axum") { axum_server(gate) } else { actix_server(gate) };
        // Wait until it listens.
        for _ in 0..100 {
            if TcpStream::connect(addr).is_ok() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        let res = send(addr, "GET", "/", None, "");
        check(format!("{name}: an ordinary page passes"), res.status == 200 && res.body == "page");
        check(format!("{name}: security headers"), res.all("x-content-type-options") == ["nosniff"]);
        check(format!("{name}: the app's own header wins"), send(addr, "GET", "/own", None, "").all("x-frame-options") == ["DENY"]);
        let echo = send(addr, "POST", "/echo", Some(FORM), &f(&[("name", "Ñandú")]));
        check(format!("{name}: the app still reads the form, in UTF-8"), echo.status == 200 && echo.body == "name=Ñandú");
        let json = send(addr, "POST", "/json", Some("application/json"), r#"{"name": "Ana"}"#);
        check(format!("{name}: the app still reads the JSON body"), json.body == r#"json={"name": "Ana"}"#);
        let blocked = send(addr, "GET", ATTACK, None, "");
        check(format!("{name}: SQL injection gets 403"), blocked.status == 403);
        check(format!("{name}: the page never names the rule"), !blocked.body.contains("sqli"));
        check(format!("{name}: .env probe gets 403"), send(addr, "GET", "/.env", None, "").status == 403);
        check(
            format!("{name}: a posted form is inspected"),
            send(addr, "POST", "/echo", Some(FORM), &f(&[("message", "x'; DROP TABLE users; --")])).status == 403,
        );
        check(
            format!("{name}: a JSON body is inspected"),
            send(addr, "POST", "/json", Some("application/json"), r#"{"q": "' OR '1'='1"}"#).status == 403,
        );
        let re = regex_lite(&blocked.body);
        let mut fields = re;
        fields.push(("draco_email".into(), "ana@example.org".into()));
        fields.push(("draco_message".into(), "I was searching".into()));
        fields.push(("draco_website".into(), String::new()));
        let thanks = send(addr, "POST", ATTACK, Some(FORM), &form(&fields));
        check(format!("{name}: the review request is thanked"), thanks.status == 200 && thanks.body.contains("Request sent"));
        check(format!("{name}: and reaches the owner"), *asked.lock().unwrap() == ["ana@example.org"]);
    }
    println!("{}", if fails == 0 { format!("all passed (Draco Insomnis {VERSION})") } else { format!("{fails} failed") });
    std::process::exit(if fails == 0 { 0 } else { 1 });
}

/// The hidden fields of the review form.
fn regex_lite(page: &str) -> Vec<(String, String)> {
    let mut o = Vec::new();
    let mut rest = page;
    while let Some(i) = rest.find("<input type=\"hidden\" name=\"") {
        rest = &rest[i + 27..];
        let Some(q) = rest.find('"') else { break };
        let name = rest[..q].to_string();
        let Some(v) = rest.find("value=\"") else { break };
        rest = &rest[v + 7..];
        let Some(q2) = rest.find('"') else { break };
        o.push((name, rest[..q2].to_string()));
    }
    o
}
