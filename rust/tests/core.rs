use draco_insomnis::json::{self, Value};
use draco_insomnis::{blocks, crowdsec, geo::GeoFile, net, review, util, waf};
use draco_insomnis::{Event, Gatekeeper, MemoryStore, Options, Request, Resolver, ReviewRequest, Store};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

const NOW: f64 = 1_800_000_000.0;

pub struct NoDns;
impl Resolver for NoDns {
    fn reverse(&self, _: &str) -> std::io::Result<Vec<String>> {
        Err(std::io::Error::other("no DNS"))
    }
    fn forward(&self, _: &str) -> std::io::Result<Vec<String>> {
        Err(std::io::Error::other("no DNS"))
    }
}

struct FakeDns;
impl Resolver for FakeDns {
    fn reverse(&self, ip: &str) -> std::io::Result<Vec<String>> {
        Ok(vec![if ip == "66.249.66.1" { "crawl-66-249-66-1.googlebot.com.".into() } else { "x.example".into() }])
    }
    fn forward(&self, host: &str) -> std::io::Result<Vec<String>> {
        Ok(if host == "crawl-66-249-66-1.googlebot.com" { vec!["66.249.66.1".into()] } else { vec![] })
    }
}

fn gate(o: Options) -> Gatekeeper {
    let g = Gatekeeper::with_clock(o, None, Arc::new(|| NOW));
    g.set_resolver(Some(Arc::new(NoDns)));
    g
}

fn req() -> Request {
    Request { remote_addr: "198.51.100.20".into(), user_agent: "Mozilla/5.0 Chrome/131.0".into(), ..Request::default() }
}

fn attack(remote: &str) -> Request {
    Request { remote_addr: remote.into(), query: "../../etc/passwd".into(), params: vec!["../../etc/passwd".into()], ..req() }
}

pub fn hidden(page: &str) -> Vec<(String, String)> {
    let re = regex::Regex::new(r#"type="hidden" name="([^"]+)" value="([^"]*)""#).unwrap();
    re.captures_iter(page).map(|c| (c[1].to_string(), c[2].to_string())).collect()
}

fn vectors(name: &str) -> Value {
    let p = format!("{}/../tests/vectors/{name}", env!("CARGO_MANIFEST_DIR"));
    json::parse(&std::fs::read_to_string(p).unwrap()).unwrap()
}

fn run(r: &Value) -> Option<&'static str> {
    let ps: Vec<String> = match r.get("params") {
        Some(Value::Arr(a)) => a.iter().map(|x| x.str().to_string()).collect(),
        _ => vec![],
    };
    let s = |k: &str| r.get(k).map(|v| v.str()).unwrap_or("");
    waf::inspect(s("path"), s("query"), &ps, s("userAgent"))
}

#[test]
fn attacks_get_the_same_rule() {
    let Some(Value::Arr(cases)) = vectors("waf.json").get("attacks").cloned() else { panic!() };
    for c in &cases {
        assert_eq!(c.get("rule").unwrap().str(), run(c.get("request").unwrap()).unwrap_or("none"), "{}", c.get("name").unwrap().str());
    }
    assert!(cases.len() >= 30);
}

#[test]
fn ordinary_requests_pass() {
    let Some(Value::Arr(cases)) = vectors("waf.json").get("ordinary").cloned() else { panic!() };
    for c in &cases {
        assert_eq!(None, run(c.get("request").unwrap()), "{}", c.get("name").unwrap().str());
    }
    assert!(cases.len() >= 10);
}

#[test]
fn classes_are_ascii_like_php() {
    // Byte-wise like PHP, "ñ" is not a word character, so there is a word boundary next to it.
    assert_eq!(Some("sqli"), waf::inspect::<String>("/", "x=ñunion select 1", &[], ""));
    assert_eq!(Some("scanner"), waf::inspect::<String>("/", "", &[], "Mozilla/5.0 nucleiñ"));
    // PCRE's "$" matches before a final "\n", never before a final "\r".
    assert_eq!(Some("probe"), waf::inspect::<String>("/.env\n", "", &[], ""));
    assert_eq!(None, waf::inspect::<String>("/.env\r", "", &[], ""));
}

#[test]
fn net_like_php() {
    assert!(!net::is_ip("01.2.3.4"));
    assert!(!net::is_ip("fe80::1%eth0"));
    assert!(!net::is_ip("1.2.3"));
    assert!(!net::is_ip("1:2:3:4:5:6:7:8:9"));
    assert!(net::is_ip("2001:db8::1"));
    assert!(net::is_ip("::ffff:1.2.3.4"));
    assert_eq!("2001:db8:1:2::/64", net::network("2001:db8:1:2:3:4:5:6"));
    assert_eq!("203.0.113.0/24", net::network("203.0.113.9"));
    assert!(blocks::valid_net("203.0.113.0/24"));
    assert!(!blocks::valid_net("10.0.0.0/8"));
    assert!(net::in_net("2a06:98c0::/29", "2a06:98c7::1"));
    assert!(!net::in_net("2a06:98c0::/29", "2a06:98c8::1"));
    assert_eq!(vec!["10.0.0.0/8", "192.0.2.1"], net::parse(&["10.0.0.0/8, x # office\n192.0.2.1"]));
    let g = gate(Options { proxy: "xff".into(), ..Options::default() });
    assert_eq!("203.0.113.5", g.ip(&Request { remote_addr: "203.0.113.5".into(), forwarded_for: "1.2.3.4".into(), ..req() }));
    assert_eq!(
        "198.51.100.7",
        g.ip(&Request { remote_addr: "10.0.0.2".into(), forwarded_for: "1.2.3.4, 198.51.100.7, 10.0.0.9".into(), ..req() })
    );
    assert_eq!("198.51.100.20", g.ip(&Request { remote_addr: "::ffff:198.51.100.20".into(), ..req() }));
}

#[test]
fn review_vectors_like_php() {
    let v = vectors("review.json");
    let secret = v.get("secret").unwrap().str().to_string();
    let Some(Value::Arr(cases)) = v.get("cases") else { panic!() };
    for c in cases {
        let s = |k: &str| c.get(k).unwrap().str().to_string();
        let ts = match c.get("ts").unwrap() {
            Value::Num(n) => n.clone(),
            x => x.str().to_string(),
        };
        assert_eq!(s("sealed"), review::seal(&secret, &s("ip"), &ts, &s("rule")));
        assert_eq!(s("opened"), review::open_sealed(&secret, &s("ip"), &ts, &s("sealed")));
        assert_eq!(s("sig"), review::sign(&secret, &s("ip"), &s("rule"), &ts));
    }
    assert!(cases.len() >= 4);
}

fn reviewing() -> Options {
    Options { waf: "block".into(), review_secret: "owner-secret-0123456789".into(), ..Options::default() }
}

#[test]
fn review_flow() {
    let asked: Arc<Mutex<Vec<ReviewRequest>>> = Arc::default();
    let g = gate(reviewing());
    let a = asked.clone();
    g.on_review(move |r| a.lock().unwrap().push(r.clone()));
    let page = g.render(&g.decide(&attack("198.51.100.20")).unwrap());
    assert_eq!(403, page.status);
    assert!(page.body.contains("Ask for a review"));
    assert!(!page.body.contains("traversal"));
    let mut form = hidden(&page.body);
    form.push(("draco_email".into(), "Ana@Example.org".into()));
    form.push(("draco_message".into(), "I was <b>reading</b>".into()));
    form.push(("draco_website".into(), "".into()));
    for _ in 0..5 {
        assert_eq!(200, g.decide(&Request { method: "POST".into(), form: form.clone(), ..req() }).unwrap().status);
    }
    let got = asked.lock().unwrap().clone();
    assert_eq!(3, got.len());
    assert_eq!("ana@example.org", got[0].email);
    assert_eq!("I was reading", got[0].message);
    assert_eq!("traversal", got[0].rule);

    let mut bad = form.clone();
    bad.push(("draco_sig".into(), "0".repeat(64)));
    let none: Arc<Mutex<Vec<ReviewRequest>>> = Arc::default();
    let g2 = gate(reviewing());
    let n = none.clone();
    g2.on_review(move |r| n.lock().unwrap().push(r.clone()));
    g2.decide(&Request { method: "POST".into(), form: bad, ..req() });
    g2.decide(&Request { method: "POST".into(), form, remote_addr: "203.0.113.7".into(), ..req() });
    assert!(none.lock().unwrap().is_empty());
}

#[test]
fn firewall_pace_and_blocks() {
    let seen: Arc<Mutex<Vec<String>>> = Arc::default();
    let g = gate(Options { waf: "block".into(), ..Options::default() });
    let s = seen.clone();
    g.on_event(move |e: &Event| s.lock().unwrap().push(e.endpoint.clone()));
    let committee =
        Request { query: "q=european union select committee".into(), params: vec!["european union select committee".into()], ..req() };
    assert_eq!(None, g.decide(&committee));
    assert_eq!("traversal", g.decide(&attack("198.51.100.20")).unwrap().why);
    assert_eq!("probe", g.decide(&Request { path: "/.env".into(), ..req() }).unwrap().why);
    for _ in 0..4 {
        g.decide(&attack("198.51.100.20"));
    }
    assert!(g.blocks().is_blocked("198.51.100.20", NOW));
    assert_eq!(None, g.decide(&req()));
    assert_eq!("blocked", g.decide(&Request { method: "POST".into(), path: "/contact".into(), ..req() }).unwrap().why);
    assert_eq!(vec!["waf:traversal", "waf:probe"], seen.lock().unwrap()[..2].to_vec());
    let admin = gate(Options { waf: "block".into(), admin_ips: vec!["198.51.100.20".into()], ..Options::default() });
    assert_eq!(None, admin.decide(&attack("198.51.100.20")));
    let except = gate(Options { waf: "block".into(), except: vec!["webhooks".into()], ..Options::default() });
    assert_eq!(None, except.decide(&Request { path: "/webhooks/stripe".into(), ..attack("198.51.100.20") }));

    let pace = || Options { waf: "off".into(), pace: "block".into(), rate_ip: 10, ..Options::default() };
    let p = gate(pace());
    let html = Request { accept: "text/html".into(), ..req() };
    let got: Vec<_> = (0..12).map(|_| p.decide(&html)).collect();
    assert_eq!(None, got[9]);
    assert_eq!(429, got[10].as_ref().unwrap().status);
    assert!(got[10].as_ref().unwrap().retry >= 1);
    assert_eq!(None, p.decide(&Request { accept: "application/json".into(), ..req() }));

    // A proved search engine is not held back; a pretender is.
    let c = gate(pace());
    c.set_resolver(Some(Arc::new(FakeDns)));
    let bot = "Mozilla/5.0 (compatible; Googlebot/2.1)";
    for _ in 0..15 {
        assert_eq!(None, c.decide(&Request { remote_addr: "66.249.66.1".into(), user_agent: bot.into(), ..req() }));
    }
    let last = (0..15).map(|_| c.decide(&Request { remote_addr: "203.0.113.50".into(), user_agent: bot.into(), ..req() })).last().unwrap();
    assert_eq!(429, last.unwrap().status);
    assert_eq!(Some("y".to_string()), c.store().get("draco:crawler:66.249.66.1:googlebot"));
}

#[test]
fn block_list_is_shared_json() {
    let s: Arc<dyn Store> = Arc::new(MemoryStore::with_clock(Arc::new(|| NOW)));
    let b = blocks::Blocks::new(s.clone());
    assert!(b.add("203.0.113.0/24", 1, "Manual", false, NOW));
    assert!(!b.add("10.0.0.0/8", 1, "too wide", false, NOW));
    assert!(b.add("198.51.100.9", 0, "Manual", false, NOW));
    assert!(b.is_blocked("203.0.113.77", NOW));
    assert_eq!(blocks::FOREVER, b.entry("198.51.100.9", NOW).unwrap().until);
    // Written by another edition: the same JSON fields.
    s.set("draco:block:192.0.2.5", r#"{"value":"192.0.2.5","until":1800003600,"reason":"Java","automatic":true}"#, 3600);
    assert_eq!("Java", b.entry("192.0.2.5", NOW).unwrap().reason);
    b.remove("203.0.113.0/24", NOW);
    assert!(!b.is_blocked("203.0.113.77", NOW));
}

#[test]
fn json_decoding_and_options() {
    let v = json::parse(r#"{"a":1,"x":[2.5,true,false,null],"s":"\ud83d\ude00"}"#).unwrap();
    assert_eq!(vec!["a", "1", "x", "2.5", "1", "", "s", "😀"], waf::flatten_json(&v, 200));
    assert_eq!(
        r#"{"a":"\u003cb\u003e","b":[1,null]}"#,
        json::write(&Value::Obj(vec![("a".into(), "<b>".into()), ("b".into(), Value::Arr(vec![1i64.into(), Value::Null]))]))
    );
    assert!(json::parse(&format!("{}{}", "[".repeat(100), "]".repeat(100))).is_err());
    assert!(json::parse(r#"{"a":1,}"#).is_err());
    assert_eq!("a b'é%zz%", util::decode("a+b%27%C3%A9%zz%", true));
    assert_eq!("a+b", util::decode("a+b", false));
    assert_eq!(
        vec![("q".to_string(), vec!["1".to_string(), "2".to_string()]), ("x".to_string(), vec![String::new()])],
        util::parse_query("q=1&q=2&x")
    );
    assert_eq!("2027-01-15T08:00:00Z", util::iso(1_800_000_000));
    assert_eq!("20270115", util::ymd(1_800_000_000));
    assert_eq!(util::days(2027, 1, 15), 1_800_000_000 / 86_400);
    let o = Options::from_pairs([
        ("waf", "block"),
        ("geo.countries", "CN, RU"),
        ("review-secret", "s3cret"),
        ("DRACO_INSOMNIS_HEADERS", "true"),
        ("texts.title", "Bloqueado"),
        ("PATH", "/usr/bin"),
    ]);
    assert_eq!("block", o.waf);
    assert_eq!(vec!["CN", "RU"], o.geo.countries);
    assert_eq!("s3cret", o.review_secret);
    assert!(o.headers);
    assert_eq!("Bloqueado", Gatekeeper::new(o).texts()["title"]);
    let env = Options::from_env_vars([
        ("DRACO_INSOMNIS_WAF", "block"),
        ("DRACO_INSOMNIS_TEXTS_REVIEW_EMAIL", "Correo"),
        ("PROXY", "xff"),
        ("HSTS", "1"),
    ]);
    assert_eq!("block", env.waf);
    assert_eq!("Correo", env.texts["review_email"]);
    assert_eq!("", env.proxy);
    assert!(!env.hsts);
}

/// A small HTTP server for the country list and the CrowdSec API.
fn serve(answer: impl Fn(&str) -> Vec<u8> + Send + 'static, asked: Arc<Mutex<Vec<String>>>) -> String {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    std::thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { continue };
            let mut r = BufReader::new(s.try_clone().unwrap());
            let mut first = String::new();
            r.read_line(&mut first).unwrap();
            let target = first.split(' ').nth(1).unwrap_or("/").to_string();
            let mut key = String::new();
            loop {
                let mut h = String::new();
                if r.read_line(&mut h).unwrap_or(0) == 0 || h == "\r\n" {
                    break;
                }
                if let Some(v) = h.strip_prefix("x-api-key: ").or_else(|| h.strip_prefix("X-Api-Key: ")) {
                    key = v.trim().to_string();
                }
            }
            let (path, query) = target.split_once('?').unwrap_or((&target, ""));
            asked.lock().unwrap().push(format!("{query} {key}"));
            let b = answer(path);
            let _ = write!(s, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", b.len());
            let _ = s.write_all(&b);
        }
    });
    url
}

fn geo_fixture(built: &str) -> Vec<u8> {
    let v4 = [("0.0.0.0", "--"), ("1.0.0.0", "AU"), ("1.0.1.0", "CN"), ("1.0.4.0", "--"), ("203.0.113.0", "ES"), ("203.0.114.0", "--")];
    let v6 = [("::", "--"), ("2a00::", "ES"), ("2a01::", "--")];
    let mut o = format!("DRGEO1{built}").into_bytes();
    o.extend((v4.len() as u32).to_be_bytes());
    o.extend((v6.len() as u32).to_be_bytes());
    for (ip, cc) in v4.iter().chain(v6.iter()) {
        o.extend(net::to_bytes(ip).unwrap());
        o.extend(cc.as_bytes());
    }
    o
}

#[test]
fn geo_like_geo_php() {
    let dir = std::env::temp_dir().join(format!("draco-geo-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("g.bin");
    std::fs::write(&path, geo_fixture("20261113")).unwrap();
    let geo = GeoFile::new(&path, false);
    let want: HashMap<&str, Option<&str>> = HashMap::from([
        ("1.0.0.200", Some("AU")),
        ("1.0.3.255", Some("CN")),
        ("1.0.4.0", None),
        ("::ffff:203.0.113.10", Some("ES")),
        ("2a00:1450::1", Some("ES")),
        ("2a01::1", None),
        ("x", None),
    ]);
    for (ip, cc) in want {
        assert_eq!(cc.map(String::from), geo.country(ip), "{ip}");
    }
    assert_eq!("20261113", geo.built());
    let g = gate(Options {
        waf: "block".into(),
        geo: draco_insomnis::GeoOptions {
            mode: "block".into(),
            countries: vec!["cn".into()],
            action: "block".into(),
            ..Default::default()
        },
        ..Options::default()
    });
    g.set_geo(Some(geo));
    assert_eq!("geo", g.decide(&Request { path: "/login".into(), remote_addr: "1.0.2.3".into(), ..req() }).unwrap().why);
    assert_eq!(None, g.decide(&Request { remote_addr: "1.0.2.3".into(), ..req() }));

    // Download with the published checksum; a wrong one keeps the old file.
    let body = geo_fixture("20991231");
    use sha2::Digest;
    let sum = Arc::new(Mutex::new(util::hex(&sha2::Sha256::digest(&body))));
    let s2 = sum.clone();
    let url = serve(
        move |p| if p.ends_with(".sha256") { format!("{}  draco-geo.bin\n", s2.lock().unwrap()).into_bytes() } else { body.clone() },
        Arc::default(),
    );
    let dl = GeoFile::new(dir.join("sub/g.bin"), false);
    dl.set_source(&format!("{url}/draco-geo.bin"));
    assert_eq!("", dl.refresh());
    assert_eq!("20991231", dl.built());
    *sum.lock().unwrap() = "0".repeat(64);
    assert_eq!("download", dl.update());
    assert_eq!("20991231", dl.built());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn crowdsec_bridge() {
    assert_eq!(14381, crowdsec::seconds("3h59m40.5s"));
    assert_eq!(1, crowdsec::seconds("250ms"));
    assert_eq!(0, crowdsec::seconds("-3s"));
    let answer = Arc::new(Mutex::new(String::from(
        r#"{"new":[{"type":"ban","value":"198.51.100.66","duration":"4h","scenario":"crowdsecurity/http-probing"},{"type":"ban","value":"203.0.113.0/24","duration":"1h"},{"type":"ban","value":"10.0.0.0/8","duration":"1h"},{"type":"ban","value":"192.0.2.1","duration":"4h"},{"type":"captcha","value":"198.51.100.67","duration":"4h"}],"deleted":null}"#,
    )));
    let asked: Arc<Mutex<Vec<String>>> = Arc::default();
    let a2 = answer.clone();
    let url = serve(move |_| a2.lock().unwrap().clone().into_bytes(), asked.clone());
    let g = gate(Options {
        waf: "block".into(),
        admin_ips: vec!["192.0.2.1".into()],
        crowdsec_url: url,
        crowdsec_api_key: "k3y".into(),
        ..Options::default()
    });
    g.blocks().add("203.0.113.200", 7, "Manual", false, NOW);
    let r = g.crowdsec().unwrap().sync();
    assert_eq!((2, 0, ""), (r.added, r.removed, r.error.as_str()));
    assert_eq!("startup=true&scopes=ip,range k3y", asked.lock().unwrap()[0]);
    assert_eq!("blocked", g.decide(&Request { path: "/login".into(), remote_addr: "198.51.100.66".into(), ..req() }).unwrap().why);
    assert_eq!("blocked", g.decide(&Request { method: "POST".into(), remote_addr: "203.0.113.9".into(), ..req() }).unwrap().why);
    assert_eq!(None, g.decide(&Request { path: "/login".into(), remote_addr: "10.1.2.3".into(), ..req() }));
    *answer.lock().unwrap() = r#"{"new":[],"deleted":[{"value":"198.51.100.66"},{"value":"203.0.113.200"}]}"#.into();
    assert_eq!(1, g.crowdsec().unwrap().sync().removed);
    assert!(g.blocks().is_blocked("203.0.113.200", NOW));
    assert!(!g.blocks().is_blocked("198.51.100.66", NOW));
    let e = Event {
        time: 1_800_000_000,
        ip: "198.51.100.9".into(),
        remote: String::new(),
        endpoint: "waf:sqli".into(),
        verdict: "bot".into(),
        reasons: vec!["waf_sqli".into()],
        user_agent: "curl/8".into(),
        detail: String::new(),
        email: None,
    };
    assert_eq!(
        r#"{"endpoint":"waf:sqli","host":"shop.example","ip":"198.51.100.9","reasons":"waf_sqli","time":"2027-01-15T08:00:00Z","user_agent":"curl/8","verdict":"bot"}"#,
        crowdsec::line(&e, "shop.example")
    );
}
