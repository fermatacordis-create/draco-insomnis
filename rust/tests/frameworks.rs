//! The tower layer in axum and the actix-web middleware, in process (the real servers are in e2e/).
#![cfg(all(feature = "axum", feature = "actix"))]

use draco_insomnis::{DracoLayer, DracoMiddleware, Gatekeeper, Options};
use std::sync::{Arc, Mutex};

const ATTACK: &str = "/search?q=1%27%20union%20select%20password%20from%20users--%20";
const FORM: &str = "application/x-www-form-urlencoded";

fn gate(asked: Arc<Mutex<Vec<String>>>) -> Arc<Gatekeeper> {
    let g = Gatekeeper::new(Options {
        waf: "block".into(),
        headers: true,
        review_secret: "owner-secret-0123456789".into(),
        ..Options::default()
    });
    g.set_resolver(None);
    g.on_review(move |r| asked.lock().unwrap().push(r.email.clone()));
    Arc::new(g)
}

fn form(fields: &[(&str, &str)]) -> String {
    fields.iter().map(|(k, v)| format!("{}={}", enc(k), enc(v))).collect::<Vec<_>>().join("&")
}

fn enc(s: &str) -> String {
    s.bytes()
        .map(|b| if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") })
        .collect()
}

fn hidden(page: &str) -> Vec<(String, String)> {
    let re = regex::Regex::new(r#"type="hidden" name="([^"]+)" value="([^"]*)""#).unwrap();
    re.captures_iter(page).map(|c| (c[1].to_string(), c[2].to_string())).collect()
}

#[tokio::test]
async fn axum_layer() {
    use axum::body::{to_bytes, Body};
    use axum::http::{Request, StatusCode};
    use axum::routing::{get, post};
    use axum::Router;
    use tower::ServiceExt;

    let asked: Arc<Mutex<Vec<String>>> = Arc::default();
    let app = Router::new()
        .route("/", get(|| async { "page" }))
        .route("/own", get(|| async { ([("x-frame-options", "DENY")], "own") }))
        .route("/search", get(|| async { "results" }).post(|| async { "results" }))
        .route("/echo", post(|body: String| async move { format!("body={body}") }))
        .layer(DracoLayer::new(gate(asked.clone())));
    let call = |r: Request<Body>| {
        let app = app.clone();
        async move {
            let res = app.oneshot(r).await.unwrap();
            let status = res.status();
            let headers = res.headers().clone();
            let body = String::from_utf8(to_bytes(res.into_body(), 1 << 20).await.unwrap().to_vec()).unwrap();
            (status, headers, body)
        }
    };
    let get_ = |p: &str| Request::get(p).header("user-agent", "Mozilla/5.0").body(Body::empty()).unwrap();
    let post_ = |p: &str, t: &str, b: String| {
        Request::post(p).header("content-type", t).header("content-length", b.len()).body(Body::from(b)).unwrap()
    };

    let (s, h, b) = call(get_("/")).await;
    assert_eq!((StatusCode::OK, "page"), (s, b.as_str()));
    assert_eq!("nosniff", h["x-content-type-options"]);
    let (_, h, _) = call(get_("/own")).await;
    assert_eq!(vec!["DENY"], h.get_all("x-frame-options").iter().collect::<Vec<_>>());
    assert_eq!("body=name=%C3%91and%C3%BA", call(post_("/echo", FORM, form(&[("name", "Ñandú")]))).await.2);
    assert_eq!(r#"body={"name": "Ana"}"#, call(post_("/echo", "application/json", r#"{"name": "Ana"}"#.into())).await.2);
    let (s, _, page) = call(get_(ATTACK)).await;
    assert_eq!(StatusCode::FORBIDDEN, s);
    assert!(!page.contains("sqli"));
    assert_eq!(StatusCode::FORBIDDEN, call(get_("/.env")).await.0);
    assert_eq!(StatusCode::FORBIDDEN, call(post_("/echo", FORM, form(&[("message", "x'; DROP TABLE users; --")]))).await.0);
    assert_eq!(StatusCode::FORBIDDEN, call(post_("/echo", "application/json", r#"{"q": "' OR '1'='1"}"#.into())).await.0);
    let mut fields: Vec<(String, String)> = hidden(&page);
    fields.extend([
        ("draco_email".into(), "ana@example.org".into()),
        ("draco_message".into(), "I was searching".into()),
        ("draco_website".into(), String::new()),
    ]);
    let f: Vec<(&str, &str)> = fields.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let (s, _, b) = call(post_(ATTACK, FORM, form(&f))).await;
    assert_eq!(StatusCode::OK, s);
    assert!(b.contains("Request sent"));
    assert_eq!(vec!["ana@example.org"], *asked.lock().unwrap());
}

#[actix_web::test]
async fn actix_middleware() {
    use actix_web::{test, web, App, HttpResponse};

    let asked: Arc<Mutex<Vec<String>>> = Arc::default();
    let app = test::init_service(
        App::new()
            .wrap(DracoMiddleware::new(gate(asked.clone())))
            .route("/", web::get().to(|| async { "page" }))
            .route("/own", web::get().to(|| async { HttpResponse::Ok().insert_header(("x-frame-options", "DENY")).body("own") }))
            .route("/search", web::get().to(|| async { "results" }))
            .route("/search", web::post().to(|| async { "results" }))
            .route("/echo", web::post().to(|f: web::Form<Vec<(String, String)>>| async move { format!("{:?}", f.0) }))
            .route("/json", web::post().to(|b: String| async move { format!("body={b}") })),
    )
    .await;
    let res = test::call_service(&app, test::TestRequest::get().uri("/").to_request()).await;
    assert_eq!(200, res.status().as_u16());
    assert_eq!("nosniff", res.headers().get("x-content-type-options").unwrap());
    let res = test::call_service(&app, test::TestRequest::get().uri("/own").to_request()).await;
    assert_eq!(vec!["DENY"], res.headers().get_all("x-frame-options").collect::<Vec<_>>());
    let post = |p: &str, t: &str, b: String| {
        test::TestRequest::post()
            .uri(p)
            .insert_header(("content-type", t.to_string()))
            .insert_header(("content-length", b.len().to_string()))
            .set_payload(b)
            .to_request()
    };
    let echo = test::call_and_read_body(&app, post("/echo", FORM, form(&[("name", "Ñandú")]))).await;
    assert_eq!(r#"[("name", "Ñandú")]"#, String::from_utf8_lossy(&echo));
    let json = test::call_and_read_body(&app, post("/json", "application/json", r#"{"name": "Ana"}"#.into())).await;
    assert_eq!(r#"body={"name": "Ana"}"#, String::from_utf8_lossy(&json));
    let res = test::call_service(&app, test::TestRequest::get().uri(ATTACK).to_request()).await;
    assert_eq!(403, res.status().as_u16());
    let page = String::from_utf8(test::read_body(res).await.to_vec()).unwrap();
    assert!(!page.contains("sqli"));
    assert_eq!(403, test::call_service(&app, test::TestRequest::get().uri("/.env").to_request()).await.status().as_u16());
    assert_eq!(
        403,
        test::call_service(&app, post("/echo", FORM, form(&[("message", "x'; DROP TABLE users; --")]))).await.status().as_u16()
    );
    assert_eq!(403, test::call_service(&app, post("/json", "application/json", r#"{"q": "' OR '1'='1"}"#.into())).await.status().as_u16());
    let mut fields: Vec<(String, String)> = hidden(&page);
    fields.extend([
        ("draco_email".into(), "ana@example.org".into()),
        ("draco_message".into(), "I was searching".into()),
        ("draco_website".into(), String::new()),
    ]);
    let f: Vec<(&str, &str)> = fields.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let thanks = test::call_service(&app, post(ATTACK, FORM, form(&f))).await;
    assert_eq!(200, thanks.status().as_u16());
    assert!(String::from_utf8_lossy(&test::read_body(thanks).await).contains("Request sent"));
    assert_eq!(vec!["ana@example.org"], *asked.lock().unwrap());
}
