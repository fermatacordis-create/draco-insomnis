//! "This is a mistake": the review form of the 403 page, with the same seals, signatures and limits
//! as src/Core/Review.php (tests/vectors/review.json).

use crate::store::Store;
use crate::util::{hex, same, unhex, ymd};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::LazyLock;

/// One accepted review request, for the owner.
#[derive(Debug, Clone, PartialEq)]
pub struct ReviewRequest {
    pub time: i64,
    pub ip: String,
    pub rule: String,
    pub email: String,
    pub message: String,
    pub user_agent: String,
}

pub const FIELD: &str = "draco_review";

static EMAIL: LazyLock<regex::bytes::Regex> = LazyLock::new(|| {
    regex::bytes::Regex::new(
        r"(?i-u)^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$",
    )
    .expect("pattern")
});
// PHP's "<(script|style)[^>]*?>.*?</\1>|<[^>]*>", without the back-reference.
static TAGS: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"(?is)<script[^>]*?>.*?</script>|<style[^>]*?>.*?</style>|<[^>]*>").expect("pattern"));
static CONTROL: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]").expect("pattern"));

fn mac(secret: &str, data: &str) -> Vec<u8> {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(secret.as_bytes()).expect("any key length");
    m.update(data.as_bytes());
    m.finalize().into_bytes().to_vec()
}

fn clean_rule(rule: &str) -> String {
    rule.to_ascii_lowercase().chars().filter(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '_').collect()
}

/// The rule, encrypted for this visitor and moment, so the page never shows it.
pub fn seal(secret: &str, ip: &str, ts: &str, rule: &str) -> String {
    let mut plain = [0u8; 32];
    let r = clean_rule(rule);
    let n = r.len().min(32);
    plain[..n].copy_from_slice(&r.as_bytes()[..n]);
    let key = mac(secret, &format!("review-rule|{ip}|{ts}"));
    for i in 0..32 {
        plain[i] ^= key[i];
    }
    hex(&plain)
}

/// The rule back from a seal; "" when it is not one.
pub fn open_sealed(secret: &str, ip: &str, ts: &str, sealed: &str) -> String {
    if sealed.len() != 64 || !sealed.bytes().all(|b| b.is_ascii_hexdigit()) {
        return String::new();
    }
    let Some(mut b) = unhex(sealed) else {
        return String::new();
    };
    let key = mac(secret, &format!("review-rule|{ip}|{ts}"));
    for i in 0..32 {
        b[i] ^= key[i];
    }
    while b.last() == Some(&0) {
        b.pop();
    }
    if b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_') {
        String::from_utf8(b).unwrap_or_default()
    } else {
        String::new()
    }
}

pub fn sign(secret: &str, ip: &str, rule: &str, ts: &str) -> String {
    hex(&mac(secret, &format!("review|{ip}|{rule}|{ts}")))
}

pub(crate) fn html(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&#39;"),
            c => o.push(c),
        }
    }
    o
}

pub(crate) fn form(secret: &str, ip: &str, why: &str, now: f64, t: &HashMap<String, String>) -> String {
    let ts = (now as i64).to_string();
    let rule = clean_rule(why);
    let tx = |k: &str| html(t.get(k).map(String::as_str).unwrap_or(""));
    format!(
        "<form method=\"post\" action=\"\"><input type=\"hidden\" name=\"{FIELD}\" value=\"1\">\
<input type=\"hidden\" name=\"draco_rule\" value=\"{}\">\
<input type=\"hidden\" name=\"draco_ts\" value=\"{}\">\
<input type=\"hidden\" name=\"draco_sig\" value=\"{}\">\
<p class=\"hp\"><label>Website <input type=\"text\" name=\"draco_website\" tabindex=\"-1\" autocomplete=\"off\"></label></p>\
<label for=\"draco-r-email\">{}</label><input id=\"draco-r-email\" type=\"email\" name=\"draco_email\" required maxlength=\"190\">\
<label for=\"draco-r-msg\">{}</label><textarea id=\"draco-r-msg\" name=\"draco_message\" rows=\"3\" maxlength=\"500\" required></textarea>\
<button type=\"submit\">{}</button></form>",
        html(&seal(secret, ip, &ts, &rule)),
        html(&ts),
        html(&sign(secret, ip, &rule, &ts)),
        tx("review_email"),
        tx("review_message"),
        tx("review_button"),
    )
}

pub(crate) fn accept(
    store: &dyn Store,
    secret: &str,
    ip: &str,
    user_agent: &str,
    post: &[(String, String)],
    now: f64,
) -> Option<ReviewRequest> {
    let p = |k: &str| post.iter().rev().find(|(n, _)| n == k).map(|(_, v)| v.as_str()).unwrap_or("");
    let ts = p("draco_ts");
    let rule = open_sealed(secret, ip, ts, p("draco_rule"));
    let email = p("draco_email").trim().to_lowercase();
    let message = TAGS.replace_all(p("draco_message"), "");
    let message = CONTROL.replace_all(&message, "");
    let message: String = message.trim().chars().take(500).collect();
    let fresh = !ts.is_empty() && ts.len() <= 18 && ts.bytes().all(|b| b.is_ascii_digit()) && {
        let t: i64 = ts.parse().unwrap_or(i64::MAX);
        (t as f64) <= now && now - (t as f64) < 86_400.0
    };
    let sig = p("draco_sig");
    let ok = fresh
        && sig.len() == 64
        && same(sign(secret, ip, &rule, ts).as_bytes(), sig.as_bytes())
        && p("draco_website").is_empty()
        && EMAIL.is_match(email.as_bytes())
        && email.len() <= 190
        && !message.is_empty();
    if !ok {
        return None;
    }
    let day = ymd(now as i64);
    if store.bump(&format!("draco:review:ip:{ip}"), 86_400) > 3 || store.bump(&format!("draco:review:day:{day}"), 86_400) > 50 {
        return None;
    }
    Some(ReviewRequest { time: now as i64, ip: ip.into(), rule, email, message, user_agent: user_agent.chars().take(255).collect() })
}
