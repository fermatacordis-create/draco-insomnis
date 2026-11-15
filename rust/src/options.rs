//! Every setting.

use std::collections::HashMap;

/// Country filter: mode "block" (refuse the countries) or "allow" (only those).
#[derive(Debug, Clone)]
pub struct GeoOptions {
    /// "off" (default), "block" or "allow".
    pub mode: String,
    /// Two-letter codes.
    pub countries: Vec<String>,
    /// "log" (default) or "block".
    pub action: String,
    /// "sensitive" (default: logins, sign-ups and any POST) or "site".
    pub scope: String,
    /// Where the country list is kept; it is downloaded there and refreshed.
    pub file: String,
}

impl Default for GeoOptions {
    fn default() -> Self {
        GeoOptions { mode: "off".into(), countries: Vec::new(), action: "log".into(), scope: "sensitive".into(), file: String::new() }
    }
}

/// Every setting, with the same names and defaults as the other editions.
#[derive(Debug, Clone)]
pub struct Options {
    /// Firewall signatures: "off", "log" (default) or "block".
    pub waf: String,
    /// Anti-copy pace: "off" (default), "log" or "block".
    pub pace: String,
    /// Pages a minute per address (default 120; at least 10).
    pub rate_ip: u32,
    /// Pages a minute per network, /24 or /64 (default 600; at least 10).
    pub rate_net: u32,
    /// "" (the connection), "cf" (CF-Connecting-IP) or "xff" (X-Forwarded-For), believed only from trusted proxies.
    pub proxy: String,
    pub trusted_proxies: Vec<String>,
    /// Addresses never inspected.
    pub admin_ips: Vec<String>,
    /// Path endings that count as sensitive, instead of the built-in list.
    pub sensitive: Vec<String>,
    /// Path prefixes never inspected (webhooks, health checks).
    pub except: Vec<String>,
    pub geo: GeoOptions,
    /// nosniff, frames, referrer and permissions headers, unless the app sets its own.
    pub headers: bool,
    /// Strict-Transport-Security over HTTPS.
    pub hsts: bool,
    /// 16 characters or more turn the review form on.
    pub review_secret: String,
    /// The owner's CrowdSec Local API and the key from "cscli bouncers add draco".
    pub crowdsec_url: String,
    pub crowdsec_api_key: String,
    /// Every line of evidence (and review request) as a JSON line on standard error.
    pub log_events: bool,
    /// The page texts, by key.
    pub texts: HashMap<String, String>,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            waf: "log".into(),
            pace: "off".into(),
            rate_ip: 0,
            rate_net: 0,
            proxy: String::new(),
            trusted_proxies: Vec::new(),
            admin_ips: Vec::new(),
            sensitive: Vec::new(),
            except: Vec::new(),
            geo: GeoOptions::default(),
            headers: false,
            hsts: false,
            review_secret: String::new(),
            crowdsec_url: String::new(),
            crowdsec_api_key: String::new(),
            log_events: false,
            texts: HashMap::new(),
        }
    }
}

fn split(v: &str) -> Vec<String> {
    v.split(|c: char| c == ',' || c.is_whitespace()).filter(|s| !s.is_empty()).map(String::from).collect()
}

fn yes(v: &str) -> bool {
    matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on")
}

impl Options {
    /// Settings from flat keys (a config file, a map): waf, pace, rate_ip, rate_net, proxy,
    /// trusted_proxies, admin_ips, sensitive, except (comma-separated), headers, hsts, log_events,
    /// geo.mode, geo.countries, geo.action, geo.scope, geo.file, review.secret, crowdsec.url,
    /// crowdsec.api_key, texts.KEY. Keys are case-insensitive; "-", "_" and "." are ignored, and a
    /// "draco-insomnis." or "draco." prefix is allowed.
    pub fn from_pairs<'a>(values: impl IntoIterator<Item = (&'a str, &'a str)>) -> Options {
        let mut o = Options::default();
        for (key, v) in values {
            let lower = key.trim().to_ascii_lowercase();
            let mut k: String = lower.chars().filter(|c| !matches!(c, '-' | '_' | '.')).collect();
            if let Some(rest) = k.strip_prefix("dracoinsomnis") {
                k = rest.to_string();
            } else if let Some(rest) = k.strip_prefix("draco") {
                k = rest.to_string();
            }
            let t = lower.find("texts.").or_else(|| lower.find("texts_"));
            if let (true, Some(t)) = (k.starts_with("texts"), t) {
                if t + 6 < lower.len() {
                    o.texts.insert(lower[t + 6..].to_string(), v.to_string());
                }
                continue;
            }
            let v = v.trim();
            let n = || v.parse::<u32>().unwrap_or(0);
            match k.as_str() {
                "waf" => o.waf = v.into(),
                "pace" => o.pace = v.into(),
                "rateip" => o.rate_ip = n(),
                "ratenet" => o.rate_net = n(),
                "proxy" => o.proxy = v.into(),
                "trustedproxies" => o.trusted_proxies = split(v),
                "adminips" => o.admin_ips = split(v),
                "sensitive" => o.sensitive = split(v),
                "except" => o.except = split(v),
                "headers" => o.headers = yes(v),
                "hsts" => o.hsts = yes(v),
                "logevents" => o.log_events = yes(v),
                "geomode" => o.geo.mode = v.into(),
                "geocountries" => o.geo.countries = split(v),
                "geoaction" => o.geo.action = v.into(),
                "geoscope" => o.geo.scope = v.into(),
                "geofile" => o.geo.file = v.into(),
                "reviewsecret" => o.review_secret = v.into(),
                "crowdsecurl" => o.crowdsec_url = v.into(),
                "crowdsecapikey" => o.crowdsec_api_key = v.into(),
                _ => {}
            }
        }
        o
    }

    /// Settings from the process environment: DRACO_INSOMNIS_WAF, DRACO_INSOMNIS_GEO_COUNTRIES and so on.
    pub fn from_env() -> Options {
        let vars: Vec<(String, String)> = std::env::vars().collect();
        Self::from_env_vars(vars.iter().map(|(k, v)| (k.as_str(), v.as_str())))
    }

    /// Settings from the variables that start with DRACO_INSOMNIS_; every other one is ignored.
    pub fn from_env_vars<'a>(vars: impl IntoIterator<Item = (&'a str, &'a str)>) -> Options {
        Self::from_pairs(vars.into_iter().filter(|(k, _)| k.to_ascii_uppercase().starts_with("DRACO_INSOMNIS_")))
    }
}
