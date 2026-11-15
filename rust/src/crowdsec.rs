//! Draco as a bouncer of the owner's own CrowdSec Local API, like server/src/CrowdSec.php: bans join
//! the block list, synced in the background at most once a minute; admin addresses are never
//! imported and blocks the owner set are never lifted by it.

use crate::blocks::{self, Blocks};
use crate::json::{self, Value};
use crate::net;
use crate::store::{Clock, Event, Store};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// What one sync did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncResult {
    pub added: usize,
    pub removed: usize,
    pub error: String,
}

pub struct CrowdSec {
    url: String,
    key: String,
    store: Arc<dyn Store>,
    blocks: Blocks,
    admins: Vec<String>,
    now: Clock,
    running: AtomicBool,
    lock: Mutex<()>,
    timeout: Duration,
}

/// A Go duration ("3h59m40.5s") in whole seconds, rounded up; 0 when negative or not one.
pub fn seconds(duration: &str) -> u64 {
    if duration.trim().starts_with('-') {
        return 0;
    }
    static RE: std::sync::LazyLock<regex::Regex> =
        std::sync::LazyLock::new(|| regex::Regex::new(r"([0-9]+(?:\.[0-9]+)?)(h|ms|m|s)").expect("pattern"));
    let mut total = 0.0;
    for c in RE.captures_iter(duration) {
        let n: f64 = c[1].parse().unwrap_or(0.0);
        total += n * match &c[2] {
            "h" => 3600.0,
            "m" => 60.0,
            "s" => 1.0,
            _ => 0.001,
        };
    }
    total.ceil() as u64
}

/// One line for CrowdSec's own log reader (acquisition), sorted keys, like the other editions.
pub fn line(e: &Event, host: &str) -> String {
    json::write(&Value::Obj(vec![
        ("endpoint".into(), e.endpoint.as_str().into()),
        ("host".into(), host.into()),
        ("ip".into(), e.ip.as_str().into()),
        ("reasons".into(), e.reasons.join(",").into()),
        ("time".into(), crate::util::iso(e.time).into()),
        ("user_agent".into(), e.user_agent.as_str().into()),
        ("verdict".into(), e.verdict.as_str().into()),
    ]))
}

impl CrowdSec {
    pub fn new(url: &str, api_key: &str, store: Arc<dyn Store>, admins: Vec<String>, now: Clock) -> Self {
        CrowdSec {
            url: url.trim_end_matches('/').to_string(),
            key: api_key.to_string(),
            blocks: Blocks::new(store.clone()),
            store,
            admins,
            now,
            running: AtomicBool::new(false),
            lock: Mutex::new(()),
            timeout: Duration::from_secs(2),
        }
    }

    /// One sync a minute at most (shared through the store), in the background.
    pub fn maybe_sync(self: &Arc<Self>) {
        if self.running.load(Ordering::SeqCst) || self.store.bump("draco:crowdsec:sync", 60) != 1 {
            return;
        }
        let me = self.clone();
        // CrowdSec never breaks the app.
        let _ = std::thread::Builder::new().name("draco-crowdsec".into()).spawn(move || {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| me.sync()));
        });
    }

    /// Pulls the decisions now.
    pub fn sync(&self) -> SyncResult {
        let _guard = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        self.running.store(true, Ordering::SeqCst);
        let r = self.pull();
        self.running.store(false, Ordering::SeqCst);
        r
    }

    fn pull(&self) -> SyncResult {
        self.store.set("draco:crowdsec:sync", "1", 60);
        let (mut added, mut removed) = (0, 0);
        let startup = self.store.get("draco:crowdsec:started").is_none();
        let url = format!("{}/v1/decisions/stream?startup={startup}&scopes=ip,range", self.url);
        let (error, data) = match crate::fetch::get_status(&url, self.timeout, &[("X-Api-Key", &self.key)]) {
            None => ("no answer".to_string(), None),
            Some((200, body)) => match json::parse(&String::from_utf8_lossy(&body)) {
                Ok(v @ Value::Obj(_)) => (String::new(), Some(v)),
                _ => ("not JSON".to_string(), None),
            },
            Some((status, _)) => (format!("HTTP {status}"), None),
        };
        let t = (self.now)();
        let Some(answer) = data else {
            self.store.set("draco:crowdsec:last", &format!("{}|{error}", t as i64), 86_400 * 30);
            return SyncResult { added: 0, removed: 0, error };
        };
        let mut imported: Vec<String> = match self.store.get("draco:crowdsec:imported").map(|r| json::parse(&r)) {
            Some(Ok(Value::Arr(a))) => a.iter().filter_map(|v| if let Value::Str(s) = v { Some(s.clone()) } else { None }).collect(),
            _ => Vec::new(),
        };
        if startup {
            removed += imported.iter().filter(|v| self.remove_if_ours(v, t)).count();
            imported.clear();
        }
        if let Some(Value::Arr(deleted)) = answer.get("deleted") {
            for d in deleted {
                let value = d.get("value").map(|v| v.str().to_lowercase()).unwrap_or_default();
                if !value.is_empty() && imported.contains(&value) && self.remove_if_ours(&value, t) {
                    removed += 1;
                    imported.retain(|v| *v != value);
                }
            }
        }
        if let Some(Value::Arr(news)) = answer.get("new") {
            for d in news {
                let s = |k: &str| d.get(k).map(|v| v.str().to_string()).unwrap_or_default();
                if s("type").to_lowercase() != "ban" {
                    continue;
                }
                let value = s("value").trim().to_lowercase();
                let ttl = seconds(&s("duration"));
                let allowed = if value.contains('/') { blocks::valid_net(&value) } else { net::is_ip(&value) };
                if ttl == 0 || !allowed || self.admins.contains(&value) {
                    continue;
                }
                let mut scenario = s("scenario");
                if scenario.is_empty() {
                    scenario = s("origin");
                }
                let scenario: String = scenario.chars().take(150).collect();
                if !self.blocks.add_until(&value, t as i64 + ttl as i64, &format!("CrowdSec: {scenario}"), true, t) {
                    continue;
                }
                added += 1;
                if !imported.contains(&value) {
                    imported.push(value);
                }
            }
        }
        let keep = &imported[imported.len().saturating_sub(20_000)..];
        self.store.set("draco:crowdsec:imported", &json::write(&Value::Arr(keep.iter().map(|v| v.as_str().into()).collect())), 0);
        self.store.set("draco:crowdsec:started", "1", 86_400 * 365);
        self.store.set("draco:crowdsec:last", &format!("{}|ok +{added} -{removed}", t as i64), 86_400 * 30);
        SyncResult { added, removed, error: String::new() }
    }

    fn remove_if_ours(&self, value: &str, t: f64) -> bool {
        match self.blocks.entry(value, t) {
            Some(e) if e.reason.starts_with("CrowdSec") => {
                self.blocks.remove(value, t);
                true
            }
            _ => false,
        }
    }
}
