//! Counters, the block list and verified crawlers. The keys are the same as in the other editions,
//! so one Redis can serve apps in several languages.

use crate::json::{self, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Where the counters and the block list live. Implement it on Redis to share them between servers.
pub trait Store: Send + Sync {
    /// Adds one and returns the new value; the counter disappears after `ttl` seconds.
    fn bump(&self, key: &str, ttl: u64) -> i64;
    /// The value, or None when there is none (or it expired).
    fn get(&self, key: &str) -> Option<String>;
    /// Keeps a value for `ttl` seconds; 0 = for good.
    fn set(&self, key: &str, value: &str, ttl: u64);
    fn delete(&self, key: &str);
}

/// The clock, in Unix seconds.
pub type Clock = Arc<dyn Fn() -> f64 + Send + Sync>;

/// One process; thread-safe; lost on restart.
pub struct MemoryStore {
    items: Mutex<HashMap<String, (String, f64)>>,
    now: Clock,
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::with_clock(Arc::new(crate::util::now))
    }

    /// With its own clock (for tests).
    pub fn with_clock(now: Clock) -> Self {
        MemoryStore { items: Mutex::new(HashMap::new()), now }
    }

    fn live(items: &mut HashMap<String, (String, f64)>, key: &str, now: f64) -> Option<(String, f64)> {
        let it = items.get(key)?.clone();
        if it.1 != 0.0 && it.1 <= now {
            items.remove(key);
            return None;
        }
        Some(it)
    }

    fn sweep(items: &mut HashMap<String, (String, f64)>, now: f64) {
        if items.len() >= 50_000 {
            items.retain(|_, v| v.1 == 0.0 || v.1 > now);
        }
    }
}

impl Store for MemoryStore {
    fn bump(&self, key: &str, ttl: u64) -> i64 {
        let now = (self.now)();
        let mut items = self.items.lock().unwrap_or_else(|e| e.into_inner());
        let it = Self::live(&mut items, key, now);
        let n = it.as_ref().and_then(|v| v.0.parse::<i64>().ok()).map_or(1, |n| n + 1);
        let until = it.map_or(now + ttl as f64, |v| v.1);
        items.insert(key.to_string(), (n.to_string(), until));
        Self::sweep(&mut items, now);
        n
    }

    fn get(&self, key: &str) -> Option<String> {
        let now = (self.now)();
        let mut items = self.items.lock().unwrap_or_else(|e| e.into_inner());
        Self::live(&mut items, key, now).map(|v| v.0)
    }

    fn set(&self, key: &str, value: &str, ttl: u64) {
        let now = (self.now)();
        let mut items = self.items.lock().unwrap_or_else(|e| e.into_inner());
        items.insert(key.to_string(), (value.to_string(), if ttl == 0 { 0.0 } else { now + ttl as f64 }));
        Self::sweep(&mut items, now);
    }

    fn delete(&self, key: &str) {
        self.items.lock().unwrap_or_else(|e| e.into_inner()).remove(key);
    }
}

/// A line of evidence: the same fields as the PHP events table and the other editions.
#[derive(Debug, Clone, PartialEq)]
pub struct Event {
    pub time: i64,
    pub ip: String,
    pub remote: String,
    pub endpoint: String,
    pub verdict: String,
    pub reasons: Vec<String>,
    pub user_agent: String,
    pub detail: String,
    pub email: Option<String>,
}

impl Event {
    /// The event as a JSON object.
    pub fn to_json(&self) -> Value {
        Value::Obj(vec![
            ("time".into(), self.time.into()),
            ("ip".into(), self.ip.as_str().into()),
            ("remote".into(), self.remote.as_str().into()),
            ("endpoint".into(), self.endpoint.as_str().into()),
            ("verdict".into(), self.verdict.as_str().into()),
            ("reasons".into(), Value::Arr(self.reasons.iter().map(|r| r.as_str().into()).collect())),
            ("userAgent".into(), self.user_agent.as_str().into()),
            ("detail".into(), self.detail.as_str().into()),
            ("email".into(), self.email.as_deref().map_or(Value::Null, Value::from)),
        ])
    }

    pub fn to_json_string(&self) -> String {
        json::write(&self.to_json())
    }
}
