//! The block list on any store: one key per address, one key holding the blocked networks.

use crate::json::{self, Value};
use crate::net;
use crate::store::Store;
use std::sync::Arc;

/// "For good": 9999-12-31 23:59:59 UTC, like the other editions.
pub const FOREVER: i64 = 253_402_300_799;

/// One blocked address or network. The JSON fields are the same in every edition.
#[derive(Debug, Clone, PartialEq)]
pub struct Entry {
    pub value: String,
    pub until: i64,
    pub reason: String,
    pub automatic: bool,
}

impl Entry {
    fn to_json(&self) -> Value {
        Value::Obj(vec![
            ("value".into(), self.value.as_str().into()),
            ("until".into(), self.until.into()),
            ("reason".into(), self.reason.as_str().into()),
            ("automatic".into(), self.automatic.into()),
        ])
    }

    fn from_json(v: &Value) -> Option<Entry> {
        let value = match v.get("value")? {
            Value::Str(s) => s.clone(),
            _ => return None,
        };
        let until = match v.get("until") {
            Some(Value::Num(n)) => n.parse::<f64>().ok()? as i64,
            Some(Value::Str(n)) => n.parse::<f64>().ok()? as i64,
            _ => 0,
        };
        Some(Entry {
            value,
            until,
            reason: v.get("reason").map(|r| r.str().to_string()).unwrap_or_default(),
            automatic: matches!(v.get("automatic"), Some(Value::Bool(true))),
        })
    }
}

/// The block list.
#[derive(Clone)]
pub struct Blocks {
    store: Arc<dyn Store>,
}

/// A network may be blocked when it is no wider than /16 (IPv4) or /32 (IPv6).
pub fn valid_net(cidr: &str) -> bool {
    let Some((ip, bits)) = cidr.trim().split_once('/') else {
        return false;
    };
    if bits.is_empty() || bits.len() > 4 || !bits.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let bits: u32 = bits.parse().unwrap_or(0);
    match net::to_bytes(ip) {
        Some(b) if b.len() == 16 => (32..=128).contains(&bits),
        Some(_) => (16..=32).contains(&bits),
        None => false,
    }
}

impl Blocks {
    pub fn new(store: Arc<dyn Store>) -> Self {
        Blocks { store }
    }

    /// Blocks an address or network for some days (0 = for good).
    pub fn add(&self, value: &str, days: u32, reason: &str, automatic: bool, now: f64) -> bool {
        let until = if days == 0 { FOREVER } else { now as i64 + days as i64 * 86_400 };
        let ttl = if days == 0 { 0 } else { days as u64 * 86_400 };
        self.write(Entry { value: value.into(), until, reason: reason.into(), automatic }, now, ttl)
    }

    /// Blocks an address or network until a Unix time.
    pub fn add_until(&self, value: &str, until: i64, reason: &str, automatic: bool, now: f64) -> bool {
        let ttl = until - now as i64;
        ttl > 0 && self.write(Entry { value: value.into(), until, reason: reason.into(), automatic }, now, ttl as u64)
    }

    pub fn remove(&self, value: &str, now: f64) {
        if value.contains('/') {
            let keep: Vec<Value> = self.nets(now).iter().filter(|n| n.value != value).map(Entry::to_json).collect();
            self.store.set("draco:nets", &json::write(&Value::Arr(keep)), 0);
        } else {
            self.store.delete(&format!("draco:block:{value}"));
        }
    }

    /// The blocked networks still in force.
    pub fn nets(&self, now: f64) -> Vec<Entry> {
        let Some(raw) = self.store.get("draco:nets") else {
            return Vec::new();
        };
        match json::parse(&raw) {
            Ok(Value::Arr(all)) => all.iter().filter_map(Entry::from_json).filter(|e| e.until as f64 > now).collect(),
            _ => Vec::new(),
        }
    }

    /// The entry of one address or network.
    pub fn entry(&self, value: &str, now: f64) -> Option<Entry> {
        if value.contains('/') {
            return self.nets(now).into_iter().find(|n| n.value == value);
        }
        let raw = self.store.get(&format!("draco:block:{value}"))?;
        json::parse(&raw).ok().as_ref().and_then(Entry::from_json)
    }

    pub fn is_blocked(&self, ip: &str, now: f64) -> bool {
        self.store.get(&format!("draco:block:{ip}")).is_some() || self.nets(now).iter().any(|n| net::in_net(&n.value, ip))
    }

    fn write(&self, e: Entry, now: f64, ttl: u64) -> bool {
        if e.value.contains('/') {
            if !valid_net(&e.value) {
                return false;
            }
            let mut nets: Vec<Value> = self.nets(now).iter().filter(|n| n.value != e.value).map(Entry::to_json).collect();
            nets.push(e.to_json());
            self.store.set("draco:nets", &json::write(&Value::Arr(nets)), 0);
            return true;
        }
        self.store.set(&format!("draco:block:{}", e.value), &json::write(&e.to_json()), ttl);
        true
    }
}
