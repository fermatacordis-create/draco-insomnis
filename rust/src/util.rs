//! Small helpers: time, hex, lenient URL decoding and query parsing that never fail.

use std::time::{SystemTime, UNIX_EPOCH};

/// Unix time in seconds, with milliseconds.
pub fn now() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

/// (year, month, day) of a day number since 1970-01-01 (Howard Hinnant's civil_from_days).
pub fn civil(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (yoe + era * 400 + if m <= 2 { 1 } else { 0 }, m, d)
}

/// Day number since 1970-01-01 of a date.
pub fn days(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let m = m as i64;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// "yyyyMMdd" (UTC) of a Unix time.
pub fn ymd(t: i64) -> String {
    let (y, m, d) = civil(t.div_euclid(86_400));
    format!("{y:04}{m:02}{d:02}")
}

/// "yyyy-MM-ddTHH:mm:ssZ" of a Unix time.
pub fn iso(t: i64) -> String {
    let (y, m, d) = civil(t.div_euclid(86_400));
    let s = t.rem_euclid(86_400);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", s / 3600, s / 60 % 60, s % 60)
}

pub fn hex(b: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut o = String::with_capacity(b.len() * 2);
    for x in b {
        o.push(H[(x >> 4) as usize] as char);
        o.push(H[(x & 15) as usize] as char);
    }
    o
}

pub fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok()).collect()
}

/// %XX decoded once as UTF-8 (broken sequences become U+FFFD; a lone "%" stays). With `form`, "+"
/// is a space, as in query strings and forms.
pub fn decode(s: &str, form: bool) -> String {
    let b = s.as_bytes();
    let mut o = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' if i + 2 < b.len() => {
                let h = (b[i + 1] as char).to_digit(16);
                let l = (b[i + 2] as char).to_digit(16);
                if let (Some(h), Some(l)) = (h, l) {
                    o.push((h * 16 + l) as u8);
                    i += 3;
                    continue;
                }
                o.push(b'%');
            }
            b'+' if form => o.push(b' '),
            c => o.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&o).into_owned()
}

/// A query string or form body: name to every value, in order of first appearance.
pub fn parse_query(s: &str) -> Vec<(String, Vec<String>)> {
    let mut o: Vec<(String, Vec<String>)> = Vec::new();
    for pair in s.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = match pair.find('=') {
            Some(eq) => (decode(&pair[..eq], true), decode(&pair[eq + 1..], true)),
            None => (decode(pair, true), String::new()),
        };
        match o.iter_mut().find(|(n, _)| *n == k) {
            Some((_, vs)) => vs.push(v),
            None => o.push((k, vec![v])),
        }
    }
    o
}

/// The last value of every field, for the review form.
pub fn last_values(fields: &[(String, Vec<String>)]) -> Vec<(String, String)> {
    fields.iter().filter_map(|(k, vs)| vs.last().map(|v| (k.clone(), v.clone()))).collect()
}

/// Time-independent comparison of two strings.
pub fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}
