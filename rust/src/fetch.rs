//! HTTP GET for the country list and CrowdSec (feature "fetch"; without it nothing is downloaded).

use std::time::Duration;

/// The body of a 200 answer, or None.
#[cfg(feature = "fetch")]
pub fn get(url: &str, timeout: Duration, headers: &[(&str, &str)]) -> Option<Vec<u8>> {
    let agent: ureq::Agent = ureq::Agent::config_builder().timeout_global(Some(timeout)).http_status_as_error(false).build().into();
    let mut req = agent.get(url).header("User-Agent", "Draco-Insomnis");
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let mut res = req.call().ok()?;
    if res.status().as_u16() != 200 {
        return None;
    }
    res.body_mut().with_config().limit(64 * 1024 * 1024).read_to_vec().ok()
}

/// The status and body of an answer, or None when there was none.
#[cfg(feature = "fetch")]
pub fn get_status(url: &str, timeout: Duration, headers: &[(&str, &str)]) -> Option<(u16, Vec<u8>)> {
    let agent: ureq::Agent = ureq::Agent::config_builder().timeout_global(Some(timeout)).http_status_as_error(false).build().into();
    let mut req = agent.get(url).header("User-Agent", "Draco-Insomnis");
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let mut res = req.call().ok()?;
    let status = res.status().as_u16();
    Some((status, res.body_mut().with_config().limit(64 * 1024 * 1024).read_to_vec().unwrap_or_default()))
}

#[cfg(not(feature = "fetch"))]
pub fn get(_url: &str, _timeout: Duration, _headers: &[(&str, &str)]) -> Option<Vec<u8>> {
    None
}

#[cfg(not(feature = "fetch"))]
pub fn get_status(_url: &str, _timeout: Duration, _headers: &[(&str, &str)]) -> Option<(u16, Vec<u8>)> {
    None
}
