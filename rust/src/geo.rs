//! The visitor's country without Cloudflare: the same file and binary search as src/Core/Geo.php
//! (DB-IP Lite, CC BY 4.0, built monthly by this project). Local: nothing is sent anywhere.

use crate::net;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

pub const DEFAULT_SOURCE: &str = "https://github.com/fermatacordis-create/draco-insomnis/releases/download/geo/draco-geo.bin";
const HEADER: usize = 22;

struct Open {
    file: File,
    v4: u64,
    v6: u64,
    built: String,
}

/// The country list, read from a local file.
pub struct GeoFile {
    path: PathBuf,
    source: Mutex<String>,
    open: Mutex<(Option<Open>, Option<Instant>)>,
}

fn u32be(b: &[u8]) -> u64 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as u64
}

pub(crate) fn read_head(head: &[u8], size: u64) -> Option<(u64, u64, String)> {
    if head.len() < HEADER || &head[..6] != b"DRGEO1" {
        return None;
    }
    let (v4, v6) = (u32be(&head[14..18]), u32be(&head[18..22]));
    (size == HEADER as u64 + v4 * 6 + v6 * 18).then(|| (v4, v6, String::from_utf8_lossy(&head[6..14]).into_owned()))
}

impl GeoFile {
    /// `update`: download the list when missing or older than 35 days, now and then daily (in a
    /// background thread that ends with the last reference to the list).
    pub fn new(path: impl AsRef<Path>, update: bool) -> Arc<GeoFile> {
        let g = Arc::new(GeoFile {
            path: path.as_ref().to_path_buf(),
            source: Mutex::new(DEFAULT_SOURCE.into()),
            open: Mutex::new((None, None)),
        });
        if update {
            let weak: Weak<GeoFile> = Arc::downgrade(&g);
            let _ = std::thread::Builder::new().name("draco-geo".into()).spawn(move || loop {
                match weak.upgrade() {
                    // The country list never breaks the app.
                    Some(g) => drop(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| g.refresh()))),
                    None => return,
                }
                std::thread::sleep(Duration::from_secs(86_400));
            });
        }
        g
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Where the list is downloaded from; its SHA-256 is read from the same address plus ".sha256".
    pub fn set_source(&self, url: &str) {
        *self.source.lock().unwrap_or_else(|e| e.into_inner()) = url.to_string();
    }

    fn with_open<T>(&self, f: impl FnOnce(&mut Open) -> Option<T>) -> Option<T> {
        let mut st = self.open.lock().unwrap_or_else(|e| e.into_inner());
        if st.0.is_none() {
            if st.1.is_some_and(|t| t.elapsed() < Duration::from_secs(60)) {
                return None;
            }
            st.1 = Some(Instant::now());
            let mut file = File::open(&self.path).ok()?;
            let mut head = [0u8; HEADER];
            file.read_exact(&mut head).ok()?;
            let size = file.metadata().ok()?.len();
            let (v4, v6, built) = read_head(&head, size)?;
            st.0 = Some(Open { file, v4, v6, built });
        }
        f(st.0.as_mut()?)
    }

    /// The two-letter country of an address, or None when unknown.
    pub fn country(&self, ip: &str) -> Option<String> {
        let addr = net::to_bytes(net::unmap(ip.trim()))?;
        self.with_open(|o| {
            let is4 = addr.len() == 4;
            let (count, size) = if is4 { (o.v4, 6u64) } else { (o.v6, 18u64) };
            let width = (size - 2) as usize;
            let base = HEADER as u64 + if is4 { 0 } else { o.v4 * 6 };
            let mut buf = vec![0u8; width];
            let (mut lo, mut hi, mut found) = (0i64, count as i64 - 1, -1i64);
            while lo <= hi {
                let mid = (lo + hi) / 2;
                o.file.seek(SeekFrom::Start(base + mid as u64 * size)).ok()?;
                o.file.read_exact(&mut buf).ok()?;
                if buf.as_slice() <= addr.as_slice() {
                    found = mid;
                    lo = mid + 1;
                } else {
                    hi = mid - 1;
                }
            }
            if found < 0 {
                return None;
            }
            o.file.seek(SeekFrom::Start(base + found as u64 * size + width as u64)).ok()?;
            let mut cc = [0u8; 2];
            o.file.read_exact(&mut cc).ok()?;
            cc.iter().all(|c| c.is_ascii_uppercase()).then(|| String::from_utf8_lossy(&cc).into_owned())
        })
    }

    /// The day the list was built (yyyyMMdd), or "".
    pub fn built(&self) -> String {
        self.with_open(|o| Some(o.built.clone())).unwrap_or_default()
    }

    pub fn stale(&self) -> bool {
        let b = self.built();
        if b.len() != 8 || !b.bytes().all(|c| c.is_ascii_digit()) {
            return true;
        }
        let (y, m, d) = (b[..4].parse().unwrap_or(0), b[4..6].parse().unwrap_or(0), b[6..].parse().unwrap_or(0));
        let today = (crate::util::now() / 86_400.0) as i64;
        today - crate::util::days(y, m, d) > 35
    }

    /// Downloads the list when it is missing or stale; "" when nothing failed.
    pub fn refresh(&self) -> String {
        if self.stale() {
            self.update()
        } else {
            String::new()
        }
    }

    /// Downloads the list, checks the published SHA-256, only then replaces the old file. "" = done.
    pub fn update(&self) -> String {
        let source = self.source.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let sum = crate::fetch::get(&format!("{source}.sha256"), Duration::from_secs(120), &[]);
        let want = sum.map(|b| String::from_utf8_lossy(&b).trim().to_ascii_lowercase()).unwrap_or_default();
        let want = want.get(..64).unwrap_or("");
        if want.len() < 64 || !want.bytes().all(|b| b.is_ascii_hexdigit()) {
            return "checksum".into();
        }
        let Some(body) = crate::fetch::get(&source, Duration::from_secs(120), &[]) else {
            return "download".into();
        };
        use sha2::Digest;
        if crate::util::hex(&sha2::Sha256::digest(&body)) != want {
            return "download".into();
        }
        if body.len() < HEADER || read_head(&body[..HEADER], body.len() as u64).is_none() {
            return "format".into();
        }
        let part = PathBuf::from(format!("{}.part", self.path.display()));
        let done = (|| -> std::io::Result<()> {
            if let Some(dir) = self.path.parent().filter(|d| !d.as_os_str().is_empty()) {
                std::fs::create_dir_all(dir)?;
            }
            std::fs::write(&part, &body)?;
            std::fs::rename(&part, &self.path)
        })();
        if done.is_err() {
            let _ = std::fs::remove_file(&part);
            return "folder".into();
        }
        *self.open.lock().unwrap_or_else(|e| e.into_inner()) = (None, None);
        String::new()
    }
}
