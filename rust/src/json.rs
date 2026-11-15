//! The little JSON Draco needs (block list, CrowdSec answers, request bodies, log lines).

use std::fmt::Write;

/// A JSON value. Objects keep their order; numbers keep their text as written.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Num(String),
    Str(String),
    Arr(Vec<Value>),
    Obj(Vec<(String, Value)>),
}

impl Value {
    /// The field of an object, or None.
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Obj(m) => m.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// The text of a string value, or "".
    pub fn str(&self) -> &str {
        match self {
            Value::Str(s) => s,
            _ => "",
        }
    }
}

impl From<&str> for Value {
    fn from(s: &str) -> Self {
        Value::Str(s.to_string())
    }
}

impl From<String> for Value {
    fn from(s: String) -> Self {
        Value::Str(s)
    }
}

impl From<i64> for Value {
    fn from(n: i64) -> Self {
        Value::Num(n.to_string())
    }
}

impl From<bool> for Value {
    fn from(b: bool) -> Self {
        Value::Bool(b)
    }
}

const MAX_DEPTH: usize = 64;

/// The text is not JSON (or nests deeper than 64 levels).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotJson;

impl std::fmt::Display for NotJson {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("not JSON")
    }
}

impl std::error::Error for NotJson {}

/// Parses one JSON value; Err when it is not JSON.
pub fn parse(text: &str) -> Result<Value, NotJson> {
    let mut p = Parser { s: text.as_bytes(), i: 0 };
    p.space();
    let v = p.value(0).map_err(|_| NotJson)?;
    p.space();
    if p.i != p.s.len() {
        return Err(NotJson);
    }
    Ok(v)
}

/// The value as compact JSON.
pub fn write(v: &Value) -> String {
    let mut o = String::new();
    write_into(&mut o, v);
    o
}

fn write_into(o: &mut String, v: &Value) {
    match v {
        Value::Null => o.push_str("null"),
        Value::Bool(b) => o.push_str(if *b { "true" } else { "false" }),
        Value::Num(n) => o.push_str(n),
        Value::Str(s) => string(o, s),
        Value::Arr(a) => {
            o.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    o.push(',');
                }
                write_into(o, x);
            }
            o.push(']');
        }
        Value::Obj(m) => {
            o.push('{');
            for (i, (k, x)) in m.iter().enumerate() {
                if i > 0 {
                    o.push(',');
                }
                string(o, k);
                o.push(':');
                write_into(o, x);
            }
            o.push('}');
        }
    }
}

fn string(o: &mut String, s: &str) {
    o.push('"');
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            '\u{8}' => o.push_str("\\b"),
            '\u{c}' => o.push_str("\\f"),
            // Control characters, and <, >, & so a line can never close a <script> it lands in.
            c if (c as u32) < 0x20 || c == '<' || c == '>' || c == '&' || c == '\u{2028}' || c == '\u{2029}' => {
                let _ = write!(o, "\\u{:04x}", c as u32);
            }
            c => o.push(c),
        }
    }
    o.push('"');
}

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
}

impl Parser<'_> {
    fn space(&mut self) {
        while self.i < self.s.len() && matches!(self.s[self.i], b' ' | b'\t' | b'\r' | b'\n') {
            self.i += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }

    fn value(&mut self, depth: usize) -> Result<Value, ()> {
        if depth > MAX_DEPTH {
            return Err(());
        }
        match self.peek().ok_or(())? {
            b'{' => self.object(depth),
            b'[' => self.array(depth),
            b'"' => Ok(Value::Str(self.string()?)),
            _ if self.s[self.i..].starts_with(b"true") => {
                self.i += 4;
                Ok(Value::Bool(true))
            }
            _ if self.s[self.i..].starts_with(b"false") => {
                self.i += 5;
                Ok(Value::Bool(false))
            }
            _ if self.s[self.i..].starts_with(b"null") => {
                self.i += 4;
                Ok(Value::Null)
            }
            _ => self.number(),
        }
    }

    fn object(&mut self, depth: usize) -> Result<Value, ()> {
        let mut o = Vec::new();
        self.i += 1;
        self.space();
        if self.peek() == Some(b'}') {
            self.i += 1;
            return Ok(Value::Obj(o));
        }
        loop {
            self.space();
            if self.peek() != Some(b'"') {
                return Err(());
            }
            let k = self.string()?;
            self.space();
            if self.peek() != Some(b':') {
                return Err(());
            }
            self.i += 1;
            self.space();
            let v = self.value(depth + 1)?;
            o.push((k, v));
            self.space();
            match self.peek() {
                Some(b'}') => {
                    self.i += 1;
                    return Ok(Value::Obj(o));
                }
                Some(b',') => self.i += 1,
                _ => return Err(()),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<Value, ()> {
        let mut o = Vec::new();
        self.i += 1;
        self.space();
        if self.peek() == Some(b']') {
            self.i += 1;
            return Ok(Value::Arr(o));
        }
        loop {
            self.space();
            o.push(self.value(depth + 1)?);
            self.space();
            match self.peek() {
                Some(b']') => {
                    self.i += 1;
                    return Ok(Value::Arr(o));
                }
                Some(b',') => self.i += 1,
                _ => return Err(()),
            }
        }
    }

    fn hex4(&mut self) -> Result<u32, ()> {
        let h = self.s.get(self.i..self.i + 4).ok_or(())?;
        let h = std::str::from_utf8(h).map_err(|_| ())?;
        if !h.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(());
        }
        self.i += 4;
        u32::from_str_radix(h, 16).map_err(|_| ())
    }

    fn string(&mut self) -> Result<String, ()> {
        let mut o: Vec<u8> = Vec::new();
        self.i += 1;
        while let Some(c) = self.peek() {
            self.i += 1;
            match c {
                b'"' => return String::from_utf8(o).map_err(|_| ()),
                c if c < 0x20 => return Err(()),
                b'\\' => {
                    let e = self.peek().ok_or(())?;
                    self.i += 1;
                    let ch = match e {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{8}',
                        b'f' => '\u{c}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'u' => {
                            let hi = self.hex4()?;
                            if (0xd800..0xdc00).contains(&hi) && self.s[self.i..].starts_with(b"\\u") {
                                let save = self.i;
                                self.i += 2;
                                let lo = self.hex4()?;
                                if (0xdc00..0xe000).contains(&lo) {
                                    char::from_u32(0x10000 + ((hi - 0xd800) << 10) + (lo - 0xdc00)).unwrap_or('\u{fffd}')
                                } else {
                                    self.i = save;
                                    '\u{fffd}'
                                }
                            } else {
                                char::from_u32(hi).unwrap_or('\u{fffd}')
                            }
                        }
                        _ => return Err(()),
                    };
                    let mut buf = [0u8; 4];
                    o.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                }
                c => o.push(c),
            }
        }
        Err(())
    }

    fn number(&mut self) -> Result<Value, ()> {
        let start = self.i;
        let digits = |p: &mut Self| {
            let s = p.i;
            while p.peek().is_some_and(|c| c.is_ascii_digit()) {
                p.i += 1;
            }
            p.i > s
        };
        if self.peek() == Some(b'-') {
            self.i += 1;
        }
        if !digits(self) {
            return Err(());
        }
        if self.peek() == Some(b'.') {
            self.i += 1;
            if !digits(self) {
                return Err(());
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.i += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.i += 1;
            }
            if !digits(self) {
                return Err(());
            }
        }
        Ok(Value::Num(String::from_utf8_lossy(&self.s[start..self.i]).into_owned()))
    }
}
