// A minimal PostgreSQL wire-protocol (v3) client: blocking startup (trust, cleartext or SCRAM-SHA-256), statements
// prepared once per connection, then non-blocking pipelined Bind/Execute/Sync driven by the worker's epoll loop.
// Results are requested in binary and turned into JSON straight from the receive buffer.

use crate::util::{b64_decode, b64_encode, json_str, push_int, push_timestamp, HmacSha256};
use hmac::{KeyInit, Mac};
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::os::fd::{IntoRawFd, RawFd};
use std::time::Duration;

const POST_SQL: &str = "SELECT p.id, p.body, p.created_at, u.username, \
     (SELECT count(*) FROM likes l WHERE l.post_id = p.id)::int AS like_count \
     FROM posts p JOIN users u ON u.id = p.user_id";

/// Prepared statements: (name, SQL, parameter type OIDs). 20 = int8, 25 = text.
fn statements() -> Vec<(&'static str, String, Vec<u32>)> {
    vec![
        ("f", format!("{POST_SQL} ORDER BY p.created_at DESC, p.id DESC LIMIT 20"), vec![]),
        ("p", format!("{POST_SQL} WHERE p.id = $1"), vec![20]),
        ("c", "INSERT INTO posts (user_id, body) VALUES ($1, $2) RETURNING id, created_at".into(), vec![20, 25]),
        ("l", "INSERT INTO likes (user_id, post_id) VALUES ($1, $2) ON CONFLICT (user_id, post_id) DO NOTHING".into(), vec![20, 20]),
        ("h", "SELECT 1".into(), vec![]),
    ]
}

#[derive(Clone)]
pub struct DbConfig {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: String,
    pub database: String,
}

fn pct_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

impl DbConfig {
    /// postgres://user:password@host:port/database[?...]
    pub fn parse(url: &str) -> Result<DbConfig, String> {
        let rest = url
            .strip_prefix("postgres://")
            .or_else(|| url.strip_prefix("postgresql://"))
            .ok_or("DATABASE_URL must start with postgres://")?;
        let rest = rest.split('?').next().unwrap();
        let (auth, hostpart) = match rest.rfind('@') {
            Some(i) => (&rest[..i], &rest[i + 1..]),
            None => ("", rest),
        };
        let (user, password) = match auth.find(':') {
            Some(i) => (pct_decode(&auth[..i]), pct_decode(&auth[i + 1..])),
            None => (pct_decode(auth), String::new()),
        };
        let (hostport, database) = match hostpart.find('/') {
            Some(i) => (&hostpart[..i], pct_decode(&hostpart[i + 1..])),
            None => (hostpart, user.clone()),
        };
        let (host, port) = match hostport.rfind(':') {
            Some(i) if !hostport.ends_with(']') => {
                (hostport[..i].to_string(), hostport[i + 1..].parse().map_err(|_| "bad port in DATABASE_URL")?)
            }
            _ => (hostport.to_string(), 5432),
        };
        let host = host.trim_start_matches('[').trim_end_matches(']').to_string();
        let host = if host.is_empty() { "localhost".into() } else { host };
        Ok(DbConfig { host, port, user, password, database })
    }
}

fn msg(out: &mut Vec<u8>, tag: u8, body: &[u8]) {
    out.push(tag);
    out.extend_from_slice(&(body.len() as u32 + 4).to_be_bytes());
    out.extend_from_slice(body);
}

fn read_msg(s: &mut TcpStream) -> io::Result<(u8, Vec<u8>)> {
    let mut h = [0u8; 5];
    s.read_exact(&mut h)?;
    let len = u32::from_be_bytes([h[1], h[2], h[3], h[4]]) as usize;
    let mut body = vec![0u8; len.saturating_sub(4)];
    s.read_exact(&mut body)?;
    Ok((h[0], body))
}

fn pg_error_text(body: &[u8]) -> String {
    let mut msg = String::new();
    let mut code = String::new();
    for f in body.split(|&b| b == 0) {
        if let Some((&t, v)) = f.split_first() {
            match t {
                b'M' => msg = String::from_utf8_lossy(v).into_owned(),
                b'C' => code = String::from_utf8_lossy(v).into_owned(),
                _ => {}
            }
        }
    }
    format!("{msg} (SQLSTATE {code})")
}

fn err(s: String) -> io::Error {
    io::Error::other(s)
}

fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut m = <HmacSha256 as KeyInit>::new_from_slice(key).unwrap();
    m.update(data);
    m.finalize().into_bytes().into()
}

fn pbkdf2(password: &[u8], salt: &[u8], iters: u32) -> [u8; 32] {
    let mut s = salt.to_vec();
    s.extend_from_slice(&1u32.to_be_bytes());
    let mut u = hmac(password, &s);
    let mut out = u;
    for _ in 1..iters {
        u = hmac(password, &u);
        for (o, x) in out.iter_mut().zip(u.iter()) {
            *o ^= x;
        }
    }
    out
}

fn scram(s: &mut TcpStream, cfg: &DbConfig) -> io::Result<()> {
    let mut nonce = [0u8; 18];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut nonce)?;
    let cnonce = b64_encode(&nonce);
    let first_bare = format!("n=,r={cnonce}");
    let first = format!("n,,{first_bare}");
    let mut body = b"SCRAM-SHA-256\0".to_vec();
    body.extend_from_slice(&(first.len() as u32).to_be_bytes());
    body.extend_from_slice(first.as_bytes());
    let mut out = Vec::new();
    msg(&mut out, b'p', &body);
    s.write_all(&out)?;
    let (t, b) = read_msg(s)?;
    if t == b'E' {
        return Err(err(pg_error_text(&b)));
    }
    if t != b'R' || b.len() < 4 || u32::from_be_bytes([b[0], b[1], b[2], b[3]]) != 11 {
        return Err(err("SCRAM: expected SASLContinue".into()));
    }
    let server_first = String::from_utf8_lossy(&b[4..]).into_owned();
    let (mut r, mut salt, mut iters) = (None, None, 0u32);
    for kv in server_first.split(',') {
        if let Some(v) = kv.strip_prefix("r=") {
            r = Some(v.to_string());
        } else if let Some(v) = kv.strip_prefix("s=") {
            salt = b64_decode(v.as_bytes(), false);
        } else if let Some(v) = kv.strip_prefix("i=") {
            iters = v.parse().unwrap_or(0);
        }
    }
    let (r, salt) = match (r, salt) {
        (Some(r), Some(salt)) if r.starts_with(&cnonce) && iters > 0 => (r, salt),
        _ => return Err(err("SCRAM: bad server-first message".into())),
    };
    let salted = pbkdf2(cfg.password.as_bytes(), &salt, iters);
    let client_key = hmac(&salted, b"Client Key");
    let stored_key: [u8; 32] = Sha256::digest(client_key).into();
    let final_wo_proof = format!("c=biws,r={r}");
    let auth_msg = format!("{first_bare},{server_first},{final_wo_proof}");
    let sig = hmac(&stored_key, auth_msg.as_bytes());
    let proof: Vec<u8> = client_key.iter().zip(sig.iter()).map(|(a, b)| a ^ b).collect();
    let fin = format!("{final_wo_proof},p={}", b64_encode(&proof));
    out.clear();
    msg(&mut out, b'p', fin.as_bytes());
    s.write_all(&out)?;
    let (t, b) = read_msg(s)?;
    if t == b'E' {
        return Err(err(pg_error_text(&b)));
    }
    let server_key = hmac(&salted, b"Server Key");
    let want = format!("v={}", b64_encode(&hmac(&server_key, auth_msg.as_bytes())));
    if t != b'R' || b.len() < 4 || u32::from_be_bytes([b[0], b[1], b[2], b[3]]) != 12 || b[4..] != *want.as_bytes() {
        return Err(err("SCRAM: server signature mismatch".into()));
    }
    Ok(())
}

/// Opens an authenticated connection with every statement prepared; returns it in non-blocking mode.
pub fn connect(cfg: &DbConfig) -> io::Result<RawFd> {
    let addr = (cfg.host.as_str(), cfg.port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| err(format!("cannot resolve {}", cfg.host)))?;
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(5))?;
    s.set_nodelay(true)?;
    s.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut body = Vec::new();
    body.extend_from_slice(&196608u32.to_be_bytes());
    for (k, v) in [("user", cfg.user.as_str()), ("database", cfg.database.as_str()), ("application_name", "feed-server")] {
        body.extend_from_slice(k.as_bytes());
        body.push(0);
        body.extend_from_slice(v.as_bytes());
        body.push(0);
    }
    body.push(0);
    let mut out = Vec::new();
    out.extend_from_slice(&(body.len() as u32 + 4).to_be_bytes());
    out.extend_from_slice(&body);
    s.write_all(&out)?;
    loop {
        let (t, b) = read_msg(&mut s)?;
        match t {
            b'R' => {
                let code = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
                match code {
                    0 => {}
                    3 => {
                        let mut pw = cfg.password.as_bytes().to_vec();
                        pw.push(0);
                        out.clear();
                        msg(&mut out, b'p', &pw);
                        s.write_all(&out)?;
                    }
                    10 => scram(&mut s, cfg)?,
                    _ => return Err(err(format!("unsupported Postgres auth method {code}"))),
                }
            }
            b'E' => return Err(err(pg_error_text(&b))),
            b'Z' => break,
            _ => {}
        }
    }
    // Session settings only. Every statement here has one plan that fits all parameters.
    out.clear();
    msg(&mut out, b'Q', b"SET plan_cache_mode = force_generic_plan\0");
    for (name, sql, types) in statements() {
        let mut b = Vec::new();
        b.extend_from_slice(name.as_bytes());
        b.push(0);
        b.extend_from_slice(sql.as_bytes());
        b.push(0);
        b.extend_from_slice(&(types.len() as u16).to_be_bytes());
        for t in types {
            b.extend_from_slice(&t.to_be_bytes());
        }
        msg(&mut out, b'P', &b);
    }
    msg(&mut out, b'S', &[]);
    s.write_all(&out)?;
    let mut ready = 0;
    while ready < 2 {
        let (t, b) = read_msg(&mut s)?;
        match t {
            b'E' => return Err(err(pg_error_text(&b))),
            b'Z' => ready += 1,
            _ => {}
        }
    }
    s.set_nonblocking(true)?;
    Ok(s.into_raw_fd())
}

/// What a queued query is for; tells the response builder how to read its rows.
pub enum Kind {
    Health,
    Feed,
    Post,
    Create { body: String, username: String },
    Like { post_id: i64 },
}

pub struct Pending {
    pub client: u64,
    pub kind: Kind,
    pub gzip: bool,
}

/// The finished result of one query.
pub struct Done {
    pub pending: Pending,
    /// Rows JSON (Feed: post objects joined by commas; Post: one post object). Create: the RETURNING row as
    /// `id` and `created_at` in `ret_*`.
    pub body: Vec<u8>,
    pub rows: u32,
    pub affected: i64,
    pub ret_id: i64,
    pub ret_ts: i64,
    /// SQLSTATE and message of an ErrorResponse, if any.
    pub error: Option<([u8; 5], String)>,
}

pub struct PgConn {
    pub fd: RawFd,
    pub out: Vec<u8>,
    out_off: usize,
    inb: Vec<u8>,
    in_off: usize,
    pub queue: VecDeque<Pending>,
    // current result
    body: Vec<u8>,
    rows: u32,
    affected: i64,
    ret_id: i64,
    ret_ts: i64,
    error: Option<([u8; 5], String)>,
    pub want_write: bool,
}

#[inline]
fn be_i64(b: &[u8]) -> i64 {
    i64::from_be_bytes(b[..8].try_into().unwrap())
}
#[inline]
fn be_i32(b: &[u8]) -> i32 {
    i32::from_be_bytes(b[..4].try_into().unwrap())
}

impl PgConn {
    pub fn new(fd: RawFd) -> PgConn {
        PgConn {
            fd,
            out: Vec::with_capacity(16 * 1024),
            out_off: 0,
            inb: Vec::with_capacity(64 * 1024),
            in_off: 0,
            queue: VecDeque::new(),
            body: Vec::with_capacity(8 * 1024),
            rows: 0,
            affected: 0,
            ret_id: 0,
            ret_ts: 0,
            error: None,
            want_write: false,
        }
    }

    /// Queues Bind (binary parameters and results) + Execute + Sync for prepared statement `stmt`.
    pub fn query(&mut self, stmt: u8, params: &[&[u8]], p: Pending) {
        let o = &mut self.out;
        let start = o.len();
        o.push(b'B');
        o.extend_from_slice(&[0, 0, 0, 0]);
        o.push(0); // unnamed portal
        o.push(stmt);
        o.push(0);
        o.extend_from_slice(&[0, 1, 0, 1]); // one format code for all parameters: binary
        o.extend_from_slice(&(params.len() as u16).to_be_bytes());
        for v in params {
            o.extend_from_slice(&(v.len() as u32).to_be_bytes());
            o.extend_from_slice(v);
        }
        o.extend_from_slice(&[0, 1, 0, 1]); // all results binary
        let len = (o.len() - start - 1) as u32;
        o[start + 1..start + 5].copy_from_slice(&len.to_be_bytes());
        o.extend_from_slice(&[b'E', 0, 0, 0, 9, 0, 0, 0, 0, 0, b'S', 0, 0, 0, 4]);
        self.queue.push_back(p);
    }

    /// Writes as much of the send buffer as the socket takes. Ok(true) when everything was sent.
    pub fn flush(&mut self) -> io::Result<bool> {
        while self.out_off < self.out.len() {
            let n = unsafe {
                libc::write(self.fd, self.out[self.out_off..].as_ptr() as *const _, self.out.len() - self.out_off)
            };
            if n < 0 {
                let e = io::Error::last_os_error();
                match e.kind() {
                    io::ErrorKind::WouldBlock => return Ok(false),
                    io::ErrorKind::Interrupted => continue,
                    _ => return Err(e),
                }
            }
            self.out_off += n as usize;
        }
        self.out.clear();
        self.out_off = 0;
        Ok(true)
    }

    /// Reads what the socket has and appends every finished query to `done`.
    pub fn read(&mut self, done: &mut Vec<Done>) -> io::Result<()> {
        loop {
            if self.inb.capacity() - self.inb.len() < 16 * 1024 {
                self.inb.reserve(64 * 1024);
            }
            let spare = self.inb.capacity() - self.inb.len();
            let n = unsafe { libc::read(self.fd, self.inb.as_mut_ptr().add(self.inb.len()) as *mut _, spare) };
            if n < 0 {
                let e = io::Error::last_os_error();
                match e.kind() {
                    io::ErrorKind::WouldBlock => return Ok(()),
                    io::ErrorKind::Interrupted => continue,
                    _ => return Err(e),
                }
            }
            if n == 0 {
                return Err(err("Postgres closed the connection".into()));
            }
            unsafe { self.inb.set_len(self.inb.len() + n as usize) };
            self.parse(done)?;
            if (n as usize) < spare {
                return Ok(());
            }
        }
    }

    fn parse(&mut self, done: &mut Vec<Done>) -> io::Result<()> {
        loop {
            let avail = &self.inb[self.in_off..];
            if avail.len() < 5 {
                break;
            }
            let len = be_i32(&avail[1..]) as usize;
            if avail.len() < 1 + len {
                break;
            }
            let tag = avail[0];
            let (s, e) = (self.in_off + 5, self.in_off + 1 + len);
            self.in_off = e;
            match tag {
                b'D' => self.data_row(s, e),
                b'C' => {
                    // "INSERT 0 <n>", "SELECT <n>": the last word is the row count
                    let t = &self.inb[s..e - 1];
                    let n = t.rsplit(|&b| b == b' ').next().unwrap_or(b"0");
                    self.affected = std::str::from_utf8(n).ok().and_then(|n| n.parse().ok()).unwrap_or(0);
                }
                b'E' => {
                    let mut code = [b'0'; 5];
                    let mut text = String::new();
                    for f in self.inb[s..e].split(|&b| b == 0) {
                        match f.split_first() {
                            Some((b'C', v)) if v.len() == 5 => code.copy_from_slice(v),
                            Some((b'M', v)) => text = String::from_utf8_lossy(v).into_owned(),
                            _ => {}
                        }
                    }
                    self.error = Some((code, text));
                }
                b'Z' => {
                    let pending =
                        self.queue.pop_front().ok_or_else(|| err("ReadyForQuery without a query".into()))?;
                    done.push(Done {
                        pending,
                        body: std::mem::replace(&mut self.body, Vec::with_capacity(8 * 1024)),
                        rows: self.rows,
                        affected: self.affected,
                        ret_id: self.ret_id,
                        ret_ts: self.ret_ts,
                        error: self.error.take(),
                    });
                    self.rows = 0;
                    self.affected = 0;
                }
                // BindComplete, NoData, ParameterStatus, NoticeResponse, ...: nothing to do
                _ => {}
            }
        }
        if self.in_off == self.inb.len() {
            self.inb.clear();
            self.in_off = 0;
        } else if self.in_off > 32 * 1024 {
            self.inb.drain(..self.in_off);
            self.in_off = 0;
        }
        Ok(())
    }

    fn data_row(&mut self, s: usize, e: usize) {
        let Some(p) = self.queue.front() else { return };
        let row = &self.inb[s..e];
        let mut cols: [&[u8]; 5] = [&[]; 5];
        let n = (u16::from_be_bytes([row[0], row[1]]) as usize).min(5);
        let mut i = 2;
        for c in cols.iter_mut().take(n) {
            let l = be_i32(&row[i..]);
            i += 4;
            if l > 0 {
                *c = &row[i..i + l as usize];
                i += l as usize;
            }
        }
        match p.kind {
            Kind::Feed | Kind::Post => {
                let b = &mut self.body;
                if self.rows > 0 {
                    b.push(b',');
                }
                b.extend_from_slice(b"{\"id\":");
                push_int(b, be_i64(cols[0]));
                b.extend_from_slice(b",\"body\":");
                json_str(b, cols[1]);
                b.extend_from_slice(b",\"created_at\":");
                push_timestamp(b, be_i64(cols[2]));
                b.extend_from_slice(b",\"author\":");
                json_str(b, cols[3]);
                b.extend_from_slice(b",\"like_count\":");
                push_int(b, be_i32(cols[4]) as i64);
                b.push(b'}');
            }
            Kind::Create { .. } => {
                self.ret_id = be_i64(cols[0]);
                self.ret_ts = be_i64(cols[1]);
            }
            _ => {}
        }
        self.rows += 1;
    }
}
