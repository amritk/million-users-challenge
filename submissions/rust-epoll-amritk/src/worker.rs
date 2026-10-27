// One worker per core: its own epoll instance, its own SO_REUSEPORT listeners on both ports, its own client
// connections and its own Postgres connections. Nothing is shared between workers, so there are no locks.
//
// An idle client connection is one slab entry (fd, generation, two empty Vecs): requests are read into a
// per-worker scratch buffer and only an incomplete request or an unsent response tail is ever copied into the
// connection itself.

use crate::pg::{self, DbConfig, Done, Kind, PgConn, Pending};
use crate::util::{json_str, push_int, push_timestamp, verify_jwt, AuthError, HmacSha256};
use libdeflater::{CompressionLvl, Compressor};
use std::io;
use std::os::fd::RawFd;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const T_LISTEN: u64 = 1 << 62;
const T_PG: u64 = 2 << 62;
const T_MASK: u64 = 3 << 62;

const MAX_HEADER: usize = 16 * 1024;
const MAX_BODY: usize = 64 * 1024;

pub struct Settings {
    pub host: String,
    pub ports: Vec<u16>,
    pub db: DbConfig,
    pub read_conns: usize,
    pub write_conns: usize,
    pub gzip_level: i32,
    pub gzip_min: usize,
    pub jwt_secret: Vec<u8>,
    pub start: Instant,
}

struct Conn {
    fd: RawFd,
    generation: u32,
    busy: bool,         // a query for this connection is in Postgres; later requests wait in `inb`
    close_after: bool,  // close once `out` is written (Connection: close, or a malformed request)
    sent_continue: bool,
    want_out: bool,     // EPOLLOUT registered
    inb: Vec<u8>,
    out: Vec<u8>,
    out_off: usize,
}

struct PgSlot {
    conn: Option<PgConn>,
    write: bool,
    dirty: bool,
    last_try: Instant,
}

pub struct Worker<'a> {
    s: &'a Settings,
    ep: RawFd,
    conns: Vec<Conn>,
    free: Vec<u32>,
    pgs: Vec<PgSlot>,
    scratch: Vec<u8>,
    done: Vec<Done>,
    body: Vec<u8>,
    gz: Compressor,
    gzbuf: Vec<u8>,
    key: HmacSha256,
    pg_down: usize,
}

fn cvt(r: libc::c_int) -> io::Result<libc::c_int> {
    if r < 0 { Err(io::Error::last_os_error()) } else { Ok(r) }
}

fn setopt(fd: RawFd, level: i32, opt: i32, v: i32) -> io::Result<()> {
    cvt(unsafe {
        libc::setsockopt(fd, level, opt, &v as *const i32 as *const _, std::mem::size_of::<i32>() as u32)
    })
    .map(|_| ())
}

fn listener(host: &str, port: u16) -> io::Result<RawFd> {
    let ip: std::net::Ipv4Addr = host.parse().map_err(|_| io::Error::other(format!("HOST {host}: not an IPv4 address")))?;
    unsafe {
        let fd = cvt(libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC, 0))?;
        setopt(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR, 1)?;
        setopt(fd, libc::SOL_SOCKET, libc::SO_REUSEPORT, 1)?;
        let mut sa: libc::sockaddr_in = std::mem::zeroed();
        sa.sin_family = libc::AF_INET as u16;
        sa.sin_port = port.to_be();
        sa.sin_addr.s_addr = u32::from(ip).to_be();
        cvt(libc::bind(fd, &sa as *const _ as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_in>() as u32))?;
        cvt(libc::listen(fd, 65535))?;
        Ok(fd)
    }
}

fn status_line(status: u16) -> &'static [u8] {
    match status {
        200 => b"HTTP/1.1 200 OK\r\n",
        201 => b"HTTP/1.1 201 Created\r\n",
        400 => b"HTTP/1.1 400 Bad Request\r\n",
        401 => b"HTTP/1.1 401 Unauthorized\r\n",
        404 => b"HTTP/1.1 404 Not Found\r\n",
        503 => b"HTTP/1.1 503 Service Unavailable\r\n",
        _ => b"HTTP/1.1 500 Internal Server Error\r\n",
    }
}

fn error_body(msg: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(msg.len() + 12);
    v.extend_from_slice(b"{\"error\":");
    json_str(&mut v, msg.as_bytes());
    v.push(b'}');
    v
}

#[derive(PartialEq)]
enum Method {
    Get,
    Post,
    Other,
}

struct Req<'a> {
    method: Method,
    path: &'a [u8],
    auth: Option<&'a [u8]>,
    body: &'a [u8],
    gzip: bool,
    close: bool,
}

enum Parse<'a> {
    Incomplete { expect_continue: bool },
    Bad,
    Done(Req<'a>, usize),
}

fn trim(b: &[u8]) -> &[u8] {
    let s = b.iter().position(|c| *c != b' ' && *c != b'\t').unwrap_or(b.len());
    let e = b.iter().rposition(|c| *c != b' ' && *c != b'\t').map_or(s, |e| e + 1);
    &b[s..e]
}

fn contains_ci(h: &[u8], needle: &[u8]) -> bool {
    h.windows(needle.len()).any(|w| w.eq_ignore_ascii_case(needle))
}

fn parse(data: &[u8]) -> Parse<'_> {
    let Some(hend) = data.windows(4).position(|w| w == b"\r\n\r\n") else {
        return if data.len() > MAX_HEADER { Parse::Bad } else { Parse::Incomplete { expect_continue: false } };
    };
    let bstart = hend + 4;
    let mut lines = data[..hend].split(|&b| b == b'\n');
    let line = lines.next().unwrap_or(b"");
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    let mut parts = line.split(|&b| b == b' ');
    let (m, target, ver) = match (parts.next(), parts.next(), parts.next()) {
        (Some(m), Some(t), Some(v)) if v.starts_with(b"HTTP/1.") => (m, t, v),
        _ => return Parse::Bad,
    };
    let method = match m {
        b"GET" => Method::Get,
        b"POST" => Method::Post,
        _ => Method::Other,
    };
    let path = target.split(|&b| b == b'?').next().unwrap_or(b"");
    let mut req = Req { method, path, auth: None, body: &[], gzip: false, close: ver == b"HTTP/1.0" };
    let mut clen = 0usize;
    let mut expect = false;
    for h in lines {
        let h = h.strip_suffix(b"\r").unwrap_or(h);
        let Some(c) = h.iter().position(|&b| b == b':') else { continue };
        let (k, v) = (&h[..c], trim(&h[c + 1..]));
        match k.len() {
            13 if k.eq_ignore_ascii_case(b"authorization") => req.auth = Some(v),
            14 if k.eq_ignore_ascii_case(b"content-length") => {
                match std::str::from_utf8(v).ok().and_then(|v| v.parse::<usize>().ok()) {
                    Some(n) if n <= MAX_BODY => clen = n,
                    _ => return Parse::Bad,
                }
            }
            15 if k.eq_ignore_ascii_case(b"accept-encoding") => req.gzip = contains_ci(v, b"gzip"),
            10 if k.eq_ignore_ascii_case(b"connection") => {
                if v.eq_ignore_ascii_case(b"close") {
                    req.close = true;
                } else if v.eq_ignore_ascii_case(b"keep-alive") {
                    req.close = false;
                }
            }
            6 if k.eq_ignore_ascii_case(b"expect") => expect = v.eq_ignore_ascii_case(b"100-continue"),
            17 if k.eq_ignore_ascii_case(b"transfer-encoding") => return Parse::Bad, // chunked bodies: out of scope
            _ => {}
        }
    }
    if data.len() < bstart + clen {
        return Parse::Incomplete { expect_continue: expect };
    }
    req.body = &data[bstart..bstart + clen];
    Parse::Done(req, bstart + clen)
}

impl<'a> Worker<'a> {
    pub fn new(s: &'a Settings) -> io::Result<Worker<'a>> {
        let ep = cvt(unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) })?;
        let lvl = CompressionLvl::new(s.gzip_level).unwrap_or_default();
        let key = <HmacSha256 as hmac::KeyInit>::new_from_slice(&s.jwt_secret).unwrap();
        let mut w = Worker {
            s,
            ep,
            conns: Vec::new(),
            free: Vec::new(),
            pgs: Vec::new(),
            scratch: vec![0u8; 64 * 1024],
            done: Vec::new(),
            body: Vec::with_capacity(16 * 1024),
            gz: Compressor::new(lvl),
            gzbuf: Vec::new(),
            key,
            pg_down: 0,
        };
        let long_ago = Instant::now() - Duration::from_secs(60);
        for i in 0..s.read_conns + s.write_conns {
            w.pgs.push(PgSlot { conn: None, write: i >= s.read_conns, dirty: false, last_try: long_ago });
            w.pg_down += 1;
            w.reconnect(i);
        }
        for (i, &port) in s.ports.iter().enumerate() {
            let fd = listener(&s.host, port)?;
            w.ctl(libc::EPOLL_CTL_ADD, fd, libc::EPOLLIN as u32, T_LISTEN | fd as u64 | (i as u64) << 32)?;
        }
        Ok(w)
    }

    fn ctl(&self, op: i32, fd: RawFd, events: u32, token: u64) -> io::Result<()> {
        let mut ev = libc::epoll_event { events, u64: token };
        cvt(unsafe { libc::epoll_ctl(self.ep, op, fd, &mut ev) }).map(|_| ())
    }

    fn reconnect(&mut self, i: usize) {
        let slot = &mut self.pgs[i];
        if slot.conn.is_some() || slot.last_try.elapsed() < Duration::from_secs(1) {
            return;
        }
        slot.last_try = Instant::now();
        match pg::connect(&self.s.db) {
            Ok(fd) => {
                self.pgs[i].conn = Some(PgConn::new(fd));
                self.pg_down -= 1;
                let _ = self.ctl(libc::EPOLL_CTL_ADD, fd, libc::EPOLLIN as u32, T_PG | i as u64);
            }
            Err(e) => eprintln!("postgres connect failed: {e}"),
        }
    }

    pub fn run(&mut self) -> ! {
        let mut events = vec![libc::epoll_event { events: 0, u64: 0 }; 1024];
        loop {
            let timeout = if self.pg_down > 0 { 1000 } else { -1 };
            let n = unsafe { libc::epoll_wait(self.ep, events.as_mut_ptr(), events.len() as i32, timeout) };
            for ev in &events[..n.max(0) as usize] {
                let (t, e) = (ev.u64, ev.events);
                match t & T_MASK {
                    0 => self.on_client(t, e),
                    T_LISTEN => self.on_accept(t as u32 as RawFd),
                    _ => self.on_pg((t & !T_MASK) as usize, e),
                }
            }
            for i in 0..self.pgs.len() {
                if self.pgs[i].dirty {
                    self.flush_pg(i);
                }
            }
            if self.pg_down > 0 {
                for i in 0..self.pgs.len() {
                    self.reconnect(i);
                }
            }
        }
    }

    fn on_accept(&mut self, lfd: RawFd) {
        for _ in 0..256 {
            let fd = unsafe { libc::accept4(lfd, std::ptr::null_mut(), std::ptr::null_mut(), libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC) };
            if fd < 0 {
                let e = io::Error::last_os_error();
                if e.raw_os_error() == Some(libc::EMFILE) || e.raw_os_error() == Some(libc::ENFILE) {
                    eprintln!("accept: {e}");
                }
                return;
            }
            let _ = setopt(fd, libc::IPPROTO_TCP, libc::TCP_NODELAY, 1);
            let idx = match self.free.pop() {
                Some(i) => i,
                None => {
                    self.conns.push(Conn {
                        fd: -1,
                        generation: 0,
                        busy: false,
                        close_after: false,
                        sent_continue: false,
                        want_out: false,
                        inb: Vec::new(),
                        out: Vec::new(),
                        out_off: 0,
                    });
                    (self.conns.len() - 1) as u32
                }
            };
            let c = &mut self.conns[idx as usize];
            c.fd = fd;
            c.generation = c.generation.wrapping_add(1) & 0x3fff_ffff;
            let token = (c.generation as u64) << 32 | idx as u64;
            if self.ctl(libc::EPOLL_CTL_ADD, fd, libc::EPOLLIN as u32, token).is_err() {
                self.close(idx);
            }
        }
    }

    fn close(&mut self, idx: u32) {
        let c = &mut self.conns[idx as usize];
        if c.fd < 0 {
            return;
        }
        unsafe { libc::close(c.fd) };
        c.fd = -1;
        c.generation = c.generation.wrapping_add(1) & 0x3fff_ffff; // late Postgres results for it are dropped
        c.busy = false;
        c.close_after = false;
        c.sent_continue = false;
        c.want_out = false;
        c.inb = Vec::new();
        c.out = Vec::new();
        c.out_off = 0;
        self.free.push(idx);
    }

    /// The slab index for a token if the connection it names is still open.
    fn live(&self, token: u64) -> Option<u32> {
        let idx = token as u32;
        let c = self.conns.get(idx as usize)?;
        (c.fd >= 0 && c.generation as u64 == token >> 32).then_some(idx)
    }

    fn on_client(&mut self, token: u64, events: u32) {
        let Some(idx) = self.live(token) else { return };
        if events & libc::EPOLLOUT as u32 != 0 {
            self.flush_client(idx);
            if self.conns[idx as usize].fd < 0 {
                return;
            }
        }
        if events & (libc::EPOLLIN | libc::EPOLLHUP | libc::EPOLLERR) as u32 == 0 {
            return;
        }
        let c = &self.conns[idx as usize];
        let n = unsafe { libc::read(c.fd, self.scratch.as_mut_ptr() as *mut _, self.scratch.len()) };
        if n == 0 {
            return self.close(idx);
        }
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() != io::ErrorKind::WouldBlock && e.kind() != io::ErrorKind::Interrupted {
                self.close(idx);
            }
            return;
        }
        let n = n as usize;
        let c = &mut self.conns[idx as usize];
        if c.inb.is_empty() && !c.busy {
            let buf = std::mem::take(&mut self.scratch);
            let used = self.process(idx, &buf[..n]);
            let c = &mut self.conns[idx as usize];
            if c.fd >= 0 && used < n {
                c.inb.extend_from_slice(&buf[used..n]);
            }
            self.scratch = buf;
        } else {
            if c.inb.len() + n > MAX_HEADER + MAX_BODY {
                return self.close(idx);
            }
            c.inb.extend_from_slice(&self.scratch[..n]);
            if !c.busy {
                self.process_inb(idx);
            }
        }
    }

    fn process_inb(&mut self, idx: u32) {
        let inb = std::mem::take(&mut self.conns[idx as usize].inb);
        let used = self.process(idx, &inb);
        let c = &mut self.conns[idx as usize];
        if c.fd >= 0 && used < inb.len() {
            let mut inb = inb;
            inb.drain(..used);
            c.inb = inb;
        }
    }

    /// Serves complete requests from `data` until one waits on Postgres. Returns the bytes consumed.
    fn process(&mut self, idx: u32, data: &[u8]) -> usize {
        let mut off = 0;
        while off < data.len() {
            let c = &self.conns[idx as usize];
            if c.fd < 0 || c.busy || c.close_after {
                break;
            }
            match parse(&data[off..]) {
                Parse::Incomplete { expect_continue } => {
                    if expect_continue && !c.sent_continue {
                        self.conns[idx as usize].sent_continue = true;
                        self.write_raw(idx, b"HTTP/1.1 100 Continue\r\n\r\n");
                    }
                    break;
                }
                Parse::Bad => {
                    self.conns[idx as usize].close_after = true;
                    self.respond(idx, 400, &error_body("bad request"), false);
                    return data.len();
                }
                Parse::Done(req, used) => {
                    off += used;
                    self.conns[idx as usize].sent_continue = false;
                    if req.close {
                        self.conns[idx as usize].close_after = true;
                    }
                    let token = (self.conns[idx as usize].generation as u64) << 32 | idx as u64;
                    self.route(idx, token, req);
                }
            }
        }
        off
    }

    fn route(&mut self, idx: u32, token: u64, req: Req) {
        let gzip = req.gzip;
        let p = req.path;
        let pending = |kind| Pending { client: token, kind, gzip };
        if req.method == Method::Get {
            if p == b"/feed" {
                return self.query(idx, false, b'f', &[], pending(Kind::Feed));
            }
            if let Some(id) = p.strip_prefix(b"/posts/") {
                if !id.contains(&b'/') {
                    return match crate::util::parse_pos_id(id) {
                        Some(id) => self.query(idx, false, b'p', &[&id.to_be_bytes()], pending(Kind::Post)),
                        None => self.respond(idx, 400, &error_body("invalid post id"), false),
                    };
                }
            }
            if p == b"/health" {
                return self.query(idx, false, b'h', &[], pending(Kind::Health));
            }
        } else if req.method == Method::Post {
            if p == b"/posts" {
                let user = match self.auth(idx, req.auth) {
                    Some(u) => u,
                    None => return,
                };
                let v: serde_json::Value = match serde_json::from_slice(req.body) {
                    Ok(v) => v,
                    Err(_) => return self.respond(idx, 400, &error_body("malformed JSON body"), false),
                };
                let body = match v.get("body").and_then(|b| b.as_str()).map(str::trim) {
                    Some(b) if !b.is_empty() => b,
                    _ => return self.respond(idx, 400, &error_body("body is required"), false),
                };
                if body.chars().count() > 500 {
                    return self.respond(idx, 400, &error_body("body must be at most 500 characters"), false);
                }
                let body = body.to_owned();
                let uid = user.id.to_be_bytes();
                return self.query(
                    idx,
                    true,
                    b'c',
                    &[&uid, body.as_bytes()],
                    pending(Kind::Create { body: body.clone(), username: user.username }),
                );
            }
            if let Some(rest) = p.strip_prefix(b"/posts/") {
                if let Some(id) = rest.strip_suffix(b"/like") {
                    if !id.contains(&b'/') {
                        let user = match self.auth(idx, req.auth) {
                            Some(u) => u,
                            None => return,
                        };
                        return match crate::util::parse_pos_id(id) {
                            Some(id) => self.query(
                                idx,
                                true,
                                b'l',
                                &[&user.id.to_be_bytes(), &id.to_be_bytes()],
                                pending(Kind::Like { post_id: id }),
                            ),
                            None => self.respond(idx, 400, &error_body("invalid post id"), false),
                        };
                    }
                }
            }
        }
        self.respond(idx, 404, &error_body("not found"), false)
    }

    fn auth(&mut self, idx: u32, header: Option<&[u8]>) -> Option<crate::util::AuthUser> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs_f64();
        match verify_jwt(header, &self.key, now) {
            Ok(u) => Some(u),
            Err(e) => {
                let msg = match e {
                    AuthError::Missing => "missing bearer token",
                    AuthError::Invalid => "invalid or expired token",
                    AuthError::Payload => "invalid token payload",
                };
                self.respond(idx, 401, &error_body(msg), false);
                None
            }
        }
    }

    /// Queues a prepared statement on the least-loaded live Postgres connection of the right kind.
    fn query(&mut self, idx: u32, write: bool, stmt: u8, params: &[&[u8]], p: Pending) {
        let mut best: Option<usize> = None;
        for (i, s) in self.pgs.iter().enumerate() {
            if s.write != write {
                continue;
            }
            if let Some(c) = &s.conn {
                if best.is_none_or(|b| c.queue.len() < self.pgs[b].conn.as_ref().unwrap().queue.len()) {
                    best = Some(i);
                }
            }
        }
        // no write connection left: writes can go on a read connection and vice versa
        let best = best.or_else(|| self.pgs.iter().position(|s| s.conn.is_some()));
        let Some(i) = best else {
            let health = matches!(p.kind, Kind::Health);
            return if health {
                self.respond(idx, 503, b"{\"status\":\"degraded\",\"db\":\"unreachable\",\"error\":\"no database connection\"}", false)
            } else {
                self.respond(idx, 500, &error_body("internal server error"), false)
            };
        };
        self.conns[idx as usize].busy = true;
        let slot = &mut self.pgs[i];
        slot.conn.as_mut().unwrap().query(stmt, params, p);
        slot.dirty = true;
    }

    fn flush_pg(&mut self, i: usize) {
        let slot = &mut self.pgs[i];
        slot.dirty = false;
        let Some(c) = slot.conn.as_mut() else { return };
        match c.flush() {
            Ok(all) => {
                if all == c.want_write {
                    let fd = c.fd;
                    c.want_write = !all;
                    let ev = if all { libc::EPOLLIN } else { libc::EPOLLIN | libc::EPOLLOUT };
                    let _ = self.ctl(libc::EPOLL_CTL_MOD, fd, ev as u32, T_PG | i as u64);
                }
            }
            Err(e) => self.pg_failed(i, e),
        }
    }

    fn on_pg(&mut self, i: usize, events: u32) {
        if events & libc::EPOLLOUT as u32 != 0 {
            self.flush_pg(i);
        }
        let mut done = std::mem::take(&mut self.done);
        let r = match self.pgs[i].conn.as_mut() {
            Some(c) => c.read(&mut done),
            None => Ok(()),
        };
        for d in done.drain(..) {
            self.finish(d);
        }
        self.done = done;
        if let Err(e) = r {
            self.pg_failed(i, e);
        }
    }

    fn pg_failed(&mut self, i: usize, e: io::Error) {
        let Some(c) = self.pgs[i].conn.take() else { return };
        eprintln!("postgres connection lost: {e}");
        unsafe { libc::close(c.fd) };
        self.pg_down += 1;
        for p in c.queue {
            let msg = e.to_string();
            self.finish(Done { pending: p, body: Vec::new(), rows: 0, affected: 0, ret_id: 0, ret_ts: 0, error: Some((*b"08006", msg)) });
        }
    }

    /// Builds and sends the response for a finished query.
    fn finish(&mut self, d: Done) {
        let Some(idx) = self.live(d.pending.client) else { return };
        self.conns[idx as usize].busy = false;
        let gzip = d.pending.gzip;
        let mut b = std::mem::take(&mut self.body);
        b.clear();
        let status = match (&d.pending.kind, &d.error) {
            (Kind::Health, None) => {
                b.extend_from_slice(b"{\"status\":\"ok\",\"db\":\"ok\",\"uptime_s\":");
                push_int(&mut b, self.s.start.elapsed().as_secs() as i64);
                b.push(b'}');
                200
            }
            (Kind::Health, Some((_, msg))) => {
                b.extend_from_slice(b"{\"status\":\"degraded\",\"db\":\"unreachable\",\"error\":");
                json_str(&mut b, msg.as_bytes());
                b.push(b'}');
                503
            }
            (Kind::Like { .. }, Some((code, _))) if code == b"23503" => {
                b.extend_from_slice(b"{\"error\":\"post not found\"}");
                404
            }
            (_, Some((code, msg))) => {
                eprintln!("query failed: {msg} (SQLSTATE {})", String::from_utf8_lossy(code));
                b.extend_from_slice(b"{\"error\":\"internal server error\"}");
                500
            }
            (Kind::Feed, None) => {
                b.extend_from_slice(b"{\"posts\":[");
                b.extend_from_slice(&d.body);
                b.extend_from_slice(b"]}");
                200
            }
            (Kind::Post, None) if d.rows == 0 => {
                b.extend_from_slice(b"{\"error\":\"post not found\"}");
                404
            }
            (Kind::Post, None) => {
                b.extend_from_slice(b"{\"post\":");
                b.extend_from_slice(&d.body);
                b.push(b'}');
                200
            }
            (Kind::Create { body, username, .. }, None) => {
                b.extend_from_slice(b"{\"post\":{\"id\":");
                push_int(&mut b, d.ret_id);
                b.extend_from_slice(b",\"body\":");
                json_str(&mut b, body.as_bytes());
                b.extend_from_slice(b",\"created_at\":");
                push_timestamp(&mut b, d.ret_ts);
                b.extend_from_slice(b",\"author\":");
                json_str(&mut b, username.as_bytes());
                b.extend_from_slice(b",\"like_count\":0}}");
                201
            }
            (Kind::Like { post_id }, None) => {
                b.extend_from_slice(if d.affected > 0 {
                    b"{\"liked\":true,\"already_liked\":false,\"post_id\":"
                } else {
                    b"{\"liked\":true,\"already_liked\":true,\"post_id\":"
                });
                push_int(&mut b, *post_id);
                b.push(b'}');
                if d.affected > 0 { 201 } else { 200 }
            }
        };
        self.respond(idx, status, &b, gzip);
        self.body = b;
        let c = &self.conns[idx as usize];
        if c.fd >= 0 && !c.busy && !c.inb.is_empty() {
            self.process_inb(idx);
        }
    }

    fn respond(&mut self, idx: u32, status: u16, body: &[u8], gzip: bool) {
        let mut gz = std::mem::take(&mut self.gzbuf);
        let mut payload = body;
        let compressed = gzip && body.len() >= self.s.gzip_min && {
            gz.resize(self.gz.gzip_compress_bound(body.len()), 0);
            match self.gz.gzip_compress(body, &mut gz) {
                Ok(n) => {
                    gz.truncate(n);
                    payload = &gz;
                    true
                }
                Err(_) => false,
            }
        };
        let mut h = [0u8; 160];
        let mut hl = 0;
        let mut put = |s: &[u8]| {
            h[hl..hl + s.len()].copy_from_slice(s);
            hl += s.len();
        };
        put(status_line(status));
        put(b"Content-Type: application/json\r\n");
        if compressed {
            put(b"Content-Encoding: gzip\r\n");
        }
        if self.conns[idx as usize].close_after {
            put(b"Connection: close\r\n");
        }
        put(b"Content-Length: ");
        let mut num = Vec::with_capacity(8);
        push_int(&mut num, payload.len() as i64);
        put(&num);
        put(b"\r\n\r\n");
        self.write_parts(idx, &h[..hl], payload);
        self.gzbuf = gz;
        let c = &self.conns[idx as usize];
        if c.fd >= 0 && c.close_after && c.out.is_empty() {
            self.close(idx);
        }
    }

    fn write_raw(&mut self, idx: u32, data: &[u8]) {
        self.write_parts(idx, data, &[]);
    }

    fn write_parts(&mut self, idx: u32, a: &[u8], b: &[u8]) {
        let c = &mut self.conns[idx as usize];
        if c.fd < 0 {
            return;
        }
        if !c.out.is_empty() {
            c.out.extend_from_slice(a);
            c.out.extend_from_slice(b);
            return;
        }
        let iov = [
            libc::iovec { iov_base: a.as_ptr() as *mut _, iov_len: a.len() },
            libc::iovec { iov_base: b.as_ptr() as *mut _, iov_len: b.len() },
        ];
        let total = a.len() + b.len();
        let n = loop {
            let n = unsafe { libc::writev(c.fd, iov.as_ptr(), if b.is_empty() { 1 } else { 2 }) };
            if n < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            break n;
        };
        let n = if n < 0 {
            if io::Error::last_os_error().kind() != io::ErrorKind::WouldBlock {
                return self.close(idx);
            }
            0
        } else {
            n as usize
        };
        if n < total {
            if n < a.len() {
                c.out.extend_from_slice(&a[n..]);
                c.out.extend_from_slice(b);
            } else {
                c.out.extend_from_slice(&b[n - a.len()..]);
            }
            c.out_off = 0;
            if !c.want_out {
                c.want_out = true;
                let (fd, token) = (c.fd, (c.generation as u64) << 32 | idx as u64);
                let _ = self.ctl(libc::EPOLL_CTL_MOD, fd, (libc::EPOLLIN | libc::EPOLLOUT) as u32, token);
            }
        }
    }

    fn flush_client(&mut self, idx: u32) {
        let c = &mut self.conns[idx as usize];
        while c.out_off < c.out.len() {
            let n = unsafe { libc::write(c.fd, c.out[c.out_off..].as_ptr() as *const _, c.out.len() - c.out_off) };
            if n < 0 {
                let e = io::Error::last_os_error();
                match e.kind() {
                    io::ErrorKind::Interrupted => continue,
                    io::ErrorKind::WouldBlock => return,
                    _ => return self.close(idx),
                }
            }
            c.out_off += n as usize;
        }
        c.out = Vec::new();
        c.out_off = 0;
        c.want_out = false;
        let (fd, token, close) = (c.fd, (c.generation as u64) << 32 | idx as u64, c.close_after);
        if close {
            return self.close(idx);
        }
        let _ = self.ctl(libc::EPOLL_CTL_MOD, fd, libc::EPOLLIN as u32, token);
    }
}
