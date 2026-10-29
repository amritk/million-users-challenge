# Nish / standard library

Nish 0.24.0 (a statically typed TypeScript subset compiled to native code through LLVM), built with clang-18 and
lld-18 from LLVM 18, against PostgreSQL 18. The compiler runs on Node.js 22.18.0 at build time only. The server is one
native binary with no runtime dependency beyond libc. Every import is Nish's own standard library:
`nish/net/http1-server` for HTTP/1.1, `nish/net/http-compress` for gzip, `nish/net/postgres` for the PostgreSQL wire protocol, `nish/json` and
`nish/json-tokenizer`, `nish/crypto/hmac` and `nish/net/prefork`. No third-party package is used.

```sh
sudo bash install.sh
bash build.sh
DATABASE_URL=postgres://feed:pw@db:5432/feed JWT_SECRET=million-users-challenge HOST=0.0.0.0 PORT=80 EXTRA_PORT=81 bash start.sh
```

## What carried over from the multicore challenge

This is a port of this author's multicore-challenge entry (nish-std-amritk) to the feed API. That challenge put
Postgres and the server on one 8-core box, and its biggest win was batching reads into "read plans". This one gives
Postgres its own 16-core box and asks for SPEC.md's queries, one per request (rule 3), so read plans don't apply.
The cost that matters is the server's CPU per request and its memory per idle connection, times a million.

Carried over:

- **Workers that share nothing.** A prefork parent starts one worker per CPU and restarts none of them (rule 10).
  Each worker binds both `PORT` and `EXTRA_PORT` with `SO_REUSEPORT` and `TCP_NODELAY`, and runs one epoll loop over
  its two listeners, its keep-alive connections and its PostgreSQL connections.
- **Idle connections hold no buffers.** With `Http1Config.idleInput`, a connection between requests gives its input
  and head buffers back to pools its worker shares. Locally, 15,000 open connections took 30 MB of RSS in all, about
  2 KB each. Nish 0.23.1's HTTP/1 server no longer walks every connection on every loop turn: at a million
  connections, any per-turn work that grows with the number of connections would be fatal.
- **Prepared, pipelined Postgres.** Each worker has its own read pool and write pool, so a commit's WAL flush never
  holds up reads queued behind it on a connection. Up to 16 groups are pipelined on each connection. Every statement
  is prepared once per connection. `plan_cache_mode=force_generic_plan`, `jit=off`,
  `max_parallel_workers_per_gather=0`, `DateStyle=ISO` and `TimeZone=UTC` go in the startup packet as session
  options. `enable_memoize` is already off server-wide in this challenge's `postgresql.conf`.
- **Rows straight into JSON.** Columns are read in place from the receive buffer: ids and like counts are copied as
  their digits, text goes through the JSON writer's escaper, and timestamps go through `PgText.timestamp`, which
  truncates to milliseconds. No string is made per row, and nothing is allocated per request once the worker has
  served its peak.
- **Tokens.** HS256 over an HMAC keyed once with `JWT_SECRET`, adapted from the multicore entry's `jwt.ts`: each
  signature copies the two keyed SHA-256 states. The signature, `alg` and `exp` are checked on every request, and
  nothing is cached between requests.

## Rules

- **Queries:** SPEC.md's SQL, one statement per request, each in its own Sync, so its own implicit transaction.
  Writes are committed before the response goes out. The `INSERT ... ON CONFLICT DO NOTHING` row count gives
  `already_liked`, and SQLSTATE 23503 gives 404 `post not found`.
- Nothing in the database is created or changed. Only session settings are used.
- **No caching:** every request reads Postgres while it is being served. Only connections and prepared statements
  are reused.
- **Connections:** by default 128 read and 32 write in total, split evenly over the workers (8 + 2 per worker on 16
  cores). That is 160 of the 512 allowed.
- **Compression:** when `Accept-Encoding` asks for gzip, bodies of 1 KB or more are gzipped at the fast level (Nish
  0.24.0's `HttpCompressor` and `Http1Connection.respondEncoded`). In practice that is only the feed: 5,102 bytes go
  out as 1,899. Smaller bodies (a post, a like, an error) are sent as they are, and `Vary` is left off because no cache
  sits in front of the server.

## Configuration (env, all optional)

| Variable | Default | |
|---|---|---|
| `HTTP_WORKERS` | the CPUs | worker processes |
| `DB_READ_CONNS` | 128 | total read connections, split over the workers |
| `DB_WRITE_CONNS` | 32 | total write connections, split over the workers |
| `DB_MAX_IN_FLIGHT` | 16 | groups pipelined on one connection |
| `HTTP_SLOTS` | 1048576 | connections per port per worker (the search goes up to 3,000,000 users on 4 cores: 375,000 per port per worker) |
| `GZIP_LEVEL` | 1 | deflate level (1 = fast, 6 = default) |
| `GZIP_MIN` | 1024 | smallest body that is gzipped; larger than any body (e.g. 999999) turns gzip off |
| `IDLE_TIMEOUT_MS` | 120000 | idle keep-alive connections are closed after this (SPEC.md asks for at least 75 s) |

## Local measurements

These were taken in a 4-vCPU dev container, with Postgres 16, `mload` and the server all on one machine, so they are
not comparable to the benchmark boxes. The server ran on one core (`taskset -c 0`, `HTTP_WORKERS=1`) and `mload` on
two others, with 15,000 users at `-think-scale 0.2`, `-gzip`, a 15 s ramp and a 40 s hold:

| | req/s | p95 | p99 | errors | server CPU ticks |
|---|--:|--:|--:|--:|--:|
| this server, gzip (default) | 6,998 / 6,984 | 1.6 / 1.7 ms | 6.3 / 7.6 ms | 0 | 1,794 / 1,755 |
| this server, gzip off (`GZIP_MIN=999999999`) | 6,995 / 6,994 | 1.3 / 1.2 ms | 2.9 / 2.5 ms | 0 | 1,507 / 1,388 |
| the same API in Rust (own epoll HTTP and Postgres client), libdeflate gzip | 6,991 | 4.7 ms | 37.5 ms | 0 | 2,205 |
| the same Rust server, gzip off | 6,988 | 3.1 ms | 7.9 ms | 0 | 1,963 |

The two Nish rows alternated, run by run. RSS was 30 MB with the 15,000 connections open, about 2 KB per connection.
On loopback gzip costs about 23% more server CPU, against 12% for libdeflate in Rust. It cuts the feed's bytes by
2.7x, and the box's network is part of the test (SPEC.md), so it stays on.

`test/run.sh`: 42/42.
