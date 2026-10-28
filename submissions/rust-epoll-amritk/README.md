# Rust: one epoll loop per core, own HTTP/1.1 and Postgres wire protocol

| Piece | Version |
|---|---|
| Language | Rust 1.97.0 (rustup in `/opt/rust`, edition 2024), fat LTO, one codegen unit, `target-cpu=native` |
| HTTP | own HTTP/1.1 parser and server on raw `epoll` (`libc` 0.2.191) |
| Postgres | own wire-protocol v3 client: SCRAM-SHA-256, prepared statements, binary results, pipelining |
| gzip | `libdeflater` 1.26.1 (libdeflate), level 1 |
| JWT | own HS256 check on `hmac` 0.13.0 + `sha2` 0.11.1; `serde_json` 1.0.154 for token payloads and request bodies |

Every version is pinned in `Cargo.lock` (`cargo build --locked`).

## What carried over from the multicore challenge

The top entries there (rust-tokio, csharp-sockets, go-raw, c-iouring) all ended up in the same place: write the
HTTP server and the Postgres client yourself, keep per-connection state tiny, prepare every statement once and
pipeline. Their big win was batching reads into one statement, but that only paid off because Postgres shared the box
with the app. Here Postgres has its own 16 cores and the rules ask for one spec query per request, so the work moves
to the app side. That means CPU per request and memory per idle connection, times a million.

- **Nothing per idle connection.** A connection is a slab entry of under 100 bytes: fd, a generation counter, a few flags,
  and two `Vec`s that stay empty. Requests are read into a per-worker 64 KB scratch buffer and parsed in place. A
  connection only keeps bytes when a request arrives in pieces or the socket won't take a whole response. With 20,000
  open keep-alive connections the whole process was **5.6 MB RSS**. At a million, userland is about 100 MB and the rest
  is the kernel's socket memory.
- **No TCP keep-alive probes.** The Go example went from 248k to 650k users in part by turning these off. They are
  off here by default (no `SO_KEEPALIVE`), and the server never closes idle connections.
- **No shared state.** Each worker thread has its own epoll, its own `SO_REUSEPORT` listeners on both ports (the
  kernel spreads new connections across them), its own client connections and its own Postgres connections. There
  are no locks, no cross-thread wakeups and no work stealing.
- **Pipelined Postgres from the same event loop.** Each query is a Bind/Execute/Sync of a prepared statement,
  appended to that connection's send buffer and flushed once per epoll pass, so one `write` carries every query from
  that pass. Results are binary and get turned into JSON straight from the receive buffer: no row objects, no
  strings. Reads go to the least-loaded of the worker's read connections. Writes go to separate connections, so a
  commit's WAL flush never stalls reads queued behind it.
- **One write per response.** Headers go on the stack and the body (gzipped if over 1 KB and the client accepts
  gzip) goes out as a two-part `writev`.
- **Cheap gzip.** libdeflate at level 1 shrinks the feed from 5.1 KB to 1.9 KB. Locally it cost about 12% more server
  CPU than no gzip, and it cuts the bytes the NIC sends by 2.7x. Only the feed is over 1 KB.

## Rules

- **Queries:** the SQL from `SPEC.md` verbatim, one statement per request, prepared once per connection, each with
  its own Sync (its own implicit transaction). Writes are committed before the response goes out.
  `ON CONFLICT DO NOTHING` row count gives `already_liked`, and SQLSTATE 23503 gives 404 `post not found`.
- **Session settings only:** `plan_cache_mode = force_generic_plan`. Nothing in the database is created or changed.
- **No caching:** every request reads Postgres while it is being served. Only connections and prepared statements
  are reused. Every authenticated request checks the HS256 signature, `alg` and `exp`.
- **Connections:** by default 128 read + 32 write in total (160 of the 512 allowed), split evenly over the workers.
- `created_at` is decoded from binary microseconds and truncated to milliseconds in UTC.

## Configuration (env, all optional)

| Variable | Default | |
|---|---|---|
| `THREADS` | CPUs in the affinity mask | worker threads |
| `DB_READ_CONNS` | 128 | total read connections, split over the workers |
| `DB_WRITE_CONNS` | 32 | total write connections, split over the workers |
| `GZIP_LEVEL` | 1 | libdeflate level |
| `GZIP_MIN` | 1024 | smallest body that gets gzipped |

## Measured on Synteq boxes

Three Synteq VPSs (Xeon Platinum 8260, Ubuntu 24.04): the server on a 16-vCPU / 32 GB app box set up with
`box/setup-app-box.sh`, Postgres 18 on its own 24-vCPU box (`box/setup-db-box.sh`, `box/postgresql.conf`), and
`mload` on a 24-vCPU / 31 GB box with 9 source IPs. Each run started from a fresh `feed` (`box/reset-db.sh`) with
`-gzip -think-scale 2.5`.

| users | ramp / hold | req/s in hold | p95 | p99 | errors | server CPU (of 16 vCPU) | result |
|--:|--:|--:|--:|--:|--:|--:|:--|
| 100,000 | 60 s / 2 m | 4,400 | 1.8 ms | 7.6 ms | 0 | ~3% | pass |
| 300,000 | 120 s / 1 m | 13,000 | 10.6 ms | 32.3 ms | 0 | ~8% | pass |
| 700,000 | 200 s / 2 m | 29,000 | 229 ms | 465 ms | 0.002% | ~16% | pass |
| 1,000,000 | 300 s / 5 m | 40,000 | 1–9 s | 1.5–11 s | 0.006% | ~15% | fail (latency) |

At 1M users all 1,000,000 connections stay open, there are no failed requests during the hold and the server uses
about 15% of the box, but latency fails. Above about 580k open connections, every box starts retransmitting, even
the database box with its 161 connections. That happens at a steady request rate too, and a UDP test showed no loss
at 200k packets per second. The packets are being dropped outside the VMs, which looks like a per-VM flow/conntrack
limit in the host network. During a 700k hold, requests sent straight to the server took 1–3 ms at p95, from
localhost and from the database box. The latency comes from those retransmits, not from the server.

What it took to load 1M users from one generator (changes to a local copy of `mload` only, none to `bench/`):
binding users round-robin to 9 source IPs, a fixed source port per user (the kernel's port search in `connect()`
pegged the load box at 92% system CPU past ~32k connections per destination), pooled per-request buffers (28 → 11
KB per user), and `GOGC=1000` (GC mark assists were stalling simulated users for hundreds of ms).

## Local measurements

A 4-vCPU dev container, with Postgres 16, the load generator and the server all on the same machine. The server was
pinned to **one core** (`taskset -c 0`, `THREADS=1`) and `mload` ran on two others. These numbers are not comparable to
the benchmark boxes.

| users | think-scale | req/s | p95 | p99 | errors | server CPU | server RSS |
|--:|--:|--:|--:|--:|--:|--:|--:|
| 20,000 | 0.25 | 8,400 | 6–80 ms | 37–240 ms | 0.06% (the load generator's own open-file limit) | ~77% of 1 core | 5.6 MB |
| 15,000 | 0.2 | 6,990 | 4.7 ms | 37.5 ms | 0 | | |

That is roughly 60 µs of CPU per request on loopback, counting the kernel's work for both ends. A million users is
about 42,000 req/s.

`test/run.sh`: 42/42. Also checked by hand: pipelined requests answered in order, requests split across many
packets, `Connection: close`, `Expect: 100-continue`, and garbage request lines (400, then close).

## Build and run

```bash
sudo bash install.sh   # build-essential + Rust 1.97.0 in /opt/rust
bash build.sh          # -> target/release/feed-server
DATABASE_URL=postgres://feed:pw@db:5432/feed JWT_SECRET=million-users-challenge HOST=0.0.0.0 PORT=80 EXTRA_PORT=81 bash start.sh
```
