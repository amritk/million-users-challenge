// The Million Users Challenge feed API: one epoll event loop per core, own HTTP/1.1 and Postgres wire protocol.

mod pg;
mod util;
mod worker;

use std::time::Instant;

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

fn env_num(name: &str, default: usize) -> usize {
    env(name).and_then(|v| v.parse().ok()).unwrap_or(default)
}

fn main() {
    let start = Instant::now();
    let db = pg::DbConfig::parse(&env("DATABASE_URL").expect("DATABASE_URL is required")).unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(1)
    });
    let cores = std::thread::available_parallelism().map_or(1, |n| n.get());
    let threads = env_num("THREADS", cores).max(1);
    // Postgres connections are a total across workers (rule 5: at most 512), split evenly.
    let read_total = env_num("DB_READ_CONNS", 128).clamp(threads, 448);
    let write_total = env_num("DB_WRITE_CONNS", 32).clamp(threads, 512 - read_total);
    let mut ports = vec![env_num("PORT", 3000) as u16];
    if let Some(p) = env("EXTRA_PORT").and_then(|p| p.parse().ok()) {
        ports.push(p);
    }
    let settings = Box::leak(Box::new(worker::Settings {
        host: env("HOST").unwrap_or_else(|| "0.0.0.0".into()),
        ports,
        db,
        read_conns: read_total / threads,
        write_conns: write_total / threads,
        gzip_level: env_num("GZIP_LEVEL", 1) as i32,
        gzip_min: env_num("GZIP_MIN", 1024),
        jwt_secret: env("JWT_SECRET").unwrap_or_else(|| "million-users-challenge".into()).into_bytes(),
        start,
    }));
    eprintln!(
        "feed-server: {threads} workers, {} read + {} write Postgres connections each, ports {:?}",
        settings.read_conns, settings.write_conns, settings.ports
    );
    let handles: Vec<_> = (0..threads)
        .map(|i| {
            let s: &'static worker::Settings = settings;
            std::thread::Builder::new()
                .name(format!("worker-{i}"))
                .spawn(move || match worker::Worker::new(s) {
                    Ok(mut w) => w.run(),
                    Err(e) => {
                        eprintln!("worker {i}: {e}");
                        std::process::exit(1)
                    }
                })
                .unwrap()
        })
        .collect();
    for h in handles {
        let _ = h.join();
    }
}
