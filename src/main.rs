use bitcoin::{Address, Network, PublicKey as BtcPublicKey};
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use futures::{SinkExt, StreamExt};
use k256::elliptic_curve::point::AffineCoordinates;
use k256::elliptic_curve::PrimeField;
use k256::elliptic_curve::BatchNormalize;
use k256::{AffinePoint, ProjectivePoint, Scalar};
use rand::Rng;
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::io::Write;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::available_parallelism;
use std::time::Instant;
use tokio::sync::broadcast;
use warp::ws::Message;
use warp::Filter;

// ── Constants ──────────────────────────────────────────────────────────────

const TARGET_ADDRESS: &str = "1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU";
const RANGE_START: u128 = 1u128 << 70;
const RANGE_END: u128 = (1u128 << 71) - 1;
const RANGE_SIZE: u128 = RANGE_END - RANGE_START + 1;

/// Each "lottery ticket" is a random starting position followed by a
/// sequential scan of this many keys.  Small enough that overhead is
/// negligible; large enough that the incremental-addition fast path
/// dominates.  1M keys ≈ 0.5 s/thread at 2 M kps.
const SCAN_CHUNK: u128 = 1_048_576; // 2^20

/// Number of projective points accumulated before batch-normalizing.
const BATCH_SIZE: usize = 4096;

const OUTPUT_FILE: &str = "found_key.txt";
const SAMPLE_EVERY: u64 = 50_000_000;
const RELAY_ADDR: &str = "0.0.0.0:3030";

// ── Per-thread stats ───────────────────────────────────────────────────────

struct PerThreadStats {
    keys: AtomicU64,
}

impl PerThreadStats {
    fn new() -> Self {
        Self { keys: AtomicU64::new(0) }
    }
}

// ── Global stats ───────────────────────────────────────────────────────────

#[derive(Clone)]
struct Stats {
    total_checked: Arc<AtomicU64>,
    keys_per_second: Arc<AtomicU64>,
    running: Arc<AtomicBool>,
    found_key: Arc<parking_lot::RwLock<Option<String>>>,
    found_event_sent: Arc<AtomicBool>,
    start_time: Instant,
}

impl Stats {
    fn new() -> Self {
        Self {
            total_checked: Arc::new(AtomicU64::new(0)),
            keys_per_second: Arc::new(AtomicU64::new(0)),
            running: Arc::new(AtomicBool::new(true)),
            found_key: Arc::new(parking_lot::RwLock::new(None)),
            found_event_sent: Arc::new(AtomicBool::new(false)),
            start_time: Instant::now(),
        }
    }

    fn add(&self, n: u64) {
        self.total_checked.fetch_add(n, Ordering::Relaxed);
    }

    fn total(&self) -> u64 {
        self.total_checked.load(Ordering::Relaxed)
    }

    fn set_kps(&self, kps: u64) {
        self.keys_per_second.store(kps, Ordering::Relaxed);
    }

    fn kps(&self) -> u64 {
        self.keys_per_second.load(Ordering::Relaxed)
    }

    fn elapsed(&self) -> f64 {
        self.start_time.elapsed().as_secs_f64()
    }

    fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }

    fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    fn found(&self, key_hex: String) -> bool {
        if self.found_event_sent.swap(true, Ordering::SeqCst) {
            return false;
        }
        *self.found_key.write() = Some(key_hex);
        self.stop();
        true
    }

    fn found_key(&self) -> Option<String> {
        self.found_key.read().clone()
    }
}

// ── Crypto helpers ─────────────────────────────────────────────────────────

fn u128_to_scalar(val: u128) -> Scalar {
    let mut bytes = [0u8; 32];
    bytes[16..].copy_from_slice(&val.to_be_bytes());
    Scalar::from_repr(bytes.into())
        .into_option()
        .expect("u128 value is always a valid secp256k1 scalar")
}

fn affine_to_hash160(point: &AffinePoint) -> [u8; 20] {
    let x: [u8; 32] = point.x().into();
    let is_odd: bool = bool::from(point.y_is_odd());
    let prefix = if is_odd { 0x03u8 } else { 0x02u8 };
    let mut pubkey = [0u8; 33];
    pubkey[0] = prefix;
    pubkey[1..].copy_from_slice(&x);
    let sha = Sha256::digest(&pubkey);
    let mut hasher = Ripemd160::new();
    hasher.update(sha);
    let mut out = [0u8; 20];
    out.copy_from_slice(hasher.finalize().as_slice());
    out
}

fn secret_key_from_u128(val: u128) -> Option<SecretKey> {
    let mut key_bytes = [0u8; 32];
    key_bytes[16..].copy_from_slice(&val.to_be_bytes());
    SecretKey::from_slice(&key_bytes).ok()
}

fn secret_key_to_address(secp: &Secp256k1<bitcoin::secp256k1::All>, key: &SecretKey) -> String {
    let pk = PublicKey::from_secret_key(secp, key);
    let bitcoin_pk = BtcPublicKey::new(pk);
    Address::p2pkh(&bitcoin_pk, Network::Bitcoin).to_string()
}

fn save_key(key_hex: &str, address: &str) {
    match OpenOptions::new().create(true).append(true).open(OUTPUT_FILE) {
        Ok(mut f) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = f.set_permissions(std::fs::Permissions::from_mode(0o600));
            }
            if let Err(e) = writeln!(f, "Key: {} Address: {}", key_hex, address) {
                eprintln!("[ERROR] could not write to {}: {}", OUTPUT_FILE, e);
            } else {
                println!("Key saved to {}", OUTPUT_FILE);
            }
        }
        Err(e) => eprintln!("[ERROR] could not open {}: {}", OUTPUT_FILE, e),
    }
}

fn hash160_from_address(addr: &str) -> Result<[u8; 20], String> {
    use std::str::FromStr;
    let address = Address::from_str(addr)
        .map_err(|e| format!("invalid address: {}", e))?
        .require_network(Network::Bitcoin)
        .map_err(|e| format!("wrong network: {}", e))?;
    let script = address.script_pubkey();
    let script_bytes = script.as_bytes();
    if script_bytes.len() == 25 && script_bytes[0] == 0x76 && script_bytes[1] == 0xa9 && script_bytes[2] == 0x14 {
        let mut h = [0u8; 20];
        h.copy_from_slice(&script_bytes[3..23]);
        Ok(h)
    } else {
        Err("target address must be P2PKH".to_string())
    }
}

// ── Verification ───────────────────────────────────────────────────────────

fn test_save_key() {
    use std::fs;
    let _ = fs::remove_file(OUTPUT_FILE);
    save_key("0000000000000000000000000000000000000000000000000000000000000001", "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH");
    save_key("0000000000000000000000000000000000000000000000000000000000000002", "1cMh228HTCiwS8ZsaakH8A8wze1JR5ZsP");
    let content = fs::read_to_string(OUTPUT_FILE).expect("read file");
    let lines: Vec<&str> = content.lines().collect();
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0], "Key: 0000000000000000000000000000000000000000000000000000000000000001 Address: 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH");
    assert_eq!(lines[1], "Key: 0000000000000000000000000000000000000000000000000000000000000002 Address: 1cMh228HTCiwS8ZsaakH8A8wze1JR5ZsP");
    fs::remove_file(OUTPUT_FILE).ok();
    println!("save_key test: PASS");
}

fn verify_address_generation() {
    println!("=== ADDRESS GENERATION VERIFICATION ===\n");
    let secp = Secp256k1::new();
    let tests = [
        ("0000000000000000000000000000000000000000000000000000000000000001", "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"),
        ("0000000000000000000000000000000000000000000000000000000000000002", "1cMh228HTCiwS8ZsaakH8A8wze1JR5ZsP"),
        ("0000000000000000000000000000000000000000000000000000000000000003", "1CUNEBjYrCn2y1SdiUMohaKUi4wpP326Lb"),
    ];

    for (i, (hex, expected)) in tests.iter().enumerate() {
        let key = SecretKey::from_slice(&hex::decode(hex).unwrap()).unwrap();
        let addr = secret_key_to_address(&secp, &key);
        let ok = addr == *expected;
        println!("Test {}: {} - {}", i + 1, if ok { "PASS" } else { "FAIL" }, hex);
        if !ok {
            println!(" got:      {}", addr);
            println!(" expected: {}", expected);
        }
        assert_eq!(addr, *expected, "Test {}: address generation mismatch", i + 1);
    }
}

// ── Solver worker ──────────────────────────────────────────────────────────
//
// Each thread operates like an independent lottery-ticket buyer:
//   1. Pick a random position in [RANGE_START, RANGE_END - SCAN_CHUNK).
//   2. Compute the starting point via one fresh scalar multiplication.
//   3. Scan SCAN_CHUNK keys sequentially (fast: incremental point addition).
//   4. Repeat.
//
// This gives *random coverage* across the entire keyspace at essentially
// the same per-key cost as a pure sequential scan.

fn solver_worker(
    stats: Stats,
    per_thread: Arc<Vec<PerThreadStats>>,
    target_hash160: [u8; 20],
    thread_id: usize,
    tx: broadcast::Sender<String>,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    threads_active: Arc<AtomicU64>,
) {
    // Pin this thread to a specific CPU core to eliminate cache migration.
    if let Some(core_ids) = core_affinity::get_core_ids() {
        let core_id = core_ids[thread_id % core_ids.len()];
        core_affinity::set_for_current(core_id);
    }

    let secp = Secp256k1::new();
    let g_affine = ProjectivePoint::GENERATOR.to_affine();
    let target_first = target_hash160[0];

    // Per-thread PRNG — seeded from OS entropy once at start.
    let mut rng = rand::thread_rng();

    // Pre-allocate the projective point buffer once.
    let mut proj_buf: Vec<ProjectivePoint> = Vec::with_capacity(BATCH_SIZE);

    let mut local_count: u64 = 0;
    let mut last_update = Instant::now();
    let mut next_sample = stats.total() + SAMPLE_EVERY;

    let chunk_span = SCAN_CHUNK;
    // The maximum start position so we never overflow RANGE_END.
    let max_start = RANGE_END.saturating_sub(chunk_span) + 1;

    // Main lottery loop: pick random spots, scan, repeat.
    'outer: while stats.is_running() {
        let chunk_start = rng.gen_range(RANGE_START..=max_start);
        let chunk_end = chunk_start + chunk_span;

        // One fresh scalar multiplication to reach the random start point.
        let start_scalar = u128_to_scalar(chunk_start);

        let mut current_point = ProjectivePoint::GENERATOR * start_scalar;
        let mut current_key = chunk_start;

        // Sequential scan within the chunk (fast path).
        while current_key < chunk_end {
            let remaining = chunk_end - current_key;
            let this_batch = remaining.min(BATCH_SIZE as u128) as usize;

            // Actual first key in this batch — used for accurate sample/found reporting.
            let batch_start_key = current_key;

            proj_buf.clear();
            for _ in 0..this_batch {
                proj_buf.push(current_point);
                current_point += &g_affine;
            }
            current_key += this_batch as u128;
            local_count += this_batch as u64;

            let affine_points = ProjectivePoint::batch_normalize(&proj_buf[..]);
            for (i, affine) in affine_points.iter().enumerate() {
                let h = affine_to_hash160(affine);
                if h[0] == target_first && h == target_hash160 {
                    let found_key = batch_start_key + i as u128;
                    let hex = format!("{:064x}", found_key);
                    println!(
                        "[Thread {}] 🎉 FOUND! Key: {}  (offset {} in chunk @ {})",
                        thread_id, hex, i, chunk_start
                    );
                    if let Some(secret_key) = secret_key_from_u128(found_key) {
                        let addr = secret_key_to_address(&secp, &secret_key);
                        if stats.found(hex.clone()) {
                            save_key(&hex, &addr);
                            let _ = tx.send(format!(
                                "{{\"type\":\"found\",\"thread\":{},\"key\":\"{}\",\"address\":\"{}\"}}",
                                thread_id, hex, addr
                            ));
                            shutdown_tx.send_replace(true);
                        }
                    } else {
                        eprintln!("[Thread {}] hash160 match but invalid secret key?!", thread_id);
                    }
                    break 'outer;
                }
            }

            // ── Sample key emission (every SAMPLE_EVERY keys globally) ──
            let total_seen = stats.total() + local_count;
            if total_seen >= next_sample {
                let hex = format!("{:064x}", batch_start_key);
                if let Some(sk) = secret_key_from_u128(batch_start_key) {
                    let addr = secret_key_to_address(&secp, &sk);
                    let _ = tx.send(format!(
                        "{{\"type\":\"sample\",\"thread\":{},\"milestone\":{},\"key\":\"{}\",\"address\":\"{}\"}}",
                        thread_id,
                        next_sample / SAMPLE_EVERY,
                        hex,
                        addr
                    ));
                }
                next_sample += SAMPLE_EVERY;
            }

            // ── Periodic stats flush (every ~500 ms) ──
            if last_update.elapsed().as_millis() >= 500 {
                stats.add(local_count);
                per_thread[thread_id]
                    .keys
                    .fetch_add(local_count, Ordering::Relaxed);
                local_count = 0;
                last_update = Instant::now();
            }
        }
    }

    // Flush remaining local count.
    stats.add(local_count);
    per_thread[thread_id]
        .keys
        .fetch_add(local_count, Ordering::Relaxed);

    // Last thread to exit signals shutdown (in case key was never found).
    if threads_active.fetch_sub(1, Ordering::SeqCst) == 1 {
        shutdown_tx.send_replace(true);
    }
}

// ── Stats broadcaster (tokio task) ─────────────────────────────────────────

async fn stats_broadcaster(
    stats: Stats,
    per_thread: Arc<Vec<PerThreadStats>>,
    tx: broadcast::Sender<String>,
) {
    let num_threads = per_thread.len();
    let mut last_total: u64 = 0;
    let mut last_per_thread: Vec<u64> = vec![0; num_threads];
    let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(500));

    while stats.is_running() {
        interval.tick().await;
        if !stats.is_running() {
            break;
        }

        // Global KPS — computed from total delta, race-free (no atomic resets).
        let current_total = stats.total();
        let global_kps =
            ((current_total.saturating_sub(last_total)) as f64 / 0.5) as u64;
        last_total = current_total;
        stats.set_kps(global_kps);

        // Per-thread KPS.
        let mut thread_parts: Vec<String> = Vec::with_capacity(num_threads);
        for (i, pt) in per_thread.iter().enumerate() {
            let current = pt.keys.load(Ordering::Relaxed);
            let kps =
                ((current.saturating_sub(last_per_thread[i])) as f64 / 0.5) as u64;
            last_per_thread[i] = current;
            thread_parts.push(format!(
                "{{\"id\":{},\"kps\":{},\"keys\":{}}}",
                i, kps, current
            ));
        }

        let _ = tx.send(format!(
            "{{\"type\":\"stats\",\"total\":{},\"kps\":{},\"elapsed\":{:.1}}}",
            current_total, global_kps, stats.elapsed()
        ));
        let _ = tx.send(format!(
            "{{\"type\":\"thread_stats\",\"threads\":[{}]}}",
            thread_parts.join(",")
        ));
    }
}

// ── Main ───────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--verify") {
        verify_address_generation();
        test_save_key();
        println!("\nAll verifications complete.");
        return;
    }

    assert!(
        SCAN_CHUNK <= RANGE_SIZE,
        "SCAN_CHUNK ({}) exceeds RANGE_SIZE ({})",
        SCAN_CHUNK,
        RANGE_SIZE
    );

    let target_hash160 = match hash160_from_address(TARGET_ADDRESS) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("[ERROR] {}", e);
            return;
        }
    };
    println!("Target hash160: {}", hex::encode(target_hash160));

    let num_threads = available_parallelism()
        .map(NonZeroUsize::get)
        .unwrap_or(1);

    let stats = Stats::new();
    let per_thread: Arc<Vec<PerThreadStats>> = Arc::new(
        (0..num_threads).map(|_| PerThreadStats::new()).collect(),
    );
    let threads_active = Arc::new(AtomicU64::new(num_threads as u64));
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
    let (tx, _) = broadcast::channel::<String>(1024);

    println!("=== BTC Puzzle Solver ===");
    println!("Mode:       random lottery scan (trust luck)");
    println!("Range:      0x{:032x} .. 0x{:032x}", RANGE_START, RANGE_END);
    println!("Keyspace:   ~{:.3}e18 keys", RANGE_SIZE as f64 / 1e18);
    println!(
        "Lottery:    {} random chunks of {:.0}K keys each",
        "∞",
        SCAN_CHUNK as f64 / 1000.0
    );
    println!("Target:     {} ({})", TARGET_ADDRESS, hex::encode(target_hash160));
    println!("Threads:    {}", num_threads);
    println!("Batch size: {}", BATCH_SIZE);
    println!(
        "Relay bind: {} (override with RUST_RELAY_ADDR env)",
        RELAY_ADDR
    );
    println!("Run with --verify to verify address generation\n");

    // ── Spawn solver threads ──────────────────────────────────────────
    let mut handles = Vec::with_capacity(num_threads);
    for i in 0..num_threads {
        let s = stats.clone();
        let pt = per_thread.clone();
        let tgt = target_hash160;
        let tx_c = tx.clone();
        let stx = shutdown_tx.clone();
        let ta = threads_active.clone();

        handles.push(std::thread::spawn(move || {
            solver_worker(s, pt, tgt, i, tx_c, stx, ta);
        }));
    }

    // ── Stats broadcaster ─────────────────────────────────────────────
    let sc = stats.clone();
    let ptc = per_thread.clone();
    let txc = tx.clone();
    tokio::spawn(async move {
        stats_broadcaster(sc, ptc, txc).await;
    });

    // ── Warp WebSocket relay + dashboard ──────────────────────────────
    let tx_ws = tx.clone();
    let ws_route = warp::path("ws")
        .and(warp::ws())
        .map(move |ws: warp::ws::Ws| {
            let mut rx = tx_ws.subscribe();
            ws.on_upgrade(move |websocket| async move {
                let (mut tx_ws_sock, _rx_ws) = websocket.split();
                while let Ok(msg) = rx.recv().await {
                    if tx_ws_sock.send(Message::text(msg)).await.is_err() {
                        break;
                    }
                }
            })
        });

    let html = warp::path::end().map(|| warp::reply::html(include_str!("index.html")));
    let routes = html.or(ws_route);

    let bind: std::net::SocketAddr = std::env::var("RUST_RELAY_ADDR")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| RELAY_ADDR.parse().unwrap());

    println!("Dashboard: http://{}", bind);

    // Graceful shutdown: warp exits when shutdown_rx flips to true.
    let (_, server) = warp::serve(routes).bind_with_graceful_shutdown(bind, async move {
        loop {
            if *shutdown_rx.borrow() {
                break;
            }
            shutdown_rx.changed().await.ok();
        }
        println!("\nShutting down server...");
    });
    server.await;

    // ── Wait for all solver threads to finish ─────────────────────────
    for h in handles {
        h.join().ok();
    }

    let elapsed = stats.elapsed();
    let total = stats.total();
    println!(
        "Done. Checked {} keys in {:.1}s ({:.0} kps avg).",
        total,
        elapsed,
        total as f64 / elapsed.max(0.001)
    );

    if let Some(key) = stats.found_key() {
        println!("🎉 FOUND PRIVATE KEY: {}", key);
    } else {
        println!("Key not found — keep trying (just re-run for a fresh lottery).");
    }
}
