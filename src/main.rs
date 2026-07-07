use bitcoin::{Address, Network, PublicKey as BtcPublicKey};
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use futures::{SinkExt, StreamExt};
use k256::elliptic_curve::point::AffineCoordinates;
use k256::elliptic_curve::{BatchNormalize, PrimeField};
use k256::{AffinePoint, ProjectivePoint, Scalar};
use rand::seq::SliceRandom;
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

const TARGET_ADDRESS: &str = "1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU";
const RANGE_START: u128 = 1u128 << 70;
const RANGE_END: u128 = (1u128 << 71) - 1;
const BATCH_SIZE: usize = 8192;
const OUTPUT_FILE: &str = "found_key.txt";
const SAMPLE_EVERY: u64 = 50_000_000;
const RELAY_ADDR: &str = "127.0.0.1:3030";

#[derive(Clone)]
struct Stats {
    total_checked: Arc<AtomicU64>,
    keys_per_second: Arc<AtomicU64>,
    kps_window: Arc<AtomicU64>,
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
            kps_window: Arc::new(AtomicU64::new(0)),
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

    fn add_kps(&self, n: u64) {
        self.kps_window.fetch_add(n, Ordering::Relaxed);
    }

    fn collect_kps_and_reset(&self) -> u64 {
        self.kps_window.swap(0, Ordering::Relaxed)
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

    fn found(&self, key_hex: String) {
        if self.found_event_sent.swap(true, Ordering::SeqCst) {
            return;
        }
        *self.found_key.write() = Some(key_hex);
        self.stop();
    }

    fn found_key(&self) -> Option<String> {
        self.found_key.read().clone()
    }
}

fn u128_to_scalar(val: u128) -> Option<Scalar> {
    let mut bytes = [0u8; 32];
    bytes[16..].copy_from_slice(&val.to_be_bytes());
    Scalar::from_repr(bytes.into()).into_option()
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
        println!(" got: {}", addr);
        println!(" expected: {}", expected);
        assert_eq!(addr, *expected, "Test {}: address generation mismatch", i + 1);
    }
}

fn hash160_from_address(addr: &str) -> Result<[u8; 20], String> {
    use std::str::FromStr;
    let address = Address::from_str(addr).expect("valid address").assume_checked();
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

#[derive(Clone, Copy)]
struct ThreadSlice {
    start: u128,
    end: u128,
}

fn partition_range(n: usize) -> Vec<ThreadSlice> {
    let total = RANGE_END - RANGE_START;
    assert!(n > 0);
    let mut slices = Vec::with_capacity(n);
    for i in 0..n {
        let start = RANGE_START + (total * i as u128) / n as u128;
        let end = RANGE_START + (total * (i + 1) as u128) / n as u128;
        slices.push(ThreadSlice { start, end });
    }
    slices.shuffle(&mut rand::thread_rng());
    slices
}

fn solver_worker(
    stats: Stats,
    target_hash160: [u8; 20],
    thread_id: usize,
    slice: ThreadSlice,
    _num_threads: usize,
    tx: broadcast::Sender<String>,
) {
    let thread_start = slice.start;
    let thread_end = slice.end;
    if thread_start >= thread_end {
        return;
    }

    let start_scalar = match u128_to_scalar(thread_start) {
        Some(s) => s,
        None => {
            eprintln!("[Thread {}] start out of order", thread_id);
            return;
        }
    };

    let mut current_point = ProjectivePoint::GENERATOR * start_scalar;
    let mut current_key = thread_start;
    let mut local_count = 0u64;
    let mut last_update = Instant::now();

    let mut proj_buf: Vec<ProjectivePoint> = Vec::with_capacity(BATCH_SIZE);
    let secp = Secp256k1::new();

    let g_affine = ProjectivePoint::GENERATOR.to_affine();
    let target_first = target_hash160[0];

    let mut next_sample = SAMPLE_EVERY;

    while stats.is_running() && current_key < thread_end {
        let remaining = thread_end - current_key;
        let this_batch = remaining.min(BATCH_SIZE as u128) as usize;

        proj_buf.clear();
        for _ in 0..this_batch {
            proj_buf.push(current_point);
            current_point += &g_affine;
        }
        let batch_start_key = current_key;
        current_key += this_batch as u128;

        let affine_points = ProjectivePoint::batch_normalize(&proj_buf[..]);
        for (i, affine) in affine_points.iter().enumerate() {
            let h = affine_to_hash160(affine);
            if h[0] == target_first && h == target_hash160 {
                let found_key = batch_start_key + i as u128;
                let hex = format!("{:064x}", found_key);
                println!("[Thread {}] FOUND! Key: {}", thread_id, hex);
                if let Some(secret_key) = secret_key_from_u128(found_key) {
                    let addr = secret_key_to_address(&secp, &secret_key);
                    save_key(&hex, &addr);
                    stats.found(hex.clone());
                    let _ = tx.send(format!(
                        "{{\"type\":\"found\",\"thread\":{},\"key\":\"{}\",\"address\":\"{}\"}}",
                        thread_id, hex, addr
                    ));
                } else {
                    eprintln!("[Thread {}] hash match but key invalid?!", thread_id);
                }
                return;
            }
        }
        local_count += this_batch as u64;

        let total_seen = stats.total() + local_count;
        if total_seen >= next_sample && thread_start < thread_end {
            let progress = current_key.saturating_sub(thread_start).saturating_sub(this_batch as u128);
            let midpt = thread_start + progress / 2;
            let hex = format!("{:064x}", midpt);
            if let Some(sk) = secret_key_from_u128(midpt) {
                let addr = secret_key_to_address(&secp, &sk);
                let _ = tx.send(format!(
                    "{{\"type\":\"sample\",\"thread\":{},\"milestone\":{},\"key\":\"{}\",\"address\":\"{}\"}}",
                    thread_id, next_sample / SAMPLE_EVERY, hex, addr
                ));
            }
            next_sample += SAMPLE_EVERY;
        }

        if last_update.elapsed().as_millis() >= 500 {
            let elapsed = last_update.elapsed().as_secs_f64();
            if elapsed > 0.0 {
                stats.add_kps(local_count);
            }
            stats.add(local_count);
            local_count = 0;
            last_update = Instant::now();
        }
    }
    stats.add(local_count);
}

async fn stats_broadcaster(stats: Stats, tx: broadcast::Sender<String>) {
    let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(500));
    while stats.is_running() {
        interval.tick().await;
        if !stats.is_running() {
            break;
        }
        let window = stats.collect_kps_and_reset();
        let kps = (window as f64 / 0.5) as u64;
        stats.set_kps(kps);
        let _ = tx.send(format!(
            "{{\"type\":\"stats\",\"total\":{},\"kps\":{},\"elapsed\":{}}}",
            stats.total(),
            stats.kps(),
            stats.elapsed()
        ));
    }
    if let Some(key) = stats.found_key() {
        let _ = tx.send(format!("{{\"type\":\"found\",\"key\":\"{}\"}}", key));
    }
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--verify") {
        verify_address_generation();
        test_save_key();
        println!("\nAll verifications complete.");
        return;
    }

    let target_hash160 = match hash160_from_address(TARGET_ADDRESS) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("[ERROR] {}", e);
            return;
        }
    };
    println!("Target hash160: {}", hex::encode(target_hash160));

    let stats = Stats::new();
    let (tx, _) = broadcast::channel::<String>(1024);
    let num_threads = available_parallelism().map(NonZeroUsize::get).unwrap_or(1);

    let slices = partition_range(num_threads);

    println!("=== BTC Puzzle Solver ===");
    println!("Range: 0x{:032x}..0x{:032x}", RANGE_START, RANGE_END);
    println!("Target: {} ({})", TARGET_ADDRESS, hex::encode(target_hash160));
    println!("Threads: {}", num_threads);
    println!("Batch size: {}", BATCH_SIZE);
    println!("Relay bind: {} (override w/ RUST_RELAY_ADDR env)", RELAY_ADDR);
    println!("Run with --verify to verify address generation\n");

    let mut handles = Vec::new();
    for (i, slice) in slices.into_iter().enumerate() {
        let s = stats.clone();
        let t = target_hash160;
        let tx_clone = tx.clone();
        handles.push(std::thread::spawn(move || {
            solver_worker(s, t, i, slice, num_threads, tx_clone);
        }));
    }

    let stats_clone = stats.clone();
    let tx_clone = tx.clone();
    tokio::spawn(async move {
        stats_broadcaster(stats_clone, tx_clone).await;
    });

    let ws_route = warp::path("ws")
        .and(warp::ws())
        .map(move |ws: warp::ws::Ws| {
            let mut rx = tx.subscribe();
            ws.on_upgrade(move |websocket| async move {
                let (mut tx_ws, _rx_ws) = websocket.split();
                while let Ok(msg) = rx.recv().await {
                    if tx_ws.send(Message::text(msg)).await.is_err() {
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
    warp::serve(routes).run(bind).await;
}
