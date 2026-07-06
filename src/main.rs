use bitcoin::{Address, Network, PublicKey};
use futures::{SinkExt, StreamExt};
use parking_lot::RwLock;
use secp256k1::{PublicKey as SecpPublicKey, Secp256k1, SecretKey};
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::broadcast;
use warp::ws::Message;
use warp::Filter;

const TARGET_ADDRESS: &str = "1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU";
const RANGE_START: u128 = 0x400000000000000000;
const RANGE_END: u128 = 0x7fffffffffffffffff;
const NUM_THREADS: u32 = 8;
const OUTPUT_FILE: &str = "found_key.txt";
const SAMPLE_EVERY: u64 = 1_000_000;

struct Stats {
    total_checked: Arc<AtomicU64>,
    keys_per_second: Arc<AtomicU64>,
    is_running: Arc<AtomicBool>,
    found_key: Arc<RwLock<Option<String>>>,
    start_time: Instant,
}

impl Stats {
    fn new() -> Self {
        Self {
            total_checked: Arc::new(AtomicU64::new(0)),
            keys_per_second: Arc::new(AtomicU64::new(0)),
            is_running: Arc::new(AtomicBool::new(true)),
            found_key: Arc::new(RwLock::new(None)),
            start_time: Instant::now(),
        }
    }

    fn increment(&self, n: u64) -> u64 {
        self.total_checked.fetch_add(n, Ordering::Relaxed)
    }

    fn get_total(&self) -> u64 {
        self.total_checked.load(Ordering::Relaxed)
    }

    fn update_kps(&self, kps: u64) {
        self.keys_per_second.store(kps, Ordering::Relaxed);
    }

    fn elapsed_secs(&self) -> f64 {
        self.start_time.elapsed().as_secs_f64()
    }

    fn stop(&self) {
        self.is_running.store(false, Ordering::Relaxed);
    }

    fn found(&self, key: String) {
        *self.found_key.write() = Some(key);
        self.stop();
    }
}

impl Clone for Stats {
    fn clone(&self) -> Self {
        Self {
            total_checked: self.total_checked.clone(),
            keys_per_second: self.keys_per_second.clone(),
            is_running: self.is_running.clone(),
            found_key: self.found_key.clone(),
            start_time: self.start_time,
        }
    }
}

fn u128_to_secret_key(val: u128) -> SecretKey {
    let bytes = val.to_be_bytes();
    let mut key_bytes = [0u8; 32];
    key_bytes[16..].copy_from_slice(&bytes);
    SecretKey::from_slice(&key_bytes).unwrap()
}

fn secret_key_to_address(secp: &Secp256k1<secp256k1::All>, key: &SecretKey) -> String {
    let public_key = SecpPublicKey::from_secret_key(secp, key);
    let bitcoin_pubkey = PublicKey {
        inner: public_key,
        compressed: true,
    };
    let address = Address::p2pkh(&bitcoin_pubkey, Network::Bitcoin);
    address.to_string()
}

fn save_key_to_file(hex_key: &str, address: &str) {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(OUTPUT_FILE)
        .expect("Cannot open output file");
    writeln!(file, "Key: {} Address: {}", hex_key, address).expect("Cannot write");
    println!("Key saved to {}", OUTPUT_FILE);
}

fn verify_address_generation() {
    println!("=== ADDRESS GENERATION VERIFICATION ===\n");
    let secp = Secp256k1::new();

    let test_cases: Vec<(&str, &str)> = vec![
        (
            "0000000000000000000000000000000000000000000000000000000000000001",
            "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
        ),
        (
            "0000000000000000000000000000000000000000000000000000000000000002",
            "1cMh228HTCiwS8ZsaakH8A8wze1JR5ZsP",
        ),
        (
            "0000000000000000000000000000000000000000000000000000000000000003",
            "1CUNEBjYrCn2y1SdiUMohaKUi4wpP326Lb",
        ),
    ];

    for (i, (hex_key, expected_addr)) in test_cases.iter().enumerate() {
        let key_bytes = hex::decode(hex_key).unwrap();
        let key = SecretKey::from_slice(&key_bytes).unwrap();
        let addr = secret_key_to_address(&secp, &key);

        let status = if &addr == expected_addr { "PASS" } else { "FAIL" };
        println!("Test {}: {} - {}", i + 1, status, hex_key);
        println!("  Generated: {}", addr);
        println!("  Expected:  {}", expected_addr);
        println!();
    }
}

fn verify_file_saving() {
    println!("=== FILE SAVING VERIFICATION ===\n");
    save_key_to_file(
        "deadbeef00000000000000000000000000000000000000000000000000000001",
        "1TestAddress",
    );
    let content = std::fs::read_to_string(OUTPUT_FILE).unwrap();
    println!("File content:\n{}", content);
    if content.contains("deadbeef") {
        println!("File save: PASS\n");
    } else {
        println!("File save: FAIL\n");
    }
    std::fs::remove_file(OUTPUT_FILE).ok();
}

fn solver_worker(stats: Stats, tx: broadcast::Sender<String>, thread_id: u32) {
    let secp = Secp256k1::new();
    let range_size = RANGE_END - RANGE_START;
    let mut local_count: u64 = 0;
    let mut last_update = Instant::now();

    while stats.is_running.load(Ordering::Relaxed) {
        let r1 = rand::random::<u64>() as u128;
        let r2 = rand::random::<u64>() as u128;
        let offset = (r1 << 64) | r2;
        let private_key = (offset % range_size) + RANGE_START;

        let key = u128_to_secret_key(private_key);
        let address = secret_key_to_address(&secp, &key);

        if address == TARGET_ADDRESS {
            let hex_key = format!("{:064x}", private_key);
            println!("[Thread {}] FOUND! Key: {} Addr: {}", thread_id, hex_key, address);
            save_key_to_file(&hex_key, &address);
            stats.found(hex_key.clone());
            let _ = tx.send(format!(
                "{{\"type\":\"found\",\"key\":\"{}\",\"address\":\"{}\"}}",
                hex_key, address
            ));
            return;
        }

        local_count += 1;

        if local_count % 1000 == 0 {
            let prev = stats.increment(1000);
            let next_sample = (prev / SAMPLE_EVERY + 1) * SAMPLE_EVERY;
            if prev < next_sample && prev + 1000 >= next_sample {
                let sample_hex = format!("{:064x}", private_key);
                println!(
                    "[Thread {}] Sample @ ~{}M | Key: {} | Addr: {}",
                    thread_id,
                    next_sample / SAMPLE_EVERY,
                    sample_hex,
                    address
                );
            }
        }

        if last_update.elapsed().as_millis() >= 500 {
            let elapsed = last_update.elapsed().as_secs_f64();
            let kps = (local_count as f64 / elapsed) as u64;
            stats.update_kps(kps);
            let _ = tx.send(format!(
                "{{\"type\":\"stats\",\"total\":{},\"kps\":{},\"elapsed\":{}}}",
                stats.get_total(),
                kps,
                stats.elapsed_secs()
            ));
            local_count = 0;
            last_update = Instant::now();
        }
    }
}

async fn stats_broadcaster(stats: Stats, tx: broadcast::Sender<String>) {
    loop {
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        if !stats.is_running.load(Ordering::Relaxed) {
            break;
        }
        let _ = tx.send(format!(
            "{{\"type\":\"stats\",\"total\":{},\"kps\":{},\"elapsed\":{}}}",
            stats.get_total(),
            stats.keys_per_second.load(Ordering::Relaxed),
            stats.elapsed_secs()
        ));
    }
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.iter().any(|a| a == "--verify") {
        verify_address_generation();
        verify_file_saving();
        println!("All verifications complete.");
        return;
    }

    let stats = Stats::new();
    let (tx, _) = broadcast::channel::<String>(100);

    println!("=== BTC Puzzle Solver ===");
    println!("Range: {:018x}..{:018x}", RANGE_START, RANGE_END);
    println!("Target: {}", TARGET_ADDRESS);
    println!("Threads: {}", NUM_THREADS);
    println!("Sample every: {}M keys", SAMPLE_EVERY / 1_000_000);
    println!("Run with --verify to prove correctness\n");

    for i in 0..NUM_THREADS {
        let stats_clone = stats.clone();
        let tx_clone = tx.clone();
        std::thread::spawn(move || {
            solver_worker(stats_clone, tx_clone, i);
        });
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
                let (mut tx_ws, mut _rx_ws) = websocket.split();
                while let Ok(msg) = rx.recv().await {
                    if tx_ws.send(Message::text(msg)).await.is_err() {
                        break;
                    }
                }
            })
        });

    let html = warp::path::end().map(|| warp::reply::html(include_str!("index.html")));

    let routes = html.or(ws_route);

    println!("Dashboard: http://localhost:3030");
    println!("Press Ctrl+C to stop\n");

    warp::serve(routes).run(([0, 0, 0, 0], 3030)).await;
}
