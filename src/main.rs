use bitcoin::{Address, Network, PublicKey as BtcPublicKey};
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use futures::{SinkExt, StreamExt};
use k256::{AffinePoint, ProjectivePoint, Scalar};
use k256::elliptic_curve::point::AffineCoordinates;
use k256::elliptic_curve::{BatchNormalize, PrimeField};
use parking_lot::RwLock;
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
const RANGE_START: u128 = 0x400000000000000000;
const RANGE_END: u128 = 0x7fffffffffffffffff;
const BATCH_SIZE: u64 = 1000;
const OUTPUT_FILE: &str = "found_key.txt";

#[derive(Clone)]
struct Stats {
    total_checked: Arc<AtomicU64>,
    keys_per_second: Arc<AtomicU64>,
    running: Arc<AtomicBool>,
    found_key: Arc<RwLock<Option<String>>>,
    start_time: Instant,
}

impl Stats {
    fn new() -> Self {
        Self {
            total_checked: Arc::new(AtomicU64::new(0)),
            keys_per_second: Arc::new(AtomicU64::new(0)),
            running: Arc::new(AtomicBool::new(true)),
            found_key: Arc::new(RwLock::new(None)),
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

    fn found(&self, key_hex: String) {
        *self.found_key.write() = Some(key_hex);
        self.stop();
    }
}

fn u128_to_scalar(val: u128) -> Scalar {
    let mut bytes = [0u8; 32];
    bytes[16..].copy_from_slice(&val.to_be_bytes());
    Scalar::from_repr(bytes.into()).unwrap()
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
    let mut hash160 = [0u8; 20];
    hash160.copy_from_slice(hasher.finalize().as_slice());
    hash160
}

fn secret_key_from_u128(val: u128) -> Option<SecretKey> {
    let bytes = val.to_be_bytes();
    let mut key_bytes = [0u8; 32];
    key_bytes[16..].copy_from_slice(&bytes);
    SecretKey::from_slice(&key_bytes).ok()
}

fn secret_key_to_address(secp: &Secp256k1<bitcoin::secp256k1::All>, key: &SecretKey) -> String {
    let pk = PublicKey::from_secret_key(secp, key);
    let bitcoin_pk = BtcPublicKey::new(pk);
    Address::p2pkh(&bitcoin_pk, Network::Bitcoin).to_string()
}

fn save_key(key_hex: &str, address: &str) {
    let mut f = OpenOptions::new().create(true).append(true).open(OUTPUT_FILE).expect("open file");
    writeln!(f, "Key: {} Address: {}", key_hex, address).expect("write file");
    println!("Key saved to {}", OUTPUT_FILE);
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
        println!("  got:      {}", addr);
        println!("  expected: {}", expected);
    }
}

fn hash160_from_address(addr: &str) -> [u8; 20] {
    use std::str::FromStr;
    let address = Address::from_str(addr).expect("valid address").assume_checked();
    let script = address.script_pubkey();
    let script_bytes = script.as_bytes();
    if script_bytes.len() == 25 && script_bytes[0] == 0x76 && script_bytes[1] == 0xa9 && script_bytes[2] == 0x14 {
        let mut h = [0u8; 20];
        h.copy_from_slice(&script_bytes[3..23]);
        h
    } else {
        panic!("target address must be P2PKH");
    }
}

fn solver_worker(stats: Stats, target_hash160: [u8; 20], thread_id: usize, num_threads: usize) {
    let range_size = RANGE_END - RANGE_START;
    let chunk_size = range_size / num_threads as u128;
    let start = RANGE_START + chunk_size * thread_id as u128;
    let end = if thread_id == num_threads - 1 { RANGE_END } else { start + chunk_size };

    let start_scalar = u128_to_scalar(start);
    let mut current_point = ProjectivePoint::GENERATOR * &start_scalar;
    let mut current_key = start;

    let mut local_count = 0u64;
    let mut last_update = Instant::now();

    while stats.is_running() && current_key < end {
        let batch_size = ((current_key + BATCH_SIZE as u128).min(end) - current_key) as usize;
        let batch_start_key = current_key;

        let mut proj_points = Vec::with_capacity(batch_size);
        for _ in 0..batch_size {
            proj_points.push(current_point);
            current_point += &ProjectivePoint::GENERATOR;
            current_key += 1;
        }

        let affine_points = ProjectivePoint::batch_normalize(proj_points.as_slice());

        for (i, affine) in affine_points.iter().enumerate() {
            let h = affine_to_hash160(affine);
            if h == target_hash160 {
                let found_key = batch_start_key + i as u128;
                let hex = format!("{:064x}", found_key);
                println!("[Thread {}] FOUND! Key: {}", thread_id, hex);
                let secp = Secp256k1::new();
                let secret_key = secret_key_from_u128(found_key).unwrap();
                let addr = secret_key_to_address(&secp, &secret_key);
                save_key(&hex, &addr);
                stats.found(hex);
                return;
            }
        }

        local_count += batch_size as u64;

        if last_update.elapsed().as_millis() >= 500 {
            let elapsed = last_update.elapsed().as_secs_f64();
            stats.set_kps((local_count as f64 / elapsed) as u64);
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
        if !stats.is_running() { break; }
        let _ = tx.send(format!(
            "{{\"type\":\"stats\",\"total\":{},\"kps\":{},\"elapsed\":{}}}",
            stats.total(), stats.kps(), stats.elapsed()
        ));
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

    let target_hash160 = hash160_from_address(TARGET_ADDRESS);
    println!("Target hash160: {}", hex::encode(target_hash160));

    let stats = Stats::new();
    let (tx, _) = broadcast::channel::<String>(100);

    let num_threads = available_parallelism().map(NonZeroUsize::get).unwrap_or(1);
    println!("=== BTC Puzzle Solver ===");
    println!("Range: {:018x}..{:018x}", RANGE_START, RANGE_END);
    println!("Target: {} ({})", TARGET_ADDRESS, hex::encode(target_hash160));
    println!("Threads: {}", num_threads);
    println!("Batch size: {}", BATCH_SIZE);
    println!("Run with --verify to verify address generation\n");

    let mut handles = Vec::new();
    for i in 0..num_threads {
        let s = stats.clone();
        let t = target_hash160;
        handles.push(std::thread::spawn(move || {
            solver_worker(s, t, i, num_threads);
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

    let addr: std::net::SocketAddr = ([0, 0, 0, 0], 3030).into();
    println!("Dashboard: http://{}", addr);
    warp::serve(ws_route).run(addr).await;
}
