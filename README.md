# BTC Puzzle Solver

Brute-force solver for Bitcoin Puzzle #71 (private key in range `[2^70, 2^71)`).

**Target:** `1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU` (~6.6 BTC reward)

## Build & Run

```bash
cargo build --release
./target/release/btc-puzzle-solver
```

Open `http://127.0.0.1:3030` for the live dashboard (WebSocket).

## Options

- `--verify` — verify address generation against known test vectors

## Architecture

- Incremental point addition (`k256` ProjectivePoint += Generator)
- Batch normalization (`BatchNormalize`) per 8192-key batch
- Hash160 (SHA-256 + RIPEMD-160) on compressed public keys
- Deterministic range partitioning across `N` threads (shuffled assignment)
- Live WebSocket dashboard via `warp`

## Key Fixes Applied

1. **RANGE_END typo** — was `0x7fffffffffffffffff` (2^63-1), corrected to `(1 << 71) - 1` (2^71-1). Previous value was *below* RANGE_START, making the entire search range empty.
2. **u128-to-usize truncation** — `remaining` computed as `(thread_end - current_key) as usize` silently truncated slice sizes > 2^64 to 0, causing all threads except one to process zero keys per batch. Fixed by computing the `min()` in u128 space before casting.
3. **kps under-reporting** — each worker overwrote a shared `keys_per_second` atomic with its own rate; dashboard showed 1/N of actual throughput. Fixed with per-window accumulation and centralized kps computation.
4. **`--verify` assertions** — `verify_address_generation` used print-based pass/fail instead of `assert_eq!`, silently hiding mismatches.
5. **File permissions** — `found_key.txt` now created with mode `0600` on Unix.
6. **Panic on bad address** — `hash160_from_address` returns `Result` instead of panicking.
7. **Dead code removed** — unused `take_found_event` method.
