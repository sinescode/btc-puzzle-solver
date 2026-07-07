# BTC Puzzle Solver

Random lottery-scan brute-force solver for Bitcoin Puzzle #71 (private key in range `[2^70, 2^71)`).

**Target:** `1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU` (~6.6 BTC reward)

## Strategy

**Random lottery scan** — each thread independently picks random starting positions
across the entire 2^70 keyspace, scans a small chunk (2^20 keys ≈ 1M) sequentially
via fast incremental point addition, then jumps to a new random spot.

This is the mathematical equivalent of buying lottery tickets spread across the
entire range rather than checking keys in order. Same per-key speed as sequential,
but random coverage means you might get lucky early.

## Build & Run

```bash
cargo build --release
./target/release/btc-puzzle-solver
```

Open `http://127.0.0.1:3030` for the live dashboard (WebSocket).

## Options

- `--verify` — verify address generation against known test vectors

## Architecture

- **Random scan**: per-thread PRNG picks random positions in [2^70, 2^71)
- **Fast sequential chunks**: incremental point addition (`P += G`) within each chunk
- **Batch normalization**: every 65536 keys, batch-convert projective → affine
- **Hash160**: SHA-256 + RIPEMD-160 on compressed public keys, with first-byte early exit
- **Thread pinning**: each worker pinned to a dedicated CPU core (`core_affinity`)
- **SHA-256 asm**: hardware-accelerated SHA-256 via `sha2/asm` feature (SHA-NI / NEON)
- **Live dashboard**: warp WebSocket relay with per-thread stats, sample keys, theme toggle

## Dashboard Features

- Real-time keys checked, KPS, elapsed time
- Estimated keyspace coverage percentage
- Lottery ticket counter (random chunks attempted)
- Per-thread KPS cards
- Sample keys with one-click copy
- Dark/light theme toggle (persisted)
- Desktop notification on key found
- Auto-reconnect on disconnect

## Key Fixes (v0.2)

1. **Random scan** — replaced sequential range partition with per-thread random lottery
2. **Graceful shutdown** — process exits cleanly when key is found (no more infinite hang)
3. **KPS computation** — race-free: broadcaster computes KPS from total deltas, no atomic resets
4. **Sample key accuracy** — reports actual batch-start keys, not estimated midpoints
5. **Thread pinning** — eliminates cache migration between cores
6. **Larger batches** — 65536 keys/batch (was 8192), better L3 cache amortization
7. **SIMD SHA-256** — `sha2/asm` feature for hardware-accelerated hashing
8. **File permissions** — `found_key.txt` created with mode `0600` on Unix
9. **Error handling** — `hash160_from_address` returns `Result` instead of panicking
