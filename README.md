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

Open `http://<your-ip>:3030` for the live dashboard (WebSocket).

## Options

- `--verify` — verify address generation against known test vectors

## Architecture

- **Random scan**: per-thread PRNG picks random positions in `[2^70, 2^71]` (inclusive)
- **Fast sequential chunks**: incremental point addition (`P += G`) within each chunk
- **Batch normalization**: every 4096 keys, batch-convert projective → affine (fits in L2 cache)
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

## Bug Fixes (v0.3)

### Critical

1. **Off-by-one range** — `RANGE_END` was never scanned; `max_start` adjusted to include final key
2. **Race condition in `found()`** — duplicate file writes and WebSocket events when two threads find simultaneously; `found()` now returns `bool`, only winner acts
3. **Broadcaster "found" overwrite** — redundant broadcaster message (missing address) raced with worker's complete message; removed broadcaster's duplicate

### Medium

4. **Sample emission burst** — new threads fired old milestone samples in rapid succession; `next_sample` now initialized from global count
5. **Batch size cache thrashing** — 65536 points (6.25 MB/thread) exceeded L2; reduced to 4096 (384 KB/thread)
6. **Last batch keys not counted** — `break 'outer'` skipped incrementing `local_count`; moved increment before batch processing

### Low

7. **`RANGE_SIZE` off by one** — inclusive range count corrected
8. **`hash160_from_address` panic** — replaced `.expect()` with `?` propagation + network validation
9. **`assume_checked()` without validation** — removed; `require_network()` already returns checked address
10. **Panic if `SCAN_CHUNK > RANGE_SIZE`** — added `assert!` guard with descriptive message
11. **Dead `None` branch** — `u128_to_scalar` made infallible (u128 values always valid scalars)
12. **`innerHTML` XSS** — dashboard thread cards now use `textContent` for data

## Performance

| Metric | Value |
|--------|-------|
| RAM usage | ~9 MB (stable, no leaks) |
| Batch size | 4096 points (L2-friendly) |
| Threads | N = CPU cores (pinned) |
| Scan chunk | 2^20 keys (~1M) per lottery ticket |
| Hash acceleration | SHA-NI / NEON via `sha2/asm` |
| Optimization | LTO + `codegen-units=1` + `target-cpu=native` |

## Memory Stability

All allocations are fixed-size or reused:
- `proj_buf`: pre-allocated, `clear()` each batch
- `broadcast::channel(1024)`: fixed ring buffer
- `thread_parts`: recreated every 500ms, dropped after each tick

After 1 month: same ~9 MB RSS, zero disk writes, no log growth.
