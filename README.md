<p align="center">
  <img src="assets/retardminer-logo.svg" alt="retardminer poop logo" width="128">
</p>

# retardminer

**Main website:** [retardminer.com](https://retardminer.com/)

retardminer is an ESP32 PlatformIO proof-of-work miner. It supports four proof-of-work modes, selected in the setup portal. Three of them expect a pool to issue a complete header over a small Stratum-v1-compatible JSON interface; the fourth, and part of the Sia mode, instead speak real Stratum V1 and build the header from job pieces themselves, the way an ordinary ASIC does:

- **Plain BLAKE2b-256:** one unkeyed BLAKE2b-256 hash of the whole supplied header. This preserves compatibility with the original local demo pool and any pool that uses this exact job and submission format.
- **Bitcoin Knots PR #359 header v2:** a 164-byte header marked by version bit 31. The firmware performs the PR's tagged-SHA256 preprocessing, two BLAKE2b-256 rounds, ASIC-profile input selection, and XOR mask. It scans the 32-bit little-endian `nNonce` at byte offset 76.
- **BLAKE2b-Sia:** the legacy 80-byte Sia header—32-byte parent ID, 64-bit little-endian nonce, 64-bit timestamp, and 32-byte Merkle root—hashed once with BLAKE2b-256. It scans the fixed 64-bit nonce at byte offset 32. If the pool's `mining.notify` has nine or more fields, the firmware instead treats it as a real Stratum V1-style job (previous ID, coinbase parts, Merkle branches, extranonce) and assembles the header and BLAKE2b Merkle root itself—the format F2Pool's Siacoin endpoint uses; otherwise it expects this firmware's small three-field job adapter.
- **Bitcoin SHA-256d Stratum V1 (F2Pool):** implements ordinary Bitcoin Stratum V1—subscribe/authorize, an extranonce1/extranonce2 coinbase, SHA-256d Merkle-branch reduction, and the standard nine-field `mining.notify`—hashing the assembled 80-byte header with double SHA-256 (not BLAKE2b) and scanning the 32-bit nonce at byte offset 76.

A marked Knots header with any length other than 164 bytes is rejected.

## Pool interoperability

"BLAKE2b" alone is not a mining protocol. Plain BLAKE2b-256, Knots v2, and Sia's small-JSON path are this firmware's own formats: a public pool works only if it sends this firmware's exact job/submission messages (see below), or in the Knots case if the pool adapter sends the complete 164-byte v2 header and accepts this miner's `mining.submit` nonce/digest submission. The Knots PR does not itself publish a pool wire protocol.

Bitcoin SHA-256d Stratum V1 mode and Sia's real-Stratum path implement ordinary Stratum V1 for their respective proof-of-work, so they work directly against any pool that follows that standard—F2Pool is the reference implementation this firmware was built against. A pool with a non-standard job-distribution protocol still needs its own adapter.

## Build and configure

1. Build: `pio run`
2. Flash: `pio run -t upload`
3. On first boot (or if Wi-Fi cannot be joined within 20 seconds), connect a phone or computer to **retardminer-setup**. Its captive portal opens automatically; otherwise browse to `http://192.168.4.1`.
4. Enter a device name, Wi-Fi, pool, payout credentials, proof-of-work mode, and (for plain mode) header nonce layout. Save to restart. Settings are stored in the ESP32's non-volatile storage, so reflashing is not required for normal configuration changes.
5. To force setup mode, hold the board's **BOOT** button while powering or resetting it.
6. Monitor: `pio device monitor`

On the standard ESP32 DevKit, the built-in LED (GPIO 2) also reports status: a slow blink means the setup portal is active, a fast blink means it is retrying the pool, and a short pulse once per second means it is connected and running.

After the ESP32 joins Wi-Fi, its configuration page remains available on the LAN. Open `http://<device-name>.local` (default: `http://retardminer.local`) or use the IP address printed on serial output. The page displays its connected IP and lets you edit all stored device, Wi-Fi, pool, proof-of-work, and plain-header nonce settings; saving restarts the board with the new values.

The page has three tabs: **Dashboard**, **Pool activity**, and **Configuration**. The live WebSocket dashboard refreshes every five seconds and shows mining state, a fixed 0-30,000 H/s hash-rate gauge/chart, uptime, templates and template age, Wi-Fi signal/channel, pool session data, submitted/accepted/rejected shares, heap and PSRAM headroom, chip details, flash/sketch usage, and ESP32 temperature. **Pool activity** adds the configured endpoint, proof-of-work mode, current template details, the 24 most recent miner/pool messages with the newest first (connection attempts, subscriptions, templates, share submissions, and pool decisions), and—for the Stratum V1 modes—a Stratum information panel with pool difficulty, extranonce1/extranonce2 size, block version, nBits, nTime, and the last server message/method. The dashboard uses port `81` on the board, so allow that port on any LAN firewall between your browser and the ESP32. Its **Request new template** button sends `mining.request_template` to the configured pool.

## Configuration recipes

In the setup portal, set **Pool host** to the pool or demo server's LAN IP, **Port** to its Stratum-like port, and **Username / payout address** to the value expected by that server. Select the same **Proof of work** mode as the server.

| Goal | Device portal: Proof of work | Demo server command | Nonce settings |
| --- | --- | --- | --- |
| Original plain BLAKE2b demo | `Plain BLAKE2b-256` | `python3 tools/demo_pool.py --pow plain` | Default: offset `76`, size `4` |
| Bitcoin Knots PR #359 demo | `Bitcoin Knots PR #359 v2` | `python3 tools/demo_pool.py --pow knots-v2` | Fixed by protocol: offset `76`, size `4` |
| Legacy Sia BLAKE2b demo | `BLAKE2b-Sia` | `python3 tools/demo_pool.py --pow sia` | Fixed by protocol: offset `32`, size `8` |
| Real Bitcoin SHA-256d Stratum V1 pool (e.g. F2Pool) | `Bitcoin SHA-256d Stratum V1 (F2Pool)` | not supported by the demo server—point at a real pool | Fixed by protocol: offset `76`, size `4` |
| Real Siacoin Stratum V1 pool (e.g. F2Pool) | `BLAKE2b-Sia` | not supported by the demo server—point at a real pool | Fixed by protocol: offset `32`, size `8` |

For every local-demo mode, use port `3333` unless you pass `--port` to the server. Start the server on a computer connected to the same network as the ESP32, then enter that computer's LAN address—not `localhost` or `127.0.0.1`—as **Pool host**. The default share target accepts roughly one share per 65,536 hashes; for a quick test, add `--target-prefix 00` to the server command. `tools/demo_pool.py` only implements the small-JSON adapter (`--pow plain`, `knots-v2`, or `sia`); it does not speak real Stratum V1, so the two real-pool rows above must be tested against an actual pool.

The Knots mode and Sia's small-JSON path deliberately ignore the editable nonce fields: their header layouts define those fields. A pool on that path works only if it sends this firmware's complete-header `mining.notify` message and accepts its four-field `mining.submit` message. Bitcoin SHA-256d Stratum V1 mode and Sia's real-Stratum path instead build the coinbase and Merkle root themselves from a standard nine-field `mining.notify`, so they work directly with pools that speak ordinary Stratum V1 for that proof-of-work.

The small-JSON adapter sends `mining.subscribe` and `mining.authorize`, then accepts either:

```json
{"method":"mining.notify","params":["job-id","header-hex","target-32-byte-hex"]}
```

or:

```json
{"method":"mining.notify","params":{"id":"job-id","header":"...","target":"..."}}
```

Shares on that path are submitted as `mining.submit` with username, job id, decimal nonce, and the calculated digest. For Knots v2, `header-hex` must be the complete 164-byte serialized header; the miner replaces only bytes 76–79. This simple format deliberately avoids pretending Bitcoin's coinbase/Merkle Stratum-v1 job format is valid for a different proof-of-work algorithm.

Bitcoin SHA-256d Stratum V1 mode and Sia's real-Stratum path instead send the same `mining.subscribe`/`mining.authorize` pair and consume ordinary Stratum V1 `mining.notify`, `mining.set_difficulty`, and `mining.set_extranonce` messages. Shares are submitted as `mining.submit` with username, job id, extranonce2, nTime, and the nonce as hex (8 hex chars for Bitcoin's 4-byte nonce, 16 for Sia's 8-byte nonce)—no digest, matching ordinary Stratum V1.

## Local demo pool

Run a development-only pool on a computer reachable from the ESP32:

```sh
python3 tools/demo_pool.py
python3 tools/demo_pool.py --pow sia
python3 tools/demo_pool.py --pow knots-v2
```

In the device portal, choose the same **Proof of work** mode as `--pow`, set **Pool host** to that computer's LAN IP, port to `3333`, and choose any username and password. The server supplies a matching job and independently verifies each submitted nonce and digest; its Knots mode uses the full v2 calculation, not plain BLAKE2b. It appends each result to `demo-pool-results.jsonl`. The default target accepts approximately one in 65,536 hashes; use `--target-prefix 00` for easier testing.

The deterministic plain-BLAKE2b fixture is [test_vectors/bitcoin_blake2b_header.json](test_vectors/bitcoin_blake2b_header.json). It uses the canonical Bitcoin genesis 80-byte header with its normal field layout and 4-byte nonce; its only difference from Bitcoin is BLAKE2b-256 in place of SHA-256d. The host tests additionally check two official PR #359 header-v2 vectors, covering ASIC profile 0 and profile 1 with a non-zero XOR key. Run them with `pytest` (or `venv/bin/python -m pytest` when pytest is installed); the BLAKE2b implementation follows RFC 7693 and uses a 32-byte digest.

## Host-side verification and benchmark

The pytest suite compiles the same C++ implementation used by the firmware, checks every `test_vectors/*.json` fixture against Python's independent `hashlib.blake2b`, then checks the compiled implementation against the same expected digest.

```sh
venv/bin/python -m pytest
venv/bin/python -m pytest -m benchmark -s
```

The benchmark reports host-native BLAKE2b-256 hashes/second for 100,000 Bitcoin-format headers. It is deliberately opt-in and has no minimum-rate assertion: host CPU speed does not represent an ESP32's hash rate. Measure the flashed device with its serial rate report for the hardware result.
