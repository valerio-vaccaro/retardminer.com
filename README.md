<p align="center">
  <img src="assets/retardminer-logo.svg" alt="retardminer poop logo" width="128">
</p>

# retardminer

**Main website:** [retardminer.com](https://retardminer.com/)

retardminer is an ESP32 PlatformIO proof-of-work miner. It supports two proof-of-work modes, selected in the setup portal, and both speak real Stratum V1 and build their work buffer from job pieces themselves, the way an ordinary ASIC does:

- **BLAKE2b-Sia:** the legacy 80-byte Sia header—32-byte parent ID, 64-bit little-endian nonce, 64-bit timestamp, and 32-byte Merkle root—hashed once with BLAKE2b-256. It scans the fixed 64-bit nonce at byte offset 32. If the pool's `mining.notify` has nine or more fields, the firmware treats it as a real Stratum V1-style job (previous ID, coinbase parts, Merkle branches, extranonce) and assembles the header and BLAKE2b Merkle root itself—the format F2Pool's Siacoin endpoint uses; otherwise it expects this firmware's small three-field job adapter.
- **Bitcoin BLAKE2b Stratum V1 (PyBLOCK):** a distinct real-Stratum-V1 job format used by [PyBLOCK](https://pool.pyblock.xyz/)'s BIP-110/BLAKE2b endpoint (`stratum+tcp://pool.pyblock.xyz:4445`, backed by a fork of OCEAN's [DATUM](https://github.com/OCEAN-xyz/datum_gateway) gateway)—not the Bitcoin Knots PR #359 header format, and not Sia's small-JSON adapter. The pool's `mining.notify` reuses the standard nine-field shape but with different contents: `prevhash` is 32 bytes and `ntime` is 8 bytes, both used exactly as sent (no byte-reversal); `coinb1` is a 39-byte value the pool already hashed on its side (3 zero bytes + a 32-byte commitment + 4 zero bytes), not a real Bitcoin coinbase fragment; `coinb2` and the merkle branch list are always empty. The firmware combines that commitment with its own randomly-chosen 8-byte extranonce2 (`0x00 ‖ coinb1 ‖ extranonce1 ‖ extranonce2`, BLAKE2b-256) into a work root, builds an 80-byte buffer (`prevhash ‖ nonce ‖ ntime ‖ root`), hashes it once with BLAKE2b-256, and reverses the digest before comparing it to target—scanning a 32-bit nonce at byte offset 32. Shares are submitted Stratum-V1-style (`username, job_id, extranonce2, ntime, nonce`, no digest).

The setup portal fills in **Pool host** and **Port** automatically when you change the **Proof of work** selector—`sc.f2pool.com:7788` for BLAKE2b-Sia, `pool.pyblock.xyz:4445` for PyBLOCK—so picking a mode is normally enough to point the miner at its reference pool; edit the fields afterwards if you're using a different endpoint.

## Pool interoperability

"BLAKE2b" alone is not a mining protocol. Sia's small-JSON path is this firmware's own format: a public pool works only if it sends this firmware's exact job/submission messages (see below).

Sia's real-Stratum path and PyBLOCK's BLAKE2b Stratum V1 mode implement real Stratum V1 job distribution for their respective proof-of-work, so they work directly against any pool that follows the same conventions—F2Pool is the reference implementation the Sia path was built against, and PyBLOCK's own pool (backed by its DATUM-gateway fork) is the reference for the BLAKE2b mode. The BLAKE2b job/submission shape (39-byte pre-hashed `coinb1`, no-reversal 8-byte `ntime`, single-round BLAKE2b-256 work root and digest, no XOR key on the wire) was reverse-engineered from that gateway fork's open-source `datum_pow.c`/`datum_stratum.c` and cross-checked against a live capture from `pool.pyblock.xyz:4445`—including submitting a structurally-correct test share, which the pool accepted for parsing and rejected only as `high-hash` (i.e. insufficient difficulty, not a malformed submission). A pool with a non-standard job-distribution protocol still needs its own adapter.

## Build and configure

1. Build: `pio run`
2. Flash: `pio run -t upload`
3. On first boot (or if Wi-Fi cannot be joined within 20 seconds), connect a phone or computer to **retardminer-setup**. Its captive portal opens automatically; otherwise browse to `http://192.168.4.1`.
4. Enter a device name, Wi-Fi, pool, payout credentials, and proof-of-work mode—**Pool host** and **Port** fill in automatically for the selected mode, so review or edit them before saving. Save to restart. Settings are stored in the ESP32's non-volatile storage, so reflashing is not required for normal configuration changes.
5. To force setup mode, hold the board's **BOOT** button while powering or resetting it.
6. Monitor: `pio device monitor`

On the standard ESP32 DevKit, the built-in LED (GPIO 2) also reports status: a slow blink means the setup portal is active, a fast blink means it is retrying the pool, and a short pulse once per second means it is connected and running.

After the ESP32 joins Wi-Fi, its configuration page remains available on the LAN. Open `http://<device-name>.local` (default: `http://retardminer.local`) or use the IP address printed on serial output. The page displays its connected IP and lets you edit all stored device, Wi-Fi, pool, and proof-of-work settings; saving restarts the board with the new values.

The page has three tabs: **Dashboard**, **Pool activity**, and **Configuration**. The live WebSocket dashboard refreshes every five seconds and shows mining state, a fixed 0-30,000 H/s hash-rate gauge/chart, uptime, templates and template age, Wi-Fi signal/channel, pool session data, submitted/accepted/rejected shares, heap and PSRAM headroom, chip details, flash/sketch usage, and ESP32 temperature. **Pool activity** adds the configured endpoint, proof-of-work mode, current template details, the 24 most recent miner/pool messages with the newest first (connection attempts, subscriptions, templates, share submissions, and pool decisions), and a Stratum information panel with pool difficulty, extranonce1/extranonce2 size, block version, nBits, nTime, and the last server message/method. The dashboard uses port `81` on the board, so allow that port on any LAN firewall between your browser and the ESP32. Its **Request new template** button sends `mining.request_template` to the configured pool.

## Configuration recipes

In the setup portal, select the **Proof of work** mode first—it auto-fills **Pool host** and **Port** with that mode's reference pool—then set **Username / payout address** to the value expected by that server. Override the host/port if you're pointing at a different pool or the local demo server.

| Goal | Device portal: Proof of work | Host / port |
| --- | --- | --- |
| Legacy Sia BLAKE2b demo | `BLAKE2b-Sia` | Demo server LAN IP, port `3333` (see below)—overwrite the auto-filled F2Pool address |
| Real Siacoin Stratum V1 pool (F2Pool) | `BLAKE2b-Sia` | Auto-filled: `sc.f2pool.com:7788` |
| PyBLOCK BIP-110/BLAKE2b pool | `Bitcoin BLAKE2b Stratum V1 (PyBLOCK)` | Auto-filled: `pool.pyblock.xyz:4445` |

Both modes use a fixed nonce layout defined by their protocol (BLAKE2b-Sia: offset 32, size 8; PyBLOCK: offset 32, size 4)—there is no user-editable header/nonce setting.

Sia's small-JSON path deliberately ignores any header layout—its 80-byte format defines it. Sia's real-Stratum path and PyBLOCK's BLAKE2b Stratum V1 mode instead build their work buffer themselves from a nine-field `mining.notify`, so they work directly with pools that speak that job format for their respective proof-of-work.

The small-JSON adapter sends `mining.subscribe` and `mining.authorize`, then accepts either:

```json
{"method":"mining.notify","params":["job-id","header-hex","target-32-byte-hex"]}
```

or:

```json
{"method":"mining.notify","params":{"id":"job-id","header":"...","target":"..."}}
```

`header-hex` must be the complete 80-byte serialized Sia header. Shares on that path are submitted as `mining.submit` with username, job id, decimal nonce, and the calculated digest. This simple format deliberately avoids pretending Bitcoin's coinbase/Merkle Stratum-v1 job format is valid for a different proof-of-work algorithm.

Sia's real-Stratum path and PyBLOCK's BLAKE2b Stratum V1 mode instead send the same `mining.subscribe`/`mining.authorize` pair and consume ordinary Stratum V1 `mining.notify`, `mining.set_difficulty`, and `mining.set_extranonce` messages. Shares are submitted as `mining.submit` with username, job id, extranonce2, nTime, and the nonce as hex (16 hex chars for Sia's 8-byte nonce, 8 for PyBLOCK's 4-byte nonce)—no digest, matching ordinary Stratum V1.

## Local demo pool

Run a development-only pool on a computer reachable from the ESP32:

```sh
python3 tools/demo_pool.py --pow sia
```

In the device portal, choose `BLAKE2b-Sia`, set **Pool host** to that computer's LAN IP (overwriting the auto-filled F2Pool address), port to `3333`, and choose any username and password. The server supplies a matching job and independently verifies each submitted nonce and digest. It appends each result to `demo-pool-results.jsonl`. The default target accepts approximately one in 65,536 hashes; use `--target-prefix 00` for easier testing.

`tools/demo_pool.py` also implements `--pow plain` and `--pow knots-v2`, small-JSON job formats for the plain-BLAKE2b and Bitcoin Knots PR #359 v2 header algorithms respectively—useful for exercising those algorithms in isolation (see `tests/test_knots_pow.py` and `src/knots_pow.cpp`)—but neither corresponds to a selectable firmware mode any more; the setup portal only offers BLAKE2b-Sia and PyBLOCK. PyBLOCK's real-Stratum job format is not supported by the demo server; test that mode against the real pool.

The host tests check two official PR #359 header-v2 vectors, covering ASIC profile 0 and profile 1 with a non-zero XOR key, plus the deterministic plain-BLAKE2b fixture at [test_vectors/bitcoin_blake2b_header.json](test_vectors/bitcoin_blake2b_header.json)—the canonical Bitcoin genesis 80-byte header with its normal field layout and 4-byte nonce, differing from Bitcoin only in using BLAKE2b-256 in place of SHA-256d. Run them with `pytest` (or `venv/bin/python -m pytest` when pytest is installed); the BLAKE2b implementation follows RFC 7693 and uses a 32-byte digest.

## Host-side verification and benchmark

The pytest suite compiles the BLAKE2b implementation the firmware also uses for its two modes, plus the standalone Knots v2 header algorithm no firmware mode currently selects, checks every `test_vectors/*.json` fixture against Python's independent `hashlib.blake2b`, then checks the compiled implementation against the same expected digest.

```sh
venv/bin/python -m pytest
venv/bin/python -m pytest -m benchmark -s
```

The benchmark reports host-native BLAKE2b-256 hashes/second for 100,000 Bitcoin-format headers. It is deliberately opt-in and has no minimum-rate assertion: host CPU speed does not represent an ESP32's hash rate. Measure the flashed device with its serial rate report for the hardware result.
