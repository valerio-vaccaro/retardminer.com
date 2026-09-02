<p align="center">
  <img src="assets/retardminer-logo.svg" alt="retardminer poop logo" width="128">
</p>

<h1 align="center">retardminer</h1>

<p align="center">
  <a href="https://retardminer.com/"><img src="https://img.shields.io/badge/site-retardminer.com-75411f?logo=googlechrome&logoColor=white" alt="Website"></a>
  <img src="https://img.shields.io/badge/board-ESP32-E7352C?logo=espressif&logoColor=white" alt="ESP32">
  <img src="https://img.shields.io/badge/build-PlatformIO-orange?logo=platformio&logoColor=white" alt="PlatformIO">
  <img src="https://img.shields.io/badge/proof%20of%20work-BLAKE2b-41e6a1" alt="BLAKE2b proof of work">
  <img src="https://img.shields.io/badge/protocol-Stratum%20V1-39a9ff" alt="Stratum V1">
  <img src="https://img.shields.io/badge/license-MIT-blue" alt="MIT license">
</p>

> 💩 **Editorial verdict:** Bitcoin BLAKE2b is a shitcoin — and the worst kind of one, because it borrows the Bitcoin name to push a fork with no real consensus behind it. Read the full explanation on [The Fork](https://retardminer.com/fork.html).

retardminer is an ESP32 proof-of-work miner and a deliberately opinionated companion to the [retard pool](https://retardminer.com/). It is useful for learning, experimenting, and measuring what a small microcontroller can do. It is not a serious path to Bitcoin mining revenue.

## 🧭 What it supports today

The firmware exposes exactly two selectable proof-of-work modes in its setup portal:

- 🟤 **BLAKE2b-Sia** — an 80-byte Sia header hashed once with BLAKE2b-256. It supports the reference F2Pool Siacoin Stratum V1 job format and the included small local demo adapter.
- 🟠 **Bitcoin BLAKE2b Stratum V1 (PyBLOCK)** — PyBLOCK's BIP-110/BLAKE2b Stratum V1 format. This is a separate fork-specific protocol, not Bitcoin's established proof of work and not the Bitcoin Knots PR #359 header format.

Both modes assemble their work from pool job data, scan a fixed nonce field, and submit shares using Stratum V1. “BLAKE2b” by itself is not a mining protocol: a pool must implement the matching job and share format.

### ⚠️ Why the editorial warning matters

Bitcoin BLAKE2b should be understood as an experimental fork, not as Bitcoin. Changing the proof-of-work algorithm changes the rules miners validate; a name, ticker, or compatible-looking Stratum endpoint cannot create network consensus. Before pointing hardware or money at it, verify the chain, software, node ecosystem, exchange support, and who actually recognizes its blocks.

The pool website makes the same distinction visible in its dashboard: it reports network health, templates, workers, shares, candidates, relay status, and explorer data, while [The Fork](https://retardminer.com/fork.html) explains the editorial case against treating this fork as Bitcoin. The [Docs](https://retardminer.com/docs.html) and [API reference](https://retardminer.com/api.html) cover the pool's live data and endpoints.

> 🔴 The public pool dashboard may be connected to **mainnet**. Block relay and RPC submission can move real funds; treat credentials, payout addresses, and block-broadcast actions accordingly.

## 🚀 Build and configure

Requirements: an ESP32 development board, PlatformIO, and a USB data cable.

```sh
pio run
pio run -t upload
pio device monitor
```

1. Flash the firmware and power the board.
2. On first boot, or after a Wi-Fi failure, connect to **retardminer-setup** and open `http://192.168.4.1` if the captive portal does not appear.
3. Enter the device name, Wi-Fi credentials, pool credentials, and proof-of-work mode. Selecting a mode fills its reference pool automatically; review or overwrite the host and port before saving.
4. Save to restart. Settings are kept in ESP32 non-volatile storage.
5. Hold the board's **BOOT** button while powering or resetting to force setup mode.

After Wi-Fi connects, the configuration and dashboard remain available at `http://<device-name>.local` (default: `http://retardminer.local`) or the IP printed over serial. The dashboard's live WebSocket uses port `81`; allow it through any LAN firewall between the browser and board.

### 📡 Reference pool settings

| Mode | Reference endpoint | Nonce field |
| --- | --- | --- |
| BLAKE2b-Sia | `sc.f2pool.com:7788` | 8 bytes at offset 32 |
| Bitcoin BLAKE2b Stratum V1 (PyBLOCK) | `pool.pyblock.xyz:4445` | 4 bytes at offset 32 |

The endpoint presets are conveniences, not endorsements or guarantees of availability. Pool usernames and payout credentials must follow the selected server's rules.

## 🧪 Local Sia demo pool

The included server is for development and LAN testing. It does not emulate PyBLOCK's real-Stratum format.

```sh
python3 tools/demo_pool.py --pow sia
```

In the portal, select **BLAKE2b-Sia**, replace the automatic host with the computer's LAN IP, keep port `3333`, and enter any username and password. The server creates a matching job, verifies submitted nonces independently, and appends results to `demo-pool-results.jsonl`. Use `--target-prefix 00` for an easier test target.

## 🔬 Tests and benchmark

The host-side tests validate the shared BLAKE2b implementation against independent `hashlib.blake2b` results and the checked-in vectors. Run:

```sh
pytest
pytest -m benchmark -s
```

The benchmark measures the host CPU only; it is not an ESP32 performance claim. For hardware results, use the live rate in the device dashboard or serial monitor.

## 📊 Device dashboard

The on-device dashboard exposes live hash rate, total hashes, uptime, templates and template age, Wi-Fi signal, pool session state, submitted/accepted/rejected shares, heap and PSRAM headroom, chip and flash details, temperature, recent pool messages, and a **Request new template** action.

For the network pool dashboard, use [retardminer.com](https://retardminer.com/) to:

- 💬 chat in the Trollbox;
- 👷 check a worker by payout address;
- 🧱 inspect found block candidates and relay status;
- 📈 review aggregate hashrate, active workers, difficulty, shares, and network activity.

## 📄 License

MIT — see [LICENSE](LICENSE).
