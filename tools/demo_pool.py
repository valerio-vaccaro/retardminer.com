#!/usr/bin/env python3
"""Small multi-mode Stratum-like demo pool for retardminer development.

It implements only the JSON messages used by this firmware: mining.subscribe,
mining.authorize, mining.request_template, mining.notify, and mining.submit.  It is deliberately not a
Bitcoin or public-pool server.
"""

import argparse
import asyncio
import hashlib
import json
import secrets
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path


# A valid, 80-byte Bitcoin-format header.  The server replaces its nonce before
# independently verifying each submitted BLAKE2b-256 digest.
DEFAULT_HEADER = (
    "01000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a"
    "29ab5f49ffff001d1dac2b7c"
)
SIA_HEADER = (
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    "080706050403020100f1536500000000"
    "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
)
KNOTS_V2_HEADER = (
    "000000a01f1e1d1c1b1a191817161514131211100f0e0d0c0b0a090807060504"
    "0302010000112233445566778899aabbccddeeff00102030405060708090a0b0c0d0e0f0a8913577ffff001d0df0ad0b44332211efcdab89ffeeddccbbaa998877665544332211005802000003005c000000000000000000000000000000000040d10c008967452301efcdab8967452301efcdab8967452301efcdab8967452301efcdab"
)


def tagged_hash(tag: str, data: bytes) -> bytes:
    tag_hash = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(tag_hash + tag_hash + data).digest()


def knots_v2_hash(header: bytes) -> bytes:
    """Bitcoin Knots PR #359 v2 PoW, mirrored from src/knots_pow.cpp."""
    if len(header) != 164 or not header[3] & 0x80:
        raise ValueError("expected a marked 164-byte Knots v2 header")
    version = (int.from_bytes(header[:4], "little") & 0x7fffffff).to_bytes(4, "little")
    ordered_prev = header[4:36][::-1]
    xor_key = header[112:128]
    h1 = tagged_hash("Bitcoin block header 1", version + ordered_prev + header[128:132] + header[36:68] + header[68:72] + b"\0" + header[72:76] + header[108:110] + b"\0\0" + header[110:112] + tagged_hash("Bitcoin block hash PoW XOR key", xor_key))
    h2 = tagged_hash("Merge-mining hook", h1 + bytes(32) + header[132:164])
    first = hashlib.blake2b(bytes(4) + h2 + header[88:104], digest_size=32).digest()
    tail = header[76:80] + header[80:84] + header[104:108] + header[84:88] + first
    profile = header[110] & 3
    if profile == 0:
        hidden_prev = bytearray(tagged_hash("Bitcoin prevblock header, hashed", ordered_prev))
        hidden_prev[:6] = bytes(6)
        second_input = bytes(hidden_prev) + tail
    elif profile == 1:
        second_input = header[76:80] + header[80:84] + header[84:88] + header[104:108] + first + h2
    else:
        second_input = bytes(48 if profile == 2 else 80) + h2 + tail
    result = hashlib.blake2b(second_input, digest_size=32).digest()
    if any(xor_key):
        mask = bytearray(tagged_hash("Bitcoin block hash PoW XOR mask", xor_key))
        clear = header[111]
        mask[: clear // 8] = bytes(clear // 8)
        mask[clear // 8] &= 0xff >> (clear % 8)
        result = bytes(a ^ b for a, b in zip(result, mask))
    return result


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


class DemoPool:
    def __init__(self, mode: str, header: bytes, target: bytes, nonce_offset: int, nonce_size: int, results: Path):
        self.mode = mode
        self.header = header
        self.target = target
        # A uniformly random 256-bit hash is accepted with probability
        # (target + 1) / 2^256.  This expected work is independent of nonce
        # order, which is essential when a miner scans on multiple cores.
        self.expected_hashes_per_share = (1 << 256) / (int.from_bytes(target, "big") + 1)
        self.nonce_offset = nonce_offset
        self.nonce_size = nonce_size
        self.results = results
        self.job_id = f"demo-{secrets.token_hex(6)}"
        self.accepted = 0
        self.rejected = 0
        self.workers: dict[str, dict] = {}

    def log(self, event: dict) -> None:
        event["time"] = now()
        with self.results.open("a", encoding="utf-8") as output:
            output.write(json.dumps(event, separators=(",", ":")) + "\n")

    def verify_share(self, nonce_text: object, digest_text: object) -> tuple[bool, str]:
        try:
            nonce = int(str(nonce_text), 10)
            claimed = bytes.fromhex(str(digest_text))
        except ValueError:
            return False, "invalid nonce or hash encoding"
        if nonce < 0 or nonce >= 1 << (8 * self.nonce_size):
            return False, "nonce is outside configured size"
        if len(claimed) != 32:
            return False, "digest must be 32 bytes"

        candidate = bytearray(self.header)
        candidate[self.nonce_offset : self.nonce_offset + self.nonce_size] = nonce.to_bytes(self.nonce_size, "little")
        calculated = knots_v2_hash(candidate) if self.mode == "knots-v2" else hashlib.blake2b(candidate, digest_size=32).digest()
        if claimed != calculated:
            return False, "digest does not match nonce"
        if calculated > self.target:
            return False, "share does not meet target"
        return True, "accepted"

    def record_hashrate(self, address: str, nonce_text: object, job_id: object) -> float | None:
        """Estimate H/s from accepted-share timing and the pool target.

        Nonce distance is invalid for parallel miners because each core has an
        independent nonce stream.  Accepted shares are Bernoulli samples, so
        the elapsed time between them multiplied by expected work per share is
        the correct estimator. A rate needs two accepted shares.
        """
        del nonce_text, job_id
        timestamp = time.monotonic()
        worker = self.workers.setdefault(address, {
            "accepted": 0,
            "rate": None,
            "last_time": None,
            "rate_samples": deque(),
            "total_rate_work": 0.0,
            "total_rate_seconds": 0.0,
        })
        rate = None
        if worker["last_time"] is not None:
            elapsed = timestamp - worker["last_time"]
            if elapsed > 0:
                rate = self.expected_hashes_per_share / elapsed
                worker["rate"] = rate
                worker["rate_samples"].append((timestamp, rate, elapsed))
                worker["total_rate_work"] += rate * elapsed
                worker["total_rate_seconds"] += elapsed
        cutoff = timestamp - 7 * 24 * 60 * 60
        while worker["rate_samples"] and worker["rate_samples"][0][0] < cutoff:
            worker["rate_samples"].popleft()
        worker["last_time"] = timestamp
        worker["accepted"] += 1
        return rate

    @staticmethod
    def format_rate(rate: float | None) -> str:
        return "-" if rate is None else f"{rate:,.1f} H/s"

    @staticmethod
    def colour(code: str, text: str) -> str:
        return f"\033[{code}m{text}\033[0m"

    def rolling_rate(self, worker: dict, seconds: float | None) -> float | None:
        if seconds is None:
            duration = worker["total_rate_seconds"]
            return worker["total_rate_work"] / duration if duration else None
        cutoff = time.monotonic() - seconds
        samples = [sample for sample in worker["rate_samples"] if sample[0] >= cutoff]
        duration = sum(sample[2] for sample in samples)
        return sum(sample[1] * sample[2] for sample in samples) / duration if duration else None

    def rate_columns(self, worker: dict) -> dict[str, float | None]:
        return {
            "event": worker["rate"],
            "1m": self.rolling_rate(worker, 60),
            "1h": self.rolling_rate(worker, 60 * 60),
            "1d": self.rolling_rate(worker, 24 * 60 * 60),
            "1w": self.rolling_rate(worker, 7 * 24 * 60 * 60),
            "total": self.rolling_rate(worker, None),
        }

    def active_total_hashrate(self) -> float:
        """Return the most recent event-rate total for the JSON share log."""
        timestamp = time.monotonic()
        return sum(
            worker["rate"] or 0.0
            for worker in self.workers.values()
            if worker["last_time"] and timestamp - worker["last_time"] < 30
        )

    def print_hashrates(self) -> None:
        headers = ("event", "1m", "1h", "1d", "1w", "total")
        print(self.colour("36", "HASH RATE (H/s)  ") + "  ".join(f"{name:>12}" for name in headers))
        if not self.workers:
            print("  waiting for a worker")
            return
        for address, worker in sorted(self.workers.items()):
            columns = self.rate_columns(worker)
            values = "  ".join(f"{self.format_rate(columns[name]):>12}" for name in headers)
            accepted = self.colour("32", f"accepted={worker['accepted']}")
            print(f"  {address:<15} {values}  {accepted}")
        accepted = self.colour("32", str(self.accepted))
        rejected = self.colour("31", str(self.rejected))
        print(f"{self.colour('33', 'SHARES')} accepted={accepted} rejected={rejected}")

    async def client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        peer_address = peer[0] if peer else "unknown"
        peer_name = f"{peer_address}:{peer[1]}" if peer else "unknown"
        authorized = False
        print(f"client connected: {peer_name}")
        try:
            while line := await reader.readline():
                try:
                    request = json.loads(line)
                    method = request["method"]
                    request_id = request.get("id")
                except (json.JSONDecodeError, KeyError, TypeError):
                    self.log({"event": "invalid_request", "client": peer_name, "line": line.decode(errors="replace").rstrip()})
                    continue

                if method == "mining.subscribe":
                    await self.reply(writer, request_id, [])
                elif method == "mining.authorize":
                    authorized = True
                    await self.reply(writer, request_id, True)
                    await self.notify(writer)
                elif method == "mining.request_template":
                    if not authorized:
                        await self.reply(writer, request_id, False, "not authorized")
                    else:
                        self.job_id = f"demo-{secrets.token_hex(6)}"
                        await self.reply(writer, request_id, True)
                        await self.notify(writer)
                elif method == "mining.submit":
                    params = request.get("params", [])
                    if len(params) != 4:
                        accepted, reason = False, "expected username, job id, nonce, digest"
                    elif not authorized:
                        accepted, reason = False, "not authorized"
                    elif params[1] != self.job_id:
                        accepted, reason = False, "unknown job"
                    else:
                        accepted, reason = self.verify_share(params[2], params[3])
                    self.accepted += accepted
                    self.rejected += not accepted
                    rate = self.record_hashrate(peer_address, params[2], params[1]) if accepted else None
                    self.log({"event": "share", "client": peer_name, "address": peer_address, "username": params[0] if params else "", "job_id": params[1] if len(params) > 1 else "", "nonce": params[2] if len(params) > 2 else "", "digest": params[3] if len(params) > 3 else "", "accepted": accepted, "reason": reason, "estimated_hashrate_hps": rate, "total_estimated_hashrate_hps": self.active_total_hashrate()})
                    outcome = self.colour("32", "ACCEPTED") if accepted else self.colour("31", "REJECTED")
                    rate_text = self.colour("36", self.format_rate(rate)) if rate is not None else "-"
                    print(f"share from {peer_name}: {outcome} ({reason}; rate={rate_text})")
                    await self.reply(writer, request_id, accepted, None if accepted else reason)
                else:
                    await self.reply(writer, request_id, None, f"unsupported method: {method}")
        finally:
            writer.close()
            await writer.wait_closed()
            print(f"client disconnected: {peer_name}")

    async def reply(self, writer: asyncio.StreamWriter, request_id: object, result: object, error: object = None) -> None:
        writer.write((json.dumps({"id": request_id, "result": result, "error": error}) + "\n").encode())
        await writer.drain()

    async def notify(self, writer: asyncio.StreamWriter) -> None:
        message = {"method": "mining.notify", "params": [self.job_id, self.header.hex(), self.target.hex()]}
        writer.write((json.dumps(message) + "\n").encode())
        await writer.drain()


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="retardminer local demo pool")
    parser.add_argument("--host", default="0.0.0.0", help="listen address (default: all interfaces)")
    parser.add_argument("--port", type=int, default=3333, help="listen port (default: 3333)")
    parser.add_argument("--results", type=Path, default=Path("demo-pool-results.jsonl"), help="JSONL results file")
    parser.add_argument("--pow", choices=("plain", "knots-v2", "sia"), default="plain", help="proof-of-work mode (default: plain)")
    parser.add_argument("--header", help="complete mode-specific header as hex")
    parser.add_argument("--target-prefix", default="0000", help="leading target hex; remaining bytes are ff (default: 0000)")
    parser.add_argument("--nonce-offset", type=int, default=76)
    parser.add_argument("--nonce-size", type=int, choices=(4, 8), default=4)
    return parser.parse_args()


async def main() -> None:
    args = arguments()
    try:
        default_header = KNOTS_V2_HEADER if args.pow == "knots-v2" else SIA_HEADER if args.pow == "sia" else DEFAULT_HEADER
        header = bytes.fromhex(args.header or default_header)
        target_prefix = bytes.fromhex(args.target_prefix)
    except ValueError as error:
        raise SystemExit(f"invalid hexadecimal argument: {error}")
    if args.pow == "knots-v2" and (len(header) != 164 or not header[3] & 0x80):
        raise SystemExit("--pow knots-v2 requires a marked 164-byte header")
    if args.pow == "sia" and len(header) != 80:
        raise SystemExit("--pow sia requires an 80-byte Sia header")
    if args.pow == "plain" and len(header) > 256:
        raise SystemExit("--pow plain accepts headers up to 256 bytes")
    if len(target_prefix) > 32:
        raise SystemExit("--target-prefix must be at most 32 bytes")
    if args.pow == "knots-v2":
        args.nonce_offset, args.nonce_size = 76, 4
    elif args.pow == "sia":
        args.nonce_offset, args.nonce_size = 32, 8
    if args.nonce_offset < 0 or args.nonce_offset + args.nonce_size > len(header):
        raise SystemExit("nonce range must fit inside the header")

    pool = DemoPool(args.pow, header, target_prefix + b"\xff" * (32 - len(target_prefix)), args.nonce_offset, args.nonce_size, args.results)
    print(f"demo pool ({args.pow}) listening on {args.host}:{args.port}; job={pool.job_id}; target={pool.target.hex()}")
    print(f"results: {args.results.resolve()}")
    server = await asyncio.start_server(pool.client, args.host, args.port)
    async def report_hashrates() -> None:
        while True:
            await asyncio.sleep(10)
            pool.print_hashrates()
    asyncio.create_task(report_hashrates())
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\ndemo pool stopped")
