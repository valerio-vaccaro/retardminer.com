import hashlib
import json
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
VECTORS = sorted((ROOT / "test_vectors").glob("*.json"))


@pytest.mark.parametrize("vector_path", VECTORS, ids=lambda p: p.stem)
def test_all_pow_vectors(vector_path, blake2b_tool):
    vector = json.loads(vector_path.read_text())
    header = bytes.fromhex(vector["header_hex"])

    assert vector["algorithm"] in ("BLAKE2b-256", "BLAKE2b-Sia-256")
    assert len(header) == 80
    nonce_size = len(vector["nonce_little_endian_hex"]) // 2
    assert header[vector["nonce_offset"] : vector["nonce_offset"] + nonce_size].hex() == vector["nonce_little_endian_hex"]
    if "stratum_notify" in vector:
        assert vector["stratum_notify"]["params"][1] == vector["header_hex"]

    # Independent standard-library result guards the test fixture itself.
    assert hashlib.blake2b(header, digest_size=32).hexdigest() == vector["hash_hex"]
    result = subprocess.run(
        [str(blake2b_tool), "hash", vector["header_hex"]],
        text=True, capture_output=True, check=True,
    )
    assert result.stdout.strip() == vector["hash_hex"]
    assert (bytes.fromhex(vector["hash_hex"]) <= bytes.fromhex(vector["target_hex"])) == vector["expected_share"]
