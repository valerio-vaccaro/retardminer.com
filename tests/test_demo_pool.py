import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import demo_pool  # noqa: E402


def test_knots_demo_pool_hash_matches_pr_vector():
    header = bytes.fromhex(demo_pool.KNOTS_V2_HEADER)
    assert demo_pool.knots_v2_hash(header).hex() == "c80e70f7a4a0dbfef4b23c32c52a8e632115c7056b85efd495eadaf66bbc0aef"


def test_sia_demo_pool_verifies_64_bit_nonce(tmp_path):
    header = bytes.fromhex(demo_pool.SIA_HEADER)
    expected = "eab37534b7fd010fe5542cb05c2fcd7d976d625f3272c0410ba75ccd9d7dcd9b"
    pool = demo_pool.DemoPool("sia", header, bytes.fromhex(expected), 32, 8, tmp_path / "results.jsonl")
    assert pool.verify_share(0x0102030405060708, expected) == (True, "accepted")
