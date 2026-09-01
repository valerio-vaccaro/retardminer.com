import json
import subprocess

import pytest


@pytest.mark.benchmark
def test_blake2b_hashrate(blake2b_tool):
    """Report native host rate. It is not an ESP32 result or a performance gate."""
    result = subprocess.run(
        [str(blake2b_tool), "bench", "100000"],
        text=True, capture_output=True, check=True,
    )
    report = json.loads(result.stdout)
    assert report["hashes"] == 100000
    assert report["seconds"] > 0
    assert report["hashes_per_second"] > 0
    print(f"\nNative BLAKE2b-256 rate: {report['hashes_per_second']:.0f} H/s ({report['hashes']} hashes in {report['seconds']:.3f}s)")
