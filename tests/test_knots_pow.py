import subprocess

import pytest


# Selected official PR #359 header-v2 vectors: profile 0 (no mask) and profile
# 1 (non-zero XOR key). They exercise both ASIC input layouts and mask handling.
VECTORS = [
    (
        "000000a01f1e1d1c1b1a191817161514131211100f0e0d0c0b0a0908070605040302010000112233445566778899aabbccddeeff00102030405060708090a0b0c0d0e0f0a8913577ffff001d0df0ad0b44332211efcdab89ffeeddccbbaa998877665544332211005802000003005c000000000000000000000000000000000040d10c008967452301efcdab8967452301efcdab8967452301efcdab8967452301efcdab",
        "c80e70f7a4a0dbfef4b23c32c52a8e632115c7056b85efd495eadaf66bbc0aef",
    ),
    (
        "000000a01f1e1d1c1b1a191817161514131211100f0e0d0c0b0a0908070605040302010000112233445566778899aabbccddeeff00102030405060708090a0b0c0d0e0f0a8913577ffff001d0df0ad0b44332211efcdab89ffeeddccbbaa998877665544332211005802000001005d00efcdab8967452301efcdab896745230141d10c008967452301efcdab8967452301efcdab8967452301efcdab8967452301efcdab",
        "5f06d990a35d229acf1706f8b9ab4b0c03ee5bf2043220c3902d85861f7cbd54",
    ),
]


@pytest.mark.parametrize(("header", "expected"), VECTORS)
def test_knots_v2_pow_vectors(header, expected, blake2b_tool):
    result = subprocess.run(
        [str(blake2b_tool), "knots-v2", header],
        text=True, capture_output=True, check=True,
    )
    assert result.stdout.strip() == expected
