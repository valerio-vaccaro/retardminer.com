import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="session")
def blake2b_tool(tmp_path_factory):
    binary = tmp_path_factory.mktemp("build") / "blake2b_tool"
    subprocess.run(
        [
            "g++",
            "-std=c++17",
            "-O3",
            "-Iinclude",
            "src/blake2b.cpp",
            "src/knots_pow.cpp",
            "tests/cpp/blake2b_tool.cpp",
            "-o",
            str(binary),
        ],
        cwd=ROOT,
        check=True,
    )
    return binary
