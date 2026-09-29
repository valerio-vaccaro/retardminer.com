#!/usr/bin/env python3
"""Package PlatformIO builds for the DIY flasher.

The DIY flasher consumes one manifest at the root of the exported directory.
Each PlatformIO environment gets a versioned directory containing binaries
whose flash addresses are part of their names.
"""

import argparse
import hashlib
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path


FLASH_FILES = (
    (0x1000, "bootloader.bin"),
    (0x8000, "partitions.bin"),
    (0xE000, "boot_app0.bin"),
    (0x10000, "firmware.bin"),
)


def boot_app0_source() -> Path | None:
    """Locate the Arduino-ESP32 boot app image installed by PlatformIO."""
    candidates = (
        Path.home() / ".platformio/packages/framework-arduinoespressif32/tools/partitions/boot_app0.bin",
        Path.home() / ".platformio/packages/framework-arduinoespressif32-libs/tools/partitions/boot_app0.bin",
    )
    return next((candidate for candidate in candidates if candidate.exists()), None)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def package_environment(environment: Path, output: Path, version: str, boot_app0: Path | None) -> dict:
    board_folder = f"{version}_{environment.name}"
    board_output = output / board_folder
    board_output.mkdir(parents=True, exist_ok=True)
    files = []

    for address, source_name in FLASH_FILES:
        source = environment / source_name
        if source_name == "boot_app0.bin" and not source.exists() and boot_app0:
            source = boot_app0
        if not source.exists():
            raise FileNotFoundError(f"{source} is required for {environment.name}")

        target_name = f"0x{address:04X}_{source_name}"
        target = board_output / target_name
        shutil.copyfile(source, target)
        files.append({
            "address": f"0x{address:X}",
            "file": f"{board_folder}/{target_name}",
            "sha256": sha256(target),
            "size": target.stat().st_size,
        })

    # Keep both spellings: `files` is useful for consumers and `flashFiles`
    # is accepted by versions of the diyflasher implementation.
    return {
        "name": environment.name,
        "platformio_environment": environment.name,
        "files": files,
        "flashFiles": files,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--build-dir", type=Path, default=Path(".pio/build"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--base-url", default=".")
    args = parser.parse_args()

    if not args.build_dir.is_dir():
        raise FileNotFoundError(f"PlatformIO build directory does not exist: {args.build_dir}")

    args.output.mkdir(parents=True, exist_ok=True)
    boot_app0 = boot_app0_source()
    environments = sorted(path for path in args.build_dir.iterdir() if path.is_dir())
    if not environments:
        raise FileNotFoundError(f"No PlatformIO environments found in {args.build_dir}")

    builds = [package_environment(environment, args.output, args.version, boot_app0) for environment in environments]
    manifest = {
        "name": "retardminer",
        "version": args.version,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "base_url": args.base_url,
        "builds": builds,
        "versions": [{"version": args.version, "builds": builds}],
    }
    (args.output / "index.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
