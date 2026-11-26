#!/usr/bin/env python3
"""Compatibility entrypoint for the existing frozen-DB comparison harness."""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "runner"))
from appsecctl.benchmark import main, snapshot_manifest, scanner_args, scan_one, hash_stream, write_json, run_checked
if __name__ == "__main__":
    sys.exit(main())
