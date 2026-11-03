"""Validate the eight CICIDS2017 CSV files expected by the canonical pipeline."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from attack_graph.benchmark_if_attack_graph_pipeline import (  # noqa: E402
    BENCHMARK_FEATURES,
    CSV_ORDER,
    _resolve_columns,
)


def validate(data_dir: Path) -> list[str]:
    if not data_dir.exists() or not data_dir.is_dir():
        raise NotADirectoryError(f"Dataset directory does not exist: {data_dir}")

    errors: list[str] = []
    required = set(BENCHMARK_FEATURES) | {
        "timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "label"
    }

    for filename in CSV_ORDER:
        path = data_dir / filename
        if not path.is_file():
            errors.append(f"Missing file: {filename}")
            continue
        try:
            raw_header = pd.read_csv(path, nrows=0, encoding="latin1", low_memory=False)
            normalized = _resolve_columns(raw_header)
            available = set(normalized.columns)
        except Exception as exc:
            errors.append(f"Could not read header for {filename}: {type(exc).__name__}: {exc}")
            continue

        missing_columns = sorted(required - available)
        size_mb = path.stat().st_size / (1024 * 1024)
        if missing_columns:
            errors.append(
                f"{filename}: missing {len(missing_columns)} required columns: "
                + ", ".join(missing_columns)
            )
        else:
            print(f"[OK] {filename} ({size_mb:.1f} MiB; required columns present)")

    if errors:
        print("\nDataset validation failed:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
    else:
        print(
            f"\nDataset structure looks valid: all {len(CSV_ORDER)} expected CSVs "
            "and required headers were found."
        )
        print("This checks file names and headers only; the pipeline performs row-level validation.")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("data_dir", type=Path, help="Directory containing the eight CICIDS2017 CSV files.")
    args = parser.parse_args()
    try:
        return 1 if validate(args.data_dir) else 0
    except Exception as exc:
        print(f"Dataset validation failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
