"""Beginner-friendly entry point.

Press Run in your Python editor with no arguments to analyse the included sample.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from sentinelprior.config import load_settings
from sentinelprior.orchestrator import CoordinatorAgent


PROJECT_ROOT = Path(__file__).resolve().parent
DEFAULT_SCAN = PROJECT_ROOT / "data" / "sample_scan.csv"
DEFAULT_OUTPUT = PROJECT_ROOT / "outputs"
DEFAULT_GOAL = (
    "Analyse this vulnerability scan for our internet-facing payment application, "
    "identify the five findings requiring immediate action, and prepare an "
    "evidence-backed remediation report."
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run SentinelPrior")
    parser.add_argument("--scan", type=Path, default=DEFAULT_SCAN)
    parser.add_argument("--goal", default=DEFAULT_GOAL)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--simulate-epss-failure",
        action="store_true",
        help="Deliberately make EPSS time out to demonstrate recovery",
    )
    parser.add_argument(
        "--no-ai",
        action="store_true",
        help="Use the documented deterministic fallback even when a key exists",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    agent = CoordinatorAgent(load_settings(), disable_ai=args.no_ai)
    result, paths = agent.run(
        args.goal,
        args.scan,
        args.output_dir,
        simulate_epss_failure=args.simulate_epss_failure,
    )

    print("\nCompleted successfully")
    print(f"Run ID: {result.run_id}")
    print(f"AI mode: {result.ai_mode}")
    for name, path in paths.items():
        print(f"{name.title()}: {path.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
