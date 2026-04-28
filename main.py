"""
main.py
────────────────────────────────────────────────────────────────
Entry point for the Hash-Based PRNG portfolio project.

Usage
-----
    python main.py              # interactive CLI menu
    python main.py --demo       # paced oral-presentation walkthrough
    python main.py --stats      # statistical tests only, then exit
    python main.py --attack     # MT attack simulation only, then exit
    python main.py --dashboard  # generate PNG dashboard and exit
"""

from __future__ import annotations

import argparse
import sys


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="hash-prng",
        description=(
            "Hash-Based PRNG Portfolio Project\n"
            "SHA-256 · NIST SP 800-90A · MT19937 Attack Simulation"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Run paced oral-presentation demo mode",
    )
    parser.add_argument(
        "--stats",
        action="store_true",
        help="Run statistical tests and exit",
    )
    parser.add_argument(
        "--attack",
        action="store_true",
        help="Run MT19937 attack simulation and exit",
    )
    parser.add_argument(
        "--dashboard",
        action="store_true",
        help="Generate PNG statistical dashboard and exit",
    )
    parser.add_argument(
        "--sample-size",
        type=int,
        default=100_000,
        metavar="N",
        help="Bytes per source for stats / dashboard (default: 100 000)",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="statistical_results.png",
        metavar="FILE",
        help="Output path for the dashboard PNG",
    )

    args = parser.parse_args()

    if args.dashboard:
        from ui.visualizer import generate_dashboard
        print(f"Generating dashboard ({args.sample_size:,} bytes per source)…")
        path = generate_dashboard(
            sample_size=args.sample_size,
            output_path=args.output,
            progress_callback=lambda m: print(f"  {m}"),
        )
        print(f"\n✓ Saved → {path}")
        return

    # Delegate everything else to the CLI module
    from ui.cli import main as cli_main
    cli_main(args)


if __name__ == "__main__":
    main()
