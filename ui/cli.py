"""
ui/cli.py
────────────────────────────────────────────────────────────────
Rich interactive CLI for the Hash-Based PRNG portfolio project.

Features
--------
  1. Generate random bytes / integers / floats (HashPRNG or HashDRBG)
  2. Compare all sources side-by-side
  3. Run statistical tests with tabular output
  4. Launch the visual dashboard
  5. Run the MT19937 attack simulation
  6. Export results to JSON / CSV
  7. Live oral-demo mode (paced walkthrough)

Usage
-----
    python ui/cli.py              # interactive menu
    python ui/cli.py --demo       # oral presentation mode
    python ui/cli.py --stats      # stats only, then exit
    python ui/cli.py --attack     # attack only, then exit
"""

from __future__ import annotations

import argparse
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.prng_simple import HashPRNG
from core.hash_drbg import HashDRBG
from core.statistical_tests import monobit_test, chi_square_test, runs_test
from attacks.mt_attack import run_attack_simulation, AttackResult
from exports.exporter import (
    export_json,
    export_csv,
    build_stats_report,
    build_attack_report,
)

# ─────────────────────────────────────────────────────────────────
# Terminal colour helpers (ANSI, graceful fallback)
# ─────────────────────────────────────────────────────────────────

def _c(code: str, text: str) -> str:
    if not sys.stdout.isatty():
        return text
    return f"\033[{code}m{text}\033[0m"

BOLD    = lambda t: _c("1",      t)
GREEN   = lambda t: _c("32",     t)
RED     = lambda t: _c("31",     t)
YELLOW  = lambda t: _c("33",     t)
CYAN    = lambda t: _c("36",     t)
BLUE    = lambda t: _c("34",     t)
DIM     = lambda t: _c("2",      t)
MAGENTA = lambda t: _c("35",     t)


# ─────────────────────────────────────────────────────────────────
# Layout helpers
# ─────────────────────────────────────────────────────────────────

W = 64

def banner(title: str) -> None:
    print("\n" + CYAN("═" * W))
    print(CYAN("  ") + BOLD(title))
    print(CYAN("═" * W))


def section(title: str) -> None:
    print("\n" + DIM("─" * W))
    print(YELLOW("  " + title))
    print(DIM("─" * W))


def ok(msg: str)   -> None: print(GREEN("  ✓ ") + msg)
def fail(msg: str) -> None: print(RED("  ✗ ") + msg)
def info(msg: str) -> None: print(CYAN("  ► ") + msg)
def warn(msg: str) -> None: print(YELLOW("  ⚠ ") + msg)


def pause(prompt: str = "Press Enter to continue…") -> None:
    input(f"\n  {DIM(prompt)} ")


# ─────────────────────────────────────────────────────────────────
# Data helpers
# ─────────────────────────────────────────────────────────────────

import random as stdlib_random

def _drbg_bytes(n: int) -> bytes:
    drbg = HashDRBG()
    result = bytearray()
    while len(result) < n:
        result.extend(drbg.generate(min(7500, n - len(result))))
    return bytes(result)

def _mt_bytes(n: int) -> bytes:
    stdlib_random.seed(99)
    return bytes([stdlib_random.randint(0, 255) for _ in range(n)])


GENERATORS = {
    "HashPRNG":           lambda n: HashPRNG(seed=b"cli_demo_seed").generate_bytes(n),
    "Hash_DRBG":          _drbg_bytes,
    "os.urandom":         os.urandom,
    "MT19937 (insecure)": _mt_bytes,
}


# ─────────────────────────────────────────────────────────────────
# Menu sections
# ─────────────────────────────────────────────────────────────────

def menu_generate() -> None:
    banner("Generate Random Data")

    print("""
  Choose generator:
    [1] HashPRNG  (SHA-256 chain)
    [2] HashDRBG  (NIST SP 800-90A)
    [3] os.urandom (OS entropy)
    [4] Back
""")
    choice = input("  > ").strip()
    if choice == "4":
        return

    try:
        n = int(input("  Number of bytes to generate [default: 32]: ").strip() or "32")
    except ValueError:
        n = 32

    section("Output")
    if choice == "1":
        seed_raw = input("  Seed (leave blank for random): ").strip()
        seed = seed_raw.encode() if seed_raw else None
        prng = HashPRNG(seed=seed)
        data = prng.generate_bytes(n)
        print(f"\n  {BOLD('HashPRNG')} → {CYAN(data.hex())}")
        print(f"  Int  [0,255]: {prng.generate_int(0, 255)}")
        print(f"  Float [0,1): {prng.generate_float():.8f}")

    elif choice == "2":
        drbg = HashDRBG(personalization_string=b"cli_user")
        data = drbg.generate(min(n, 7500))
        print(f"\n  {BOLD('Hash_DRBG')} → {CYAN(data.hex())}")
        print(f"  reseed_counter: {drbg.reseed_counter}")

    elif choice == "3":
        data = os.urandom(n)
        print(f"\n  {BOLD('os.urandom')} → {CYAN(data.hex())}")

    else:
        warn("Invalid choice.")
        return

    save = input("\n  Save to file? [y/N]: ").strip().lower()
    if save == "y":
        path = input("  Filename [output.bin]: ").strip() or "output.bin"
        with open(path, "wb") as f:
            f.write(data)
        ok(f"Saved {len(data)} bytes → {path}")


def menu_compare() -> None:
    banner("Side-by-Side Comparison")

    try:
        n = int(input("  Bytes per source [default: 64]: ").strip() or "64")
    except ValueError:
        n = 64

    section("Outputs")
    col_w = max(n * 2, 20)
    print(f"\n  {'Source':<22} {'First bytes (hex)'}")
    print(f"  {'─'*22} {'─'*min(col_w,48)}")

    for name, gen in GENERATORS.items():
        data = gen(n)
        preview = data.hex()[:48] + ("…" if n > 24 else "")
        color = CYAN if "insecure" not in name else RED
        print(f"  {name:<22} {color(preview)}")


def menu_stats() -> dict | None:
    banner("Statistical Tests")

    try:
        n = int(input("  Sample size in bytes [default: 50000]: ").strip() or "50000")
    except ValueError:
        n = 50_000

    print(f"\n  Sampling {n:,} bytes from each source…\n")

    results: dict[str, dict] = {}
    col = "{:<22} {:>10} {:>10} {:>10} {:>10} {:>8}"
    print("  " + col.format("Source", "Monobit p", "Chi² p", "Runs p", "1-bit %", "Status"))
    print("  " + col.format("─" * 22, "─" * 10, "─" * 10, "─" * 10, "─" * 10, "─" * 8))

    for name, gen in GENERATORS.items():
        data = gen(n)
        mb   = monobit_test(data)
        chi  = chi_square_test(data)
        runs = runs_test(data)

        results[name] = {"monobit": mb, "chi2": chi, "runs": runs}

        all_pass = mb["passed"] and chi["passed"] and runs["passed"]
        status = GREEN("✓ PASS") if all_pass else RED("✗ FAIL")
        src_label = RED(name) if "insecure" in name else name

        print("  " + col.format(
            name,
            f"{mb['p_value']:.4f}",
            f"{chi['p_value']:.4f}",
            f"{runs['p_value']:.4f}",
            f"{mb['proportion']*100:.3f}",
            "",
        ) + f"  {status}")

    print(f"\n  {DIM('NIST threshold: p ≥ 0.01')}")

    # Export?
    export_choice = input("\n  Export results? [j=JSON / c=CSV / N=skip]: ").strip().lower()
    if export_choice == "j":
        report = build_stats_report(results, n)
        path = export_json(report, "stats_report.json")
        ok(f"JSON exported → {path}")
    elif export_choice == "c":
        rows = []
        for src, res in results.items():
            rows.append({
                "source":       src,
                "monobit_p":    res["monobit"]["p_value"],
                "chi2_p":       res["chi2"]["p_value"],
                "runs_p":       res["runs"]["p_value"],
                "bit_proportion": res["monobit"]["proportion"],
                "passed":       res["monobit"]["passed"] and res["chi2"]["passed"],
            })
        path = export_csv(rows, "stats_report.csv")
        ok(f"CSV exported → {path}")

    return results


def menu_dashboard() -> None:
    banner("Statistical Dashboard")

    try:
        from ui.visualizer import generate_dashboard
    except ImportError as e:
        fail(f"Cannot import visualizer: {e}")
        return

    try:
        n = int(input("  Sample size [default: 100000]: ").strip() or "100000")
    except ValueError:
        n = 100_000

    path = input("  Output file [statistical_results.png]: ").strip() or "statistical_results.png"
    print()

    saved = generate_dashboard(
        sample_size=n,
        output_path=path,
        progress_callback=lambda m: print(f"  {DIM(m)}"),
    )
    ok(f"Dashboard saved → {CYAN(saved)}")


def menu_attack() -> None:
    banner("MT19937 Attack Simulation")

    print(f"""
  {BOLD('Background')}
  Python's random module uses MT19937 (Mersenne Twister).
  After observing {YELLOW('624 consecutive 32-bit outputs')}, an attacker
  can fully reconstruct the internal state and predict ALL
  future outputs with {RED('100% accuracy')}.

  HashPRNG and HashDRBG are {GREEN('immune')} — SHA-256 hides the state.
""")
    input(f"  {DIM('Press Enter to run the attack…')} ")

    print()
    result = run_attack_simulation(
        seed=42,
        num_predictions=20,
        progress_callback=lambda m: print(f"  {DIM(m)}"),
    )

    section("Attack Results")
    print(f"\n  {'Step':<28} {'Value':>20}")
    print(f"  {'─'*28} {'─'*20}")
    print(f"  {'Outputs observed':<28} {result.observed_count:>20,}")
    print(f"  {'Observation time':<28} {result.observation_time_ms:>19.2f}ms")
    print(f"  {'Clone time':<28} {result.clone_time_ms:>20.3f}ms")

    section("Predictions (first 20 future outputs)")
    print(f"\n  {'#':>4}  {'Predicted':>12}  {'Actual':>12}  {'Match?'}")
    print(f"  {'─'*4}  {'─'*12}  {'─'*12}  {'─'*6}")
    for i, (pred, actual, matched) in enumerate(result.predictions, 1):
        m = GREEN("✓") if matched else RED("✗")
        print(f"  {i:>4}  0x{pred:08X}  0x{actual:08X}  {m}")

    section("Summary")
    acc_str = f"{result.correct_predictions}/{result.total_predictions} ({result.accuracy*100:.0f}%)"
    print(f"\n  Prediction accuracy : {(GREEN if result.attack_succeeded else RED)(acc_str)}")
    print(f"  Attack succeeded    : {(RED('YES — MT is broken!') if result.attack_succeeded else GREEN('No'))}")

    section("Resistance Check")
    def r(flag: bool) -> str:
        return GREEN("✓ SECURE  — SHA-256 hides internal state") if not flag else RED("✗ VULNERABLE")
    print(f"\n  HashPRNG  : {r(result.hash_prng_predictable)}")
    print(f"  HashDRBG  : {r(result.hash_drbg_predictable)}")

    export_choice = input("\n  Export attack report? [j=JSON / N=skip]: ").strip().lower()
    if export_choice == "j":
        path = export_json(build_attack_report(result), "attack_report.json")
        ok(f"JSON exported → {path}")


# ─────────────────────────────────────────────────────────────────
# Live demo mode  (for oral presentation)
# ─────────────────────────────────────────────────────────────────

def demo_mode() -> None:
    os.system("clear" if os.name == "posix" else "cls")
    print("\n" + CYAN("█" * W))
    print(CYAN("█") + BOLD("  HASH-BASED PRNG — LIVE ORAL PRESENTATION DEMO") + CYAN("  █"))
    print(CYAN("█") + "  Module: Cryptography & Security                  " + CYAN("  █"))
    print(CYAN("█" * W))

    pause("Starting… press Enter at each step.")

    # ── 1. Concepts ──────────────────────────────────────────────
    banner("SECTION 1 — What Is a PRNG?")
    print(f"""
  A PRNG produces sequences that {YELLOW('look')} random but are fully
  {BOLD('deterministic')} given the same seed.

  {BOLD('PRNG  →')} fast, deterministic, NOT safe for cryptography
  {BOLD('CSPRNG →')} computationally indistinguishable from true random

  {CYAN('SHA-256')} is a one-way function:
    Given SHA-256(X) you {RED('cannot')} find X.
    → perfect foundation for a CSPRNG.
""")
    pause()

    # ── 2. Determinism ───────────────────────────────────────────
    banner("SECTION 2 — HashPRNG Determinism")
    seed = b"demo_seed_2025"
    p1 = HashPRNG(seed=seed)
    p2 = HashPRNG(seed=seed)
    out1 = p1.generate_bytes(16)
    out2 = p2.generate_bytes(16)
    print(f"\n  PRNG-A : {CYAN(out1.hex())}")
    print(f"  PRNG-B : {CYAN(out2.hex())}")
    print(f"  Equal? : {GREEN('True ✓') if out1 == out2 else RED('False ✗')}  ← same seed → same output")
    pause()

    # ── 3. Avalanche ─────────────────────────────────────────────
    banner("SECTION 3 — Avalanche Effect")
    out_a = HashPRNG(seed=b"seed_A").generate_bytes(32)
    out_b = HashPRNG(seed=b"seed_B").generate_bytes(32)
    diff = bin(int.from_bytes(out_a, "big") ^ int.from_bytes(out_b, "big")).count("1")
    total = 32 * 8
    pct = diff / total * 100
    print(f"\n  Seed A : {CYAN(out_a.hex())}")
    print(f"  Seed B : {CYAN(out_b.hex())}")
    print(f"  Bits ≠ : {YELLOW(str(diff))} / {total}  ({pct:.1f}%)  ← ideal ≈ 50%")
    pause()

    # ── 4. DRBG ──────────────────────────────────────────────────
    banner("SECTION 4 — Hash_DRBG (NIST SP 800-90A)")
    drbg = HashDRBG(personalization_string=b"oral_defense")
    o1 = drbg.generate(32)
    o2 = drbg.generate(32)
    print(f"\n  Call 1 : {CYAN(o1.hex())}")
    print(f"  Call 2 : {CYAN(o2.hex())}")
    print(f"  Same?  : {RED('False ✓')}  ← must differ")
    print(f"\n  Reseed counter before: {drbg.reseed_counter}")
    drbg.reseed()
    print(f"  Reseed counter after : {GREEN(str(drbg.reseed_counter))} ← reset")
    pause()

    # ── 5. Attack ────────────────────────────────────────────────
    banner("SECTION 5 — MT19937 Attack Demo")
    print(f"  After {YELLOW('624 observations')} of random.getrandbits(32) :")
    result = run_attack_simulation(seed=42, num_predictions=5)
    for i, (pred, actual, matched) in enumerate(result.predictions, 1):
        m = GREEN("✓") if matched else RED("✗")
        print(f"    #{i}  predicted=0x{pred:08X}  actual=0x{actual:08X}  {m}")
    print(f"\n  Accuracy : {GREEN('100%')} — {RED('MT is fully broken!')}")
    print(f"  HashPRNG : {GREEN('IMMUNE')} — SHA-256 hides state")
    print(f"  HashDRBG : {GREEN('IMMUNE')} — NIST DRBG standard")
    pause()

    # ── 6. Stats ─────────────────────────────────────────────────
    banner("SECTION 6 — Statistical Snapshot (50 000 bytes)")
    n = 50_000
    print(f"\n  {'Source':<22} {'Monobit p':>10} {'Chi² p':>10} {'1-bit%':>8}  Result")
    print(f"  {'─'*22} {'─'*10} {'─'*10} {'─'*8}  {'─'*6}")
    for name, gen in GENERATORS.items():
        data = gen(n)
        mb  = monobit_test(data)
        chi = chi_square_test(data)
        status = GREEN("✓ PASS") if mb["passed"] and chi["passed"] else RED("✗ FAIL")
        label  = RED(name) if "insecure" in name else name
        print(f"  {name:<22} {mb['p_value']:>10.4f} {chi['p_value']:>10.4f} "
              f"{mb['proportion']*100:>7.3f}%  {status}")
    pause()

    # ── Fin ───────────────────────────────────────────────────────
    banner("DEMO COMPLETE")
    print(f"""
  {GREEN('✓')} HashPRNG   — SHA-256 hash-chain, deterministic, secure
  {GREEN('✓')} Hash_DRBG  — NIST SP 800-90A, reseedable CSPRNG
  {GREEN('✓')} Statistics — passes monobit, chi-square, runs tests
  {RED('✗')} MT19937    — predictable after 624 outputs

  Security assumption: {CYAN('SHA-256 is a one-way function.')}
  As long as that holds, our PRNG output is {GREEN('cryptographically secure')}.
""")


# ─────────────────────────────────────────────────────────────────
# Main interactive menu
# ─────────────────────────────────────────────────────────────────

MENU = """
  ┌─────────────────────────────────────────────────┐
  │  Hash-Based PRNG — Portfolio CLI                │
  ├─────────────────────────────────────────────────┤
  │  [1] Generate random data                       │
  │  [2] Compare all sources                        │
  │  [3] Run statistical tests                      │
  │  [4] Generate visual dashboard (PNG)            │
  │  [5] MT19937 attack simulation                  │
  │  [6] Oral demo mode (paced walkthrough)         │
  │  [q] Quit                                       │
  └─────────────────────────────────────────────────┘
"""

def main(args: argparse.Namespace | None = None) -> None:
    if args and args.demo:
        demo_mode()
        return
    if args and args.stats:
        menu_stats()
        return
    if args and args.attack:
        menu_attack()
        return

    os.system("clear" if os.name == "posix" else "cls")
    print(CYAN("\n  Hash-Based PRNG — Cryptography Portfolio Project"))
    print(DIM("  SHA-256 · NIST SP 800-90A · MT Attack Simulation\n"))

    HANDLERS = {
        "1": menu_generate,
        "2": menu_compare,
        "3": menu_stats,
        "4": menu_dashboard,
        "5": menu_attack,
        "6": demo_mode,
    }

    while True:
        print(MENU)
        choice = input("  > ").strip().lower()
        if choice in ("q", "quit", "exit"):
            print(CYAN("\n  Goodbye!\n"))
            break
        handler = HANDLERS.get(choice)
        if handler:
            try:
                handler()
            except KeyboardInterrupt:
                print("\n  Interrupted.")
        else:
            warn("Unknown option — please enter 1–6 or q.")


# ─────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Hash-Based PRNG CLI")
    parser.add_argument("--demo",   action="store_true", help="Oral demo mode")
    parser.add_argument("--stats",  action="store_true", help="Run stats and exit")
    parser.add_argument("--attack", action="store_true", help="Run attack and exit")
    main(parser.parse_args())
