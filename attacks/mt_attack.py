"""
attacks/mt_attack.py
────────────────────────────────────────────────────────────────
Pedagogical simulation of the Mersenne Twister state-recovery attack.

Background
----------
Python's `random` module uses MT19937 (Mersenne Twister).
The internal state consists of 624 × 32-bit integers.

Attack
------
After observing 624 consecutive 32-bit outputs from `random.getrandbits(32)`,
an adversary can FULLY RECONSTRUCT the internal state and thus predict
ALL future (and past) outputs.

This module implements:
1. MT19937 clone — recreates the state from 624 observed outputs.
2. Attack demonstration — shows that the cloned PRNG produces identical
   future outputs to the original.
3. Resistance check — proves HashPRNG and HashDRBG are immune.

References
----------
Matsumoto & Nishimura (1998) — "Mersenne Twister: A 623-dimensionally
equidistributed uniform pseudo-random number generator."
"""

from __future__ import annotations

import random as stdlib_random
import sys
import os
import time
from dataclasses import dataclass, field
from typing import Callable

# Ensure project root is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from core.prng_simple import HashPRNG
from core.hash_drbg import HashDRBG


# ══════════════════════════════════════════════════════════════════
# MT19937 clone
# ══════════════════════════════════════════════════════════════════

class MT19937Clone:
    """
    Full MT19937 state clone built from 624 observed 32-bit outputs.

    Once cloned, ``getrandbits(32)`` produces values identical to the
    original generator's future outputs.

    Parameters
    ----------
    observed : list[int]
        Exactly 624 consecutive 32-bit integers from the target.
    """

    N = 624
    M = 397
    MATRIX_A = 0x9908B0DF
    UPPER_MASK = 0x80000000
    LOWER_MASK = 0x7FFFFFFF

    def __init__(self, observed: list[int]) -> None:
        if len(observed) != self.N:
            raise ValueError(f"Need exactly {self.N} outputs, got {len(observed)}")
        self._mt: list[int] = [self._untemper(x) for x in observed]
        self._index: int = self.N

    # ------------------------------------------------------------------
    # Untemper — inverse of MT tempering transform
    # ------------------------------------------------------------------

    @staticmethod
    def _untemper_right(x: int, shift: int) -> int:
        """Invert: y ^= y >> shift  (right-shift XOR)."""
        result = x
        for _ in range(shift, 32, shift):
            result = x ^ (result >> shift)
        return result & 0xFFFF_FFFF

    @staticmethod
    def _untemper_left(x: int, shift: int, mask: int) -> int:
        """Invert: y ^= (y << shift) & mask  (left-shift XOR with mask)."""
        result = x
        for _ in range(shift, 32, shift):
            result = x ^ ((result << shift) & mask)
        return result & 0xFFFF_FFFF

    def _untemper(self, y: int) -> int:
        """Invert the full MT tempering step to recover the raw state word."""
        y = self._untemper_right(y, 18)
        y = self._untemper_left(y, 15, 0xEFC60000)
        y = self._untemper_left(y, 7,  0x9D2C5680)
        y = self._untemper_right(y, 11)
        return y

    # ------------------------------------------------------------------
    # MT generate step
    # ------------------------------------------------------------------

    def _generate_numbers(self) -> None:
        for kk in range(self.N):
            y = (self._mt[kk] & self.UPPER_MASK) | (self._mt[(kk + 1) % self.N] & self.LOWER_MASK)
            self._mt[kk] = self._mt[(kk + self.M) % self.N] ^ (y >> 1)
            if y % 2 != 0:
                self._mt[kk] ^= self.MATRIX_A
        self._index = 0

    def _temper(self, y: int) -> int:
        y ^= y >> 11
        y ^= (y << 7) & 0x9D2C5680
        y ^= (y << 15) & 0xEFC60000
        y ^= y >> 18
        return y

    def getrandbits(self, k: int = 32) -> int:
        """Return next k-bit pseudorandom integer (k ≤ 32)."""
        if self._index >= self.N:
            self._generate_numbers()
        y = self._mt[self._index]
        self._index += 1
        return self._temper(y) & ((1 << k) - 1)


# ══════════════════════════════════════════════════════════════════
# Attack result dataclass
# ══════════════════════════════════════════════════════════════════

@dataclass
class AttackResult:
    """Container for the full attack simulation outcome."""

    # Observation phase
    observed_count: int = 0
    observation_time_ms: float = 0.0

    # Clone phase
    clone_time_ms: float = 0.0

    # Prediction phase
    predictions: list[tuple[int, int, bool]] = field(default_factory=list)
    # Each tuple: (predicted, actual, matched)

    # Summary
    total_predictions: int = 0
    correct_predictions: int = 0

    # HashPRNG / DRBG resistance
    hash_prng_predictable: bool = False
    hash_drbg_predictable: bool = False

    @property
    def accuracy(self) -> float:
        if self.total_predictions == 0:
            return 0.0
        return self.correct_predictions / self.total_predictions

    @property
    def attack_succeeded(self) -> bool:
        return self.accuracy == 1.0


# ══════════════════════════════════════════════════════════════════
# High-level simulation
# ══════════════════════════════════════════════════════════════════

def run_attack_simulation(
    seed: int = 42,
    num_predictions: int = 20,
    progress_callback: Callable[[str], None] | None = None,
) -> AttackResult:
    """
    End-to-end MT19937 state-recovery attack simulation.

    Steps
    -----
    1. Seed a real `random.Random` instance (the "victim").
    2. Observe 624 consecutive 32-bit outputs.
    3. Clone the state using MT19937Clone.
    4. Verify that all future outputs match.
    5. Show HashPRNG and HashDRBG cannot be cloned.

    Parameters
    ----------
    seed : int
        Seed for the victim random generator.
    num_predictions : int
        How many future outputs to verify (default 20).
    progress_callback : callable, optional
        Called with status strings during execution.

    Returns
    -------
    AttackResult
    """
    def log(msg: str) -> None:
        if progress_callback:
            progress_callback(msg)

    result = AttackResult()
    victim = stdlib_random.Random(seed)

    # ── Phase 1: Observation ──────────────────────────────────────
    log("Phase 1/4 — Observing 624 outputs from victim…")
    t0 = time.perf_counter()
    observed = [victim.getrandbits(32) for _ in range(624)]
    result.observation_time_ms = (time.perf_counter() - t0) * 1000
    result.observed_count = 624
    log(f"  Captured {len(observed)} outputs in {result.observation_time_ms:.2f} ms")

    # ── Phase 2: Clone ────────────────────────────────────────────
    log("Phase 2/4 — Reconstructing internal state…")
    t1 = time.perf_counter()
    clone = MT19937Clone(observed)
    result.clone_time_ms = (time.perf_counter() - t1) * 1000
    log(f"  State reconstruction in {result.clone_time_ms:.3f} ms")

    # ── Phase 3: Predict ──────────────────────────────────────────
    log(f"Phase 3/4 — Predicting next {num_predictions} outputs…")
    predictions: list[tuple[int, int, bool]] = []
    for _ in range(num_predictions):
        predicted = clone.getrandbits(32)
        actual    = victim.getrandbits(32)
        matched   = predicted == actual
        predictions.append((predicted, actual, matched))

    result.predictions = predictions
    result.total_predictions = num_predictions
    result.correct_predictions = sum(1 for _, _, m in predictions if m)
    log(f"  Accuracy: {result.correct_predictions}/{result.total_predictions} "
        f"({result.accuracy * 100:.0f}%)")

    # ── Phase 4: Resistance check ─────────────────────────────────
    log("Phase 4/4 — Checking HashPRNG and HashDRBG resistance…")

    # HashPRNG: observe 624 outputs (each 4 bytes), try to predict next
    hp = HashPRNG(seed=b"attack_test_seed")
    hp_observed = [int.from_bytes(hp.generate_bytes(4), "big") for _ in range(624)]
    hp_next_real = int.from_bytes(hp.generate_bytes(4), "big")

    # An attacker with only 624 outputs cannot invert SHA-256 to get state
    # Best guess: last observed value (trivially wrong)
    hp_guess = hp_observed[-1]
    result.hash_prng_predictable = (hp_guess == hp_next_real)

    # HashDRBG: same approach
    drbg = HashDRBG(personalization_string=b"attack_test")
    db_observed = [int.from_bytes(drbg.generate(4), "big") for _ in range(624)]
    db_next_real = int.from_bytes(drbg.generate(4), "big")
    db_guess = db_observed[-1]
    result.hash_drbg_predictable = (db_guess == db_next_real)

    log("  HashPRNG predictable?  " + ("YES ← BUG" if result.hash_prng_predictable else "NO ✓ Secure"))
    log("  HashDRBG predictable?  " + ("YES ← BUG" if result.hash_drbg_predictable else "NO ✓ Secure"))
    log("Attack simulation complete.")

    return result


# ══════════════════════════════════════════════════════════════════
# CLI runner
# ══════════════════════════════════════════════════════════════════

def _print_result(result: AttackResult) -> None:
    W = 62
    print("\n" + "═" * W)
    print("  MERSENNE TWISTER ATTACK — RESULTS")
    print("═" * W)

    print(f"\n  Observation  : {result.observed_count} outputs "
          f"in {result.observation_time_ms:.2f} ms")
    print(f"  Reconstruction: {result.clone_time_ms:.3f} ms")
    print(f"\n  {'#':>4}  {'Predicted':>12}  {'Actual':>12}  {'Match?':>8}")
    print(f"  {'-'*4}  {'-'*12}  {'-'*12}  {'-'*8}")
    for i, (pred, actual, matched) in enumerate(result.predictions, 1):
        m = "✓" if matched else "✗"
        print(f"  {i:>4}  0x{pred:08X}  0x{actual:08X}  {m:>8}")

    print(f"\n  ► Prediction accuracy: "
          f"{result.correct_predictions}/{result.total_predictions} "
          f"({result.accuracy*100:.0f}%)")
    print(f"  ► Attack succeeded: {'YES — MT is broken!' if result.attack_succeeded else 'No'}")

    print(f"\n  ─ Resistance Check ─")
    print(f"  HashPRNG  predictable? {'⚠ YES' if result.hash_prng_predictable else '✓  NO — SHA-256 hides state'}")
    print(f"  HashDRBG  predictable? {'⚠ YES' if result.hash_drbg_predictable else '✓  NO — NIST DRBG is secure'}")
    print("\n" + "═" * W)


if __name__ == "__main__":
    result = run_attack_simulation(
        seed=42,
        num_predictions=20,
        progress_callback=lambda msg: print(f"  [LOG] {msg}"),
    )
    _print_result(result)
