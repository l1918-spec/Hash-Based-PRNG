"""
core/prng_simple.py
────────────────────────────────────────────────────────────────
Simple SHA-256 hash-chain PRNG.

Design:
  state₀ = SHA-256(seed)
  outputᵢ = SHA-256(stateᵢ)
  stateᵢ₊₁ = SHA-256(stateᵢ ‖ counter)

Security note:
  Forward secrecy is guaranteed (SHA-256 is one-way).
  This is NOT a NIST-approved DRBG; see hash_drbg.py for that.
"""

from __future__ import annotations

import hashlib
import os
from typing import Optional


class HashPRNG:
    """
    Simple hash-chain pseudo-random number generator using SHA-256.

    Parameters
    ----------
    seed : bytes, optional
        Seed material.  If *None*, ``os.urandom(32)`` is used so every
        instance is unpredictable by default.

    Examples
    --------
    >>> prng = HashPRNG(seed=b"my secret seed")
    >>> prng.generate_bytes(16).hex()   # doctest: +ELLIPSIS
    '...'
    >>> prng.generate_int(1, 6)         # fair d6
    ...
    """

    HASH_ALGO: str = "sha256"
    STATE_SIZE: int = 32  # bytes

    def __init__(self, seed: Optional[bytes] = None) -> None:
        if seed is None:
            seed = os.urandom(self.STATE_SIZE)
        self._state: bytes = self._hash(seed)
        self._output_count: int = 0

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _hash(self, data: bytes) -> bytes:
        """Return SHA-256 digest of *data*."""
        return hashlib.new(self.HASH_ALGO, data).digest()

    def _advance(self) -> bytes:
        """
        Produce one 32-byte output block and update the internal state.

        Returns
        -------
        bytes
            32 pseudorandom bytes derived from the current state.
        """
        output_block: bytes = self._hash(self._state)
        counter_bytes: bytes = self._output_count.to_bytes(8, "big")
        self._state = self._hash(self._state + counter_bytes)
        self._output_count += 1
        return output_block

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate_bytes(self, n: int) -> bytes:
        """
        Return *n* pseudorandom bytes.

        Parameters
        ----------
        n : int
            Number of bytes requested (must be > 0).

        Raises
        ------
        ValueError
            If *n* ≤ 0.
        """
        if n <= 0:
            raise ValueError("n must be a positive integer")
        result = bytearray()
        while len(result) < n:
            result.extend(self._advance())
        return bytes(result[:n])

    def generate_int(self, low: int, high: int) -> int:
        """
        Return a uniformly distributed integer in [low, high].

        Uses rejection sampling to avoid modular bias.

        Parameters
        ----------
        low : int
        high : int

        Raises
        ------
        ValueError
            If *low* > *high*.
        """
        if low > high:
            raise ValueError("low must be <= high")
        range_size = high - low + 1
        num_bytes = (range_size.bit_length() + 7) // 8
        mask = (1 << range_size.bit_length()) - 1
        while True:
            candidate = int.from_bytes(self.generate_bytes(num_bytes), "big") & mask
            if candidate < range_size:
                return low + candidate

    def generate_float(self) -> float:
        """Return a pseudorandom float in [0, 1)."""
        raw = int.from_bytes(self.generate_bytes(8), "big")
        return raw / (2**64)

    def reseed(self, new_seed: bytes) -> None:
        """
        Mix *new_seed* into the current state and reset the counter.

        Parameters
        ----------
        new_seed : bytes
            Fresh entropy to incorporate.
        """
        self._state = self._hash(self._state + new_seed)
        self._output_count = 0

    @property
    def output_count(self) -> int:
        """Total number of 32-byte blocks generated so far."""
        return self._output_count

    def __repr__(self) -> str:
        return (
            f"HashPRNG("
            f"algo={self.HASH_ALGO!r}, "
            f"outputs_generated={self._output_count})"
        )


# ------------------------------------------------------------------
# Quick smoke-test
# ------------------------------------------------------------------
if __name__ == "__main__":
    print("=" * 55)
    print("  Simple Hash-Based PRNG — SHA-256 Demo")
    print("=" * 55)

    prng_fixed = HashPRNG(seed=b"university_demo_seed_2025")
    print("\n[Fixed seed — reproducible output]")
    print(f"  16 bytes  : {prng_fixed.generate_bytes(16).hex()}")
    print(f"  Int [1,100]: {prng_fixed.generate_int(1, 100)}")
    print(f"  Float     : {prng_fixed.generate_float():.6f}")

    prng_fixed2 = HashPRNG(seed=b"university_demo_seed_2025")
    print("\n[Same seed — must produce identical output]")
    print(f"  16 bytes  : {prng_fixed2.generate_bytes(16).hex()}")

    prng_random = HashPRNG()
    print("\n[Random seed — unpredictable output]")
    print(f"  16 bytes  : {prng_random.generate_bytes(16).hex()}")
    print(f"  {prng_random}")
    print("\n✓ HashPRNG working correctly.")
