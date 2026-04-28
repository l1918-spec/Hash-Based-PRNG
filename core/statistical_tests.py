"""
core/statistical_tests.py
────────────────────────────────────────────────────────────────
Statistical randomness tests for PRNG output evaluation.

Tests implemented
-----------------
1. NIST Monobit (Frequency) Test  — SP 800-22 section 2.1
2. Chi-Square Uniformity Test     — byte-level goodness-of-fit
3. Runs Test                      — SP 800-22 section 2.3
4. Autocorrelation                — lag-1 … lag-N correlation

All tests return a dict with at minimum:
  passed  : bool   — True if the test's p-value ≥ 0.01
  p_value : float  — the computed p-value
"""

from __future__ import annotations

import math
from typing import TypedDict

import numpy as np
from scipy import stats


# ------------------------------------------------------------------
# Type aliases
# ------------------------------------------------------------------

class MonobitResult(TypedDict):
    ones: int
    zeros: int
    proportion: float
    s_obs: float
    p_value: float
    passed: bool


class ChiSquareResult(TypedDict):
    chi2_stat: float
    p_value: float
    passed: bool


class RunsResult(TypedDict):
    runs_count: int
    p_value: float
    passed: bool


# ------------------------------------------------------------------
# Test 1 — NIST Monobit (Frequency) Test
# ------------------------------------------------------------------

def monobit_test(data: bytes) -> MonobitResult:
    """
    NIST SP 800-22 Section 2.1 — Frequency (Monobit) Test.

    Checks whether the number of 1-bits is approximately equal to
    the number of 0-bits in the entire sequence.

    Parameters
    ----------
    data : bytes
        Raw byte sequence to test.

    Returns
    -------
    MonobitResult
        Dictionary with test statistics and pass/fail verdict.
    """
    bits: list[int] = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)

    n = len(bits)
    ones = sum(bits)
    zeros = n - ones
    s_n = ones - zeros
    s_obs = abs(s_n) / math.sqrt(n)
    p_value = math.erfc(s_obs / math.sqrt(2))

    return MonobitResult(
        ones=ones,
        zeros=zeros,
        proportion=ones / n,
        s_obs=s_obs,
        p_value=p_value,
        passed=p_value >= 0.01,
    )


# ------------------------------------------------------------------
# Test 2 — Chi-Square Uniformity Test
# ------------------------------------------------------------------

def chi_square_test(data: bytes) -> ChiSquareResult:
    """
    Chi-Square goodness-of-fit test for byte uniformity.

    Tests whether each of the 256 possible byte values appears with
    equal frequency (expected: n/256 each).

    Parameters
    ----------
    data : bytes
        Raw byte sequence to test.

    Returns
    -------
    ChiSquareResult
    """
    observed = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    expected = np.full(256, len(data) / 256)
    chi2_stat, p_value = stats.chisquare(observed, expected)

    return ChiSquareResult(
        chi2_stat=float(chi2_stat),
        p_value=float(p_value),
        passed=float(p_value) >= 0.01,
    )


# ------------------------------------------------------------------
# Test 3 — Runs Test
# ------------------------------------------------------------------

def runs_test(data: bytes) -> RunsResult:
    """
    NIST SP 800-22 Section 2.3 — Runs Test.

    A *run* is a maximal sequence of identical consecutive bits.
    Tests whether the oscillation between 0- and 1-blocks is too
    fast or too slow.

    Parameters
    ----------
    data : bytes
        Raw byte sequence to test.

    Returns
    -------
    RunsResult
    """
    bits: list[int] = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)

    n = len(bits)
    ones = sum(bits)
    pi = ones / n  # proportion of 1s

    # Pre-test: if |π - 0.5| ≥ 2/√n the test is not applicable
    tau = 2.0 / math.sqrt(n)
    if abs(pi - 0.5) >= tau:
        return RunsResult(runs_count=0, p_value=0.0, passed=False)

    # Count runs
    runs_count = 1 + sum(bits[i] != bits[i - 1] for i in range(1, n))

    numerator = abs(runs_count - 2 * n * pi * (1 - pi))
    denominator = 2 * math.sqrt(2 * n) * pi * (1 - pi)
    p_value = math.erfc(numerator / denominator)

    return RunsResult(
        runs_count=runs_count,
        p_value=p_value,
        passed=p_value >= 0.01,
    )


# ------------------------------------------------------------------
# Helper — Autocorrelation
# ------------------------------------------------------------------

def autocorrelation(data: bytes, max_lag: int = 50) -> np.ndarray:
    """
    Compute normalised autocorrelation coefficients for lags 1…max_lag.

    Parameters
    ----------
    data : bytes
    max_lag : int

    Returns
    -------
    np.ndarray
        Shape (max_lag,).  Values near 0 indicate no serial correlation.
    """
    arr = np.frombuffer(data, dtype=np.uint8).astype(float)
    arr -= arr.mean()
    full_corr = np.correlate(arr, arr, mode="full")
    full_corr /= full_corr[len(arr) - 1]
    mid = len(arr) - 1
    return full_corr[mid + 1 : mid + 1 + max_lag]


# ------------------------------------------------------------------
# Quick smoke-test
# ------------------------------------------------------------------
if __name__ == "__main__":
    import os

    sample = os.urandom(50_000)
    print("os.urandom(50 000 bytes)")
    mb = monobit_test(sample)
    chi = chi_square_test(sample)
    runs = runs_test(sample)
    print(f"  Monobit  : p={mb['p_value']:.4f}  {'✓ PASS' if mb['passed'] else '✗ FAIL'}")
    print(f"  Chi²     : p={chi['p_value']:.4f}  {'✓ PASS' if chi['passed'] else '✗ FAIL'}")
    print(f"  Runs     : p={runs['p_value']:.4f}  {'✓ PASS' if runs['passed'] else '✗ FAIL'}")
