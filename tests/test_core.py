"""
tests/test_core.py
────────────────────────────────────────────────────────────────
Unit tests for HashPRNG, HashDRBG, statistical tests, and the
MT attack simulation.

Run with:
    python -m pytest tests/test_core.py -v
"""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.prng_simple import HashPRNG
from core.hash_drbg import HashDRBG, ReseedRequiredError, hash_df
from core.statistical_tests import (
    monobit_test,
    chi_square_test,
    runs_test,
    autocorrelation,
)
from attacks.mt_attack import MT19937Clone, run_attack_simulation


# ══════════════════════════════════════════════════════════════════
# HashPRNG
# ══════════════════════════════════════════════════════════════════

class TestHashPRNG:
    def test_determinism(self):
        """Same seed → same output."""
        seed = b"test_seed_abc"
        p1 = HashPRNG(seed=seed)
        p2 = HashPRNG(seed=seed)
        assert p1.generate_bytes(64) == p2.generate_bytes(64)

    def test_different_seeds_differ(self):
        p1 = HashPRNG(seed=b"seed_one")
        p2 = HashPRNG(seed=b"seed_two")
        assert p1.generate_bytes(32) != p2.generate_bytes(32)

    def test_output_length(self):
        prng = HashPRNG(seed=b"len_test")
        for n in [1, 16, 32, 100, 1000]:
            assert len(prng.generate_bytes(n)) == n

    def test_generate_int_range(self):
        prng = HashPRNG(seed=b"int_test")
        for _ in range(200):
            v = prng.generate_int(0, 9)
            assert 0 <= v <= 9

    def test_generate_float_range(self):
        prng = HashPRNG(seed=b"float_test")
        for _ in range(100):
            v = prng.generate_float()
            assert 0.0 <= v < 1.0

    def test_zero_length_raises(self):
        prng = HashPRNG(seed=b"x")
        with pytest.raises(ValueError):
            prng.generate_bytes(0)

    def test_reseed_changes_output(self):
        prng = HashPRNG(seed=b"before_reseed")
        _ = prng.generate_bytes(32)
        out_before = prng.generate_bytes(32)
        prng.reseed(b"new_entropy_xyz")
        out_after = prng.generate_bytes(32)
        assert out_before != out_after

    def test_random_seed_different_instances(self):
        p1 = HashPRNG()  # random seed
        p2 = HashPRNG()  # random seed
        # Extremely unlikely to collide
        assert p1.generate_bytes(32) != p2.generate_bytes(32)

    def test_output_count_increments(self):
        prng = HashPRNG(seed=b"counter_test")
        assert prng.output_count == 0
        prng.generate_bytes(32)
        assert prng.output_count == 1
        prng.generate_bytes(64)
        assert prng.output_count == 3  # 32+64 = 96 bytes = 3 × 32-byte blocks

    def test_avalanche(self):
        """1-character seed difference → ≈50% bit difference."""
        out_a = HashPRNG(seed=b"seed_A").generate_bytes(64)
        out_b = HashPRNG(seed=b"seed_B").generate_bytes(64)
        diff = bin(int.from_bytes(out_a, "big") ^ int.from_bytes(out_b, "big")).count("1")
        ratio = diff / (64 * 8)
        assert 0.35 <= ratio <= 0.65, f"Avalanche ratio {ratio:.3f} outside [0.35, 0.65]"


# ══════════════════════════════════════════════════════════════════
# hash_df
# ══════════════════════════════════════════════════════════════════

class TestHashDF:
    def test_output_length(self):
        for bits in [128, 256, 440]:
            result = hash_df(b"test_input", bits)
            assert len(result) == bits // 8

    def test_non_multiple_of_8_raises(self):
        with pytest.raises(ValueError):
            hash_df(b"x", 100)

    def test_determinism(self):
        a = hash_df(b"same", 256)
        b = hash_df(b"same", 256)
        assert a == b


# ══════════════════════════════════════════════════════════════════
# HashDRBG
# ══════════════════════════════════════════════════════════════════

class TestHashDRBG:
    def test_successive_outputs_differ(self):
        drbg = HashDRBG(personalization_string=b"test")
        a = drbg.generate(32)
        b = drbg.generate(32)
        assert a != b

    def test_output_length(self):
        drbg = HashDRBG()
        for n in [1, 32, 100, 7500]:
            assert len(drbg.generate(n)) == n

    def test_exceeding_max_raises(self):
        drbg = HashDRBG()
        with pytest.raises(ValueError):
            drbg.generate(7501)

    def test_reseed_resets_counter(self):
        drbg = HashDRBG()
        drbg.generate(32)
        drbg.generate(32)
        assert drbg.reseed_counter == 3
        drbg.reseed()
        assert drbg.reseed_counter == 1

    def test_additional_input_changes_output(self):
        drbg1 = HashDRBG(entropy_input=b"E" * 32, nonce=b"N" * 16)
        drbg2 = HashDRBG(entropy_input=b"E" * 32, nonce=b"N" * 16)
        a = drbg1.generate(32, additional_input=b"context_A")
        b = drbg2.generate(32, additional_input=b"context_B")
        assert a != b

    def test_determinism_with_fixed_seed(self):
        kwargs = dict(entropy_input=b"E" * 32, nonce=b"N" * 16, personalization_string=b"P")
        out1 = HashDRBG(**kwargs).generate(32)
        out2 = HashDRBG(**kwargs).generate(32)
        assert out1 == out2

    def test_repr(self):
        drbg = HashDRBG()
        assert "HashDRBG" in repr(drbg)


# ══════════════════════════════════════════════════════════════════
# Statistical tests (smoke — secure sources should pass)
# ══════════════════════════════════════════════════════════════════

SAMPLE = os.urandom(50_000)

class TestStatisticalTests:
    def test_monobit_pass(self):
        result = monobit_test(SAMPLE)
        assert result["passed"], f"p={result['p_value']:.4f}"

    def test_chi_square_pass(self):
        result = chi_square_test(SAMPLE)
        assert result["passed"], f"p={result['p_value']:.4f}"

    def test_runs_pass(self):
        result = runs_test(SAMPLE)
        assert result["passed"], f"p={result['p_value']:.4f}"

    def test_autocorr_near_zero(self):
        ac = autocorrelation(SAMPLE, max_lag=10)
        assert all(abs(v) < 0.05 for v in ac), f"max |AC| = {max(abs(ac)):.4f}"

    def test_monobit_keys(self):
        r = monobit_test(b"\x00" * 100)
        assert {"ones", "zeros", "proportion", "p_value", "passed"} <= r.keys()

    def test_biased_fails_monobit(self):
        """All-zeros bytes → all 0-bits → monobit must fail."""
        r = monobit_test(b"\x00" * 10_000)
        assert not r["passed"]

    def test_biased_fails_chi(self):
        """Only byte 0x00 → chi-square must fail."""
        r = chi_square_test(b"\x00" * 10_000)
        assert not r["passed"]


# ══════════════════════════════════════════════════════════════════
# MT Attack
# ══════════════════════════════════════════════════════════════════

class TestMTAttack:
    def test_clone_requires_624(self):
        with pytest.raises(ValueError):
            MT19937Clone([0] * 100)

    def test_attack_succeeds(self):
        result = run_attack_simulation(seed=42, num_predictions=10)
        assert result.attack_succeeded, f"Accuracy: {result.accuracy:.2f}"

    def test_hash_prng_not_predictable(self):
        result = run_attack_simulation(seed=42, num_predictions=5)
        assert not result.hash_prng_predictable

    def test_hash_drbg_not_predictable(self):
        result = run_attack_simulation(seed=42, num_predictions=5)
        assert not result.hash_drbg_predictable
