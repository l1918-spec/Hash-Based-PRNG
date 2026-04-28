# 🔐 Hash-Based PRNG — Cryptography Portfolio Project

> A production-quality implementation of a **SHA-256 hash-chain PRNG** and a **NIST SP 800-90A Hash_DRBG**, with statistical validation, a live attack simulation against Python's Mersenne Twister, and a full interactive CLI.

---

## Table of Contents

1. [Overview](#overview)
2. [PRNG vs CSPRNG](#prng-vs-csprng)
3. [Architecture](#architecture)
4. [Modules](#modules)
5. [Installation](#installation)
6. [How to Run](#how-to-run)
7. [Statistical Dashboard](#statistical-dashboard)
8. [Attack Simulation](#attack-simulation)
9. [Security Analysis](#security-analysis)
10. [Running Tests](#running-tests)
11. [Exporting Results](#exporting-results)
12. [Conclusion](#conclusion)

---

## Overview

This project demonstrates the design, implementation, and security analysis of hash-based cryptographically secure pseudo-random number generators (CSPRNGs).

| Component | Description |
|-----------|-------------|
| `HashPRNG` | Simple SHA-256 hash-chain PRNG with forward secrecy |
| `HashDRBG` | Full NIST SP 800-90A Hash_DRBG (instantiate / generate / reseed) |
| `MT19937 Attack` | State-recovery attack against Python's `random` module |
| `Statistical Tests` | NIST monobit, chi-square, runs test, autocorrelation |
| `Dashboard` | 7-panel matplotlib comparison across all sources |
| `CLI` | Interactive menu + oral demo mode |

---

## PRNG vs CSPRNG

```
PRNG  (Pseudo-Random Number Generator)
  ✓ Fast and deterministic
  ✓ Passes basic statistical tests
  ✗ Internal state can be reconstructed from output
  ✗ NOT safe for cryptographic use
  Example: Mersenne Twister (Python random module)

CSPRNG  (Cryptographically Secure PRNG)
  ✓ Computationally indistinguishable from true random
  ✓ Forward secrecy — past outputs reveal nothing about future
  ✓ Backward secrecy — future outputs reveal nothing about past
  ✓ Passes NIST Statistical Test Suite
  Example: HashPRNG (this project), Hash_DRBG, os.urandom
```

### Why SHA-256?

SHA-256 is a **one-way function**:

```
Given H = SHA-256(X)  →  finding X is computationally infeasible
```

This property guarantees that even if an attacker observes outputs of our PRNG, they cannot reverse the hash to recover the internal state.

---

## Architecture

```
hash-prng/
├── main.py                    ← Entry point (CLI + flags)
│
├── core/
│   ├── prng_simple.py         ← HashPRNG: SHA-256 hash-chain
│   ├── hash_drbg.py           ← HashDRBG: NIST SP 800-90A
│   └── statistical_tests.py   ← Monobit, Chi², Runs, Autocorrelation
│
├── attacks/
│   └── mt_attack.py           ← MT19937 full state-recovery attack
│
├── ui/
│   ├── cli.py                 ← Interactive CLI + demo mode
│   └── visualizer.py          ← 7-panel matplotlib dashboard
│
├── tests/
│   └── test_core.py           ← pytest unit tests (30+ cases)
│
├── exports/
│   └── exporter.py            ← JSON / CSV export helpers
│
└── requirements.txt
```

### Data-flow: HashPRNG

```
seed ──► SHA-256 ──► state₀
                        │
              ┌─────────┴──────────┐
              │                    │
           SHA-256(state₀)   SHA-256(state₀ ‖ counter)
              │                    │
           output₀             state₁ ──► output₁ ──► …
```

### Data-flow: Hash_DRBG (NIST SP 800-90A)

```
entropy ‖ nonce ‖ personalization
        │
      Hash_df
        │
    ┌───┴───┐
    V       C          (55-byte working values)
    │
  generate() ──► Hashgen(V) ──► output
                    │
               update_state(V, C, counter)
```

---

## Modules

### `core/prng_simple.py` — HashPRNG

```python
from core.prng_simple import HashPRNG

prng = HashPRNG(seed=b"my secret")

prng.generate_bytes(32)        # → 32 pseudorandom bytes
prng.generate_int(1, 100)      # → int in [1, 100]
prng.generate_float()          # → float in [0.0, 1.0)
prng.reseed(b"new entropy")    # → inject fresh entropy
```

**Key properties:**
- Deterministic given the same seed
- Forward-secure (SHA-256 one-way chain)
- Rejection sampling for unbiased integer generation

---

### `core/hash_drbg.py` — Hash_DRBG

```python
from core.hash_drbg import HashDRBG

drbg = HashDRBG(
    entropy_input=os.urandom(32),
    nonce=os.urandom(16),
    personalization_string=b"my_app_v1",
)

drbg.generate(32)                            # 32 random bytes
drbg.generate(16, additional_input=b"ctx")  # domain separation
drbg.reseed()                                # auto-fetch new entropy
```

**NIST compliance:**
- Seed length: 55 bytes (per SP 800-90A table)
- Max bytes per request: 7 500
- Reseed interval: 2⁴⁸ calls
- Security strength: 256 bits

---

### `attacks/mt_attack.py` — MT19937 State Recovery

```python
from attacks.mt_attack import run_attack_simulation

result = run_attack_simulation(seed=42, num_predictions=20)
print(result.accuracy)         # 1.0 → 100% prediction accuracy
print(result.attack_succeeded) # True
```

**Attack steps:**
1. Observe 624 consecutive `getrandbits(32)` outputs
2. Invert the MT tempering function for each output
3. Reconstruct the full 19937-bit internal state
4. Predict all future outputs with 100% accuracy

---

### `core/statistical_tests.py`

| Test | Standard | What it checks |
|------|----------|----------------|
| Monobit | NIST SP 800-22 §2.1 | Equal 0- and 1-bits overall |
| Chi-Square | Pearson | Uniform byte distribution |
| Runs | NIST SP 800-22 §2.3 | Oscillation speed of bit sequences |
| Autocorrelation | — | Serial independence across lags |

---

## Installation

```bash
# Clone
git clone https://github.com/your-username/hash-prng.git
cd hash-prng

# Create virtual environment
python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

**Requirements:** Python 3.11+, numpy, matplotlib, scipy, pytest

---

## How to Run

### Interactive CLI (recommended)

```bash
python main.py
```

Menu options:
```
[1] Generate random data          → bytes / int / float, save to file
[2] Compare all sources           → side-by-side hex preview
[3] Run statistical tests         → tabular NIST results + export
[4] Generate visual dashboard     → 7-panel PNG
[5] MT19937 attack simulation     → live state-recovery demo
[6] Oral demo mode                → paced walkthrough for presentation
```

### Direct flags

```bash
python main.py --demo              # oral presentation walkthrough
python main.py --stats             # statistical tests only
python main.py --attack            # attack simulation only
python main.py --dashboard         # generate PNG and exit
python main.py --dashboard --sample-size 200000 --output out.png
```

### Module standalone

```bash
python core/prng_simple.py         # HashPRNG smoke-test
python core/hash_drbg.py           # HashDRBG smoke-test
python attacks/mt_attack.py        # MT attack results
python ui/visualizer.py            # stats report + PNG
```

---

## Statistical Dashboard

Running `python main.py --dashboard` produces a 7-panel PNG:

| Panel | Content |
|-------|---------|
| Top-left | Byte distribution histogram — HashPRNG |
| Top-right | Byte distribution histogram — Hash_DRBG |
| Mid-left | Autocorrelation (lags 1–50) for all sources |
| Mid-right | Shannon entropy heatmap (256-byte blocks) |
| Bot-left | Monobit p-values (bar chart) |
| Bot-right | Chi-square p-values (bar chart) |
| Full-width | 1-bit proportion comparison |

Expected results (100 000 bytes, p-value ≥ 0.01 = PASS):

| Source | Monobit | Chi² | Runs | Secure? |
|--------|---------|------|------|---------|
| HashPRNG | ✓ PASS | ✓ PASS | ✓ PASS | ✓ Yes |
| Hash_DRBG | ✓ PASS | ✓ PASS | ✓ PASS | ✓ Yes |
| os.urandom | ✓ PASS | ✓ PASS | ✓ PASS | ✓ Yes |
| MT19937 | ✓ PASS | ✓ PASS | ✓ PASS | ✗ No* |

> *MT19937 passes statistical tests but is NOT cryptographically secure — its state is fully recoverable after 624 observations.

---

## Attack Simulation

### Why Mersenne Twister is Broken for Cryptography

Python's `random` module uses **MT19937**, whose entire 19937-bit state can be reconstructed from 624 consecutive 32-bit outputs.

```
Attacker observes:  r₁, r₂, …, r₆₂₄   (624 getrandbits(32) outputs)
Attacker computes:  untemper(rᵢ) for each i   (inverts MT tempering)
Attacker has:       full internal state
Attacker predicts:  r₆₂₅, r₆₂₆, …   with 100% accuracy
```

**Demonstration output:**
```
  #     Predicted       Actual    Match?
   1  0x3B4A21C0  0x3B4A21C0       ✓
   2  0xF2E8D931  0xF2E8D931       ✓
  …
  20  0x7C1A0053  0x7C1A0053       ✓

  Accuracy: 20/20 (100%)  ← MT is fully broken!

  HashPRNG : ✓ SECURE — SHA-256 hides internal state
  HashDRBG : ✓ SECURE — NIST DRBG standard
```

### Why HashPRNG and HashDRBG are Immune

Even with 624 observed outputs of HashPRNG, an attacker would need to:

```
Invert SHA-256(state) → state     (computationally infeasible)
```

The security reduces to the **preimage resistance** of SHA-256, which has no known attack faster than brute force (2²⁵⁶ operations).

---

## Running Tests

```bash
# Run all tests
python -m pytest tests/ -v

# Run a specific class
python -m pytest tests/test_core.py::TestHashPRNG -v
python -m pytest tests/test_core.py::TestMTAttack -v

# Run with coverage
pip install pytest-cov
python -m pytest tests/ --cov=core --cov=attacks --cov-report=term-missing
```

**Test coverage includes:**
- HashPRNG: determinism, avalanche, range, output count, reseed
- HashDRBG: successive outputs, additional input, reseed counter, limits
- Statistical tests: pass on secure data, fail on biased data
- MT Attack: clone correctness, 100% prediction accuracy, resistance check

---

## Exporting Results

From the CLI (option 3 or 5), select `j` for JSON or `c` for CSV.

**JSON structure:**
```json
{
  "generated_at": "2025-01-15T14:32:00",
  "sample_size_bytes": 100000,
  "sources": {
    "HashPRNG": {
      "monobit":    { "p_value": 0.7231, "passed": true },
      "chi_square": { "p_value": 0.4812, "passed": true },
      "runs":       { "p_value": 0.3940, "passed": true },
      "overall_passed": true
    }
  }
}
```

---

## Security Analysis

### Security Model

The security of HashPRNG and Hash_DRBG rests on a single assumption:

> **SHA-256 is a computationally secure one-way function.**

Given this assumption:

| Property | HashPRNG | Hash_DRBG |
|----------|----------|-----------|
| Forward secrecy | ✓ | ✓ |
| Backward secrecy | Partial | ✓ (reseed) |
| State recovery resistance | ✓ | ✓ |
| NIST compliance | — | ✓ SP 800-90A |
| Side-channel resistance | ✗ | ✗ |

### Limitations

- No side-channel or timing-attack hardening (out of scope)
- No hardware RNG integration
- HashPRNG is not NIST-approved (use Hash_DRBG for production)

---

## Conclusion

This project demonstrates:

1. **Correct implementation** of a SHA-256 hash-chain PRNG and the NIST SP 800-90A Hash_DRBG standard.
2. **Statistical validation** — output is indistinguishable from true random under NIST tests.
3. **Attack awareness** — Python's `random` module is fully broken for cryptographic use; HashPRNG and HashDRBG are provably resistant.
4. **Software engineering** — modular architecture, full typing, docstrings, 30+ unit tests, interactive CLI.

**Use `os.urandom()`, `secrets`, or a NIST-approved DRBG for any cryptographic application. Never use `random.random()`.**

---

*Built for the Cryptography & Security module — University Portfolio Project 2025.*
