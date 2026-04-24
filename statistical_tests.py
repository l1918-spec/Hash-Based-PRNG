

import os
import random as stdlib_random
from typing import Callable
import math

import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
from scipy import stats

from prng_simple import HashPRNG
from hash_drbg import HashDRBG




SAMPLE_SIZE   = 100_000
FIGURE_DPI    = 150
OUTPUT_FILE   = "statistical_results.png"

COLORS = {
    "hash_prng": "#2196F3",
    "hash_drbg": "#4CAF50",
    "os_random" : "#FF9800",
    "stdlib"    : "#F44336",
    "ideal"     : "#9E9E9E",
}



def get_bytes_hash_prng(n: int) -> bytes:
    prng = HashPRNG(seed=b"stats_test_seed")
    return prng.generate_bytes(n)


def get_bytes_hash_drbg(n: int) -> bytes:
    drbg = HashDRBG(personalization_string=b"stats_test")
    result = bytearray()
    while len(result) < n:
        chunk = min(7500, n - len(result))
        result.extend(drbg.generate(chunk))
    return bytes(result)


def get_bytes_os_random(n: int) -> bytes:
    return os.urandom(n)


def get_bytes_stdlib_random(n: int) -> bytes:

    stdlib_random.seed(42)
    return bytes([stdlib_random.randint(0, 255) for _ in range(n)])


GENERATORS: dict[str, Callable[[int], bytes]] = {
    "HashPRNG (SHA-256)"    : get_bytes_hash_prng,
    "Hash_DRBG (NIST)"      : get_bytes_hash_drbg,
    "os.urandom (OS)"        : get_bytes_os_random,
    "random.random (INSECURE)": get_bytes_stdlib_random,
}

GENERATOR_COLORS = {
    "HashPRNG (SHA-256)"    : COLORS["hash_prng"],
    "Hash_DRBG (NIST)"      : COLORS["hash_drbg"],
    "os.urandom (OS)"        : COLORS["os_random"],
    "random.random (INSECURE)": COLORS["stdlib"],
}


def monobit_test(data: bytes) -> dict:

    bits = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)

    n = len(bits)
    ones  = sum(bits)
    zeros = n - ones

    s_n = ones - zeros

    s_obs = abs(s_n) / math.sqrt(n)


    p_value = math.erfc(s_obs / math.sqrt(2))

    return {
        "ones"      : ones,
        "zeros"     : zeros,
        "proportion": ones / n,
        "s_obs"     : s_obs,
        "p_value"   : p_value,
        "passed"    : p_value >= 0.01,
    }


def chi_square_test(data: bytes) -> dict:

    observed = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    expected = np.full(256, len(data) / 256)

    chi2_stat, p_value = stats.chisquare(observed, expected)

    return {
        "chi2_stat": chi2_stat,
        "p_value"  : p_value,
        "passed"   : p_value >= 0.01,
    }


def autocorrelation(data: bytes, max_lag: int = 50) -> np.ndarray:

    arr = np.frombuffer(data, dtype=np.uint8).astype(float)
    arr -= arr.mean()

    full_corr = np.correlate(arr, arr, mode="full")
    full_corr /= full_corr[len(arr) - 1]

    mid = len(arr) - 1
    return full_corr[mid + 1 : mid + 1 + max_lag]


def plot_all_results(sample_size: int = SAMPLE_SIZE) -> None:

    print(f"\nGenerating {sample_size:,} bytes from each source...\n")

    all_data: dict[str, bytes] = {}
    for name, gen in GENERATORS.items():
        print(f"  Sampling: {name}")
        all_data[name] = gen(sample_size)


    fig = plt.figure(figsize=(18, 20), facecolor="#0D1117")
    fig.suptitle(
        "Hash-Based PRNG — Statistical Analysis Dashboard",
        fontsize=22, fontweight="bold", color="white", y=0.98
    )

    gs = gridspec.GridSpec(
        3, 2,
        figure=fig,
        hspace=0.45,
        wspace=0.3,
        top=0.93, bottom=0.05, left=0.07, right=0.97
    )

    ax_hist_prng  = fig.add_subplot(gs[0, 0])
    ax_hist_drbg  = fig.add_subplot(gs[0, 1])
    ax_autocorr   = fig.add_subplot(gs[1, 0])
    ax_monobit    = fig.add_subplot(gs[1, 1])
    ax_chi        = fig.add_subplot(gs[2, 0])
    ax_comparison = fig.add_subplot(gs[2, 1])

    style = dict(facecolor="#161B22", edgecolor="#30363D")
    for ax in [ax_hist_prng, ax_hist_drbg, ax_autocorr,
               ax_monobit, ax_chi, ax_comparison]:
        ax.set_facecolor(style["facecolor"])
        for spine in ax.spines.values():
            spine.set_edgecolor(style["edgecolor"])
        ax.tick_params(colors="white", labelsize=9)
        ax.xaxis.label.set_color("white")
        ax.yaxis.label.set_color("white")
        ax.title.set_color("white")

    ideal_line_style = dict(color=COLORS["ideal"], linestyle="--",
                            linewidth=1.5, label="Ideal uniform")


    for ax, name, color, title in [
        (ax_hist_prng, "HashPRNG (SHA-256)",  COLORS["hash_prng"],
         "Byte Distribution — HashPRNG"),
        (ax_hist_drbg, "Hash_DRBG (NIST)",    COLORS["hash_drbg"],
         "Byte Distribution — Hash_DRBG"),
    ]:
        counts = np.bincount(
            np.frombuffer(all_data[name], dtype=np.uint8), minlength=256
        )
        ax.bar(range(256), counts, color=color, alpha=0.75, width=1.0)
        ideal_freq = sample_size / 256
        ax.axhline(ideal_freq, **ideal_line_style)
        ax.set_title(title, fontsize=12, fontweight="bold")
        ax.set_xlabel("Byte Value (0–255)", fontsize=9)
        ax.set_ylabel("Frequency", fontsize=9)
        ax.set_xlim(0, 255)
        ax.legend(fontsize=8, facecolor="#21262D", labelcolor="white")
        # Annotate std dev
        std = counts.std()
        ax.text(
            0.98, 0.95, f"σ = {std:.1f}",
            transform=ax.transAxes, ha="right", va="top",
            color="white", fontsize=10,
            bbox=dict(boxstyle="round,pad=0.3", facecolor="#21262D", alpha=0.8)
        )

    max_lag = 50
    for name, color in GENERATOR_COLORS.items():
        ac = autocorrelation(all_data[name], max_lag=max_lag)
        ax_autocorr.plot(range(1, max_lag + 1), ac, color=color,
                         alpha=0.9, linewidth=1.5, label=name)

    ax_autocorr.axhline(0, color="white", linestyle="-", linewidth=0.5, alpha=0.4)
    ax_autocorr.axhline( 0.05, color="#FFEB3B", linestyle=":", linewidth=1,
                         label="±5% threshold", alpha=0.6)
    ax_autocorr.axhline(-0.05, color="#FFEB3B", linestyle=":", linewidth=1, alpha=0.6)
    ax_autocorr.set_title("Autocorrelation (Lags 1–50)", fontsize=12, fontweight="bold")
    ax_autocorr.set_xlabel("Lag", fontsize=9)
    ax_autocorr.set_ylabel("Correlation", fontsize=9)
    ax_autocorr.legend(fontsize=7.5, facecolor="#21262D", labelcolor="white")


    names       = list(GENERATORS.keys())
    p_values_mb = [monobit_test(all_data[n])["p_value"] for n in names]
    bar_colors  = [GENERATOR_COLORS[n] for n in names]

    bars = ax_monobit.bar(
        range(len(names)), p_values_mb,
        color=bar_colors, alpha=0.85, edgecolor="#30363D"
    )
    ax_monobit.axhline(
        0.01, color="#F44336", linestyle="--", linewidth=2,
        label="NIST threshold (p=0.01)"
    )
    ax_monobit.set_title("Monobit Test — p-values", fontsize=12, fontweight="bold")
    ax_monobit.set_ylabel("p-value (higher = more random)", fontsize=9)
    ax_monobit.set_xticks(range(len(names)))
    ax_monobit.set_xticklabels(
        [n.replace(" (", "\n(") for n in names], fontsize=8
    )
    ax_monobit.legend(fontsize=8, facecolor="#21262D", labelcolor="white")
    for bar, pv in zip(bars, p_values_mb):
        ax_monobit.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + 0.01,
            f"{pv:.3f}", ha="center", va="bottom",
            color="white", fontsize=9, fontweight="bold"
        )


    p_values_chi = [chi_square_test(all_data[n])["p_value"] for n in names]

    bars2 = ax_chi.bar(
        range(len(names)), p_values_chi,
        color=bar_colors, alpha=0.85, edgecolor="#30363D"
    )
    ax_chi.axhline(
        0.01, color="#F44336", linestyle="--", linewidth=2,
        label="Significance threshold (p=0.01)"
    )
    ax_chi.set_title("Chi-Square Uniformity Test — p-values", fontsize=12, fontweight="bold")
    ax_chi.set_ylabel("p-value (higher = more uniform)", fontsize=9)
    ax_chi.set_xticks(range(len(names)))
    ax_chi.set_xticklabels(
        [n.replace(" (", "\n(") for n in names], fontsize=8
    )
    ax_chi.legend(fontsize=8, facecolor="#21262D", labelcolor="white")
    for bar, pv in zip(bars2, p_values_chi):
        ax_chi.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + 0.005,
            f"{pv:.3f}", ha="center", va="bottom",
            color="white", fontsize=9, fontweight="bold"
        )


    bit_props = [monobit_test(all_data[n])["proportion"] for n in names]

    bars3 = ax_comparison.bar(
        range(len(names)), bit_props,
        color=bar_colors, alpha=0.85, edgecolor="#30363D"
    )
    ax_comparison.axhline(
        0.5, color=COLORS["ideal"], linestyle="--",
        linewidth=2, label="Ideal: 50%"
    )
    ax_comparison.set_ylim(0.48, 0.52)
    ax_comparison.set_title("Bit Proportion (1-bits) — All Sources", fontsize=12, fontweight="bold")
    ax_comparison.set_ylabel("Proportion of 1-bits", fontsize=9)
    ax_comparison.set_xticks(range(len(names)))
    ax_comparison.set_xticklabels(
        [n.replace(" (", "\n(") for n in names], fontsize=8
    )
    ax_comparison.legend(fontsize=8, facecolor="#21262D", labelcolor="white")
    for bar, prop in zip(bars3, bit_props):
        ax_comparison.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + 0.0003,
            f"{prop:.4f}", ha="center", va="bottom",
            color="white", fontsize=9, fontweight="bold"
        )

    plt.savefig(OUTPUT_FILE, dpi=FIGURE_DPI, bbox_inches="tight",
                facecolor=fig.get_facecolor())
    plt.close()
    print(f"\n✓ Plot saved to: {OUTPUT_FILE}")



def print_full_report(sample_size: int = SAMPLE_SIZE) -> None:

    print("\n" + "=" * 65)
    print("  STATISTICAL TEST REPORT")
    print(f"  Sample size: {sample_size:,} bytes ({sample_size * 8:,} bits)")
    print("=" * 65)

    for name, gen in GENERATORS.items():
        data = gen(sample_size)
        mb   = monobit_test(data)
        chi  = chi_square_test(data)

        status_mb  = "✓ PASS" if mb["passed"]  else "✗ FAIL"
        status_chi = "✓ PASS" if chi["passed"] else "✗ FAIL"

        print(f"\n  [{name}]")
        print(f"    Monobit Test  : {status_mb}  (p = {mb['p_value']:.4f})")
        print(f"    1-bit ratio   : {mb['proportion']:.5f}  (ideal = 0.50000)")
        print(f"    Chi-Square    : {status_chi}  (p = {chi['p_value']:.4f})")
        print(f"    χ² statistic  : {chi['chi2_stat']:.2f}  (ideal ≈ 255)")

    print("\n" + "=" * 65)
    print("  NOTE: p-value ≥ 0.01 = pass (NIST threshold)")
    print("=" * 65 + "\n")



if __name__ == "__main__":
    print_full_report()
    plot_all_results()