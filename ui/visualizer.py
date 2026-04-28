"""
ui/visualizer.py
────────────────────────────────────────────────────────────────
Advanced statistical dashboard for PRNG comparison.

Generates a multi-panel figure comparing HashPRNG, Hash_DRBG,
os.urandom, and the insecure Mersenne Twister on:
  • Byte-value distribution (histogram)
  • Autocorrelation (lags 1–50)
  • Monobit p-values
  • Chi-square p-values
  • Bit-proportion comparison
  • Entropy heatmap

Usage
-----
    from ui.visualizer import generate_dashboard
    generate_dashboard(sample_size=100_000, output_path="results.png")
"""

from __future__ import annotations

import os
import random as stdlib_random
import sys
from typing import Callable

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
import matplotlib.patches as mpatches
from matplotlib.colors import LinearSegmentedColormap
import numpy as np
from scipy import stats

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from core.prng_simple import HashPRNG
from core.hash_drbg import HashDRBG
from core.statistical_tests import (
    monobit_test,
    chi_square_test,
    runs_test,
    autocorrelation,
)

# ══════════════════════════════════════════════════════════════════
# Colour palette — dark "terminal" theme
# ══════════════════════════════════════════════════════════════════

PALETTE = {
    "bg_fig":      "#0D1117",
    "bg_ax":       "#161B22",
    "spine":       "#30363D",
    "tick":        "#8B949E",
    "text":        "#E6EDF3",
    "text_dim":    "#8B949E",
    "hash_prng":   "#58A6FF",   # blue
    "hash_drbg":   "#3FB950",   # green
    "os_random":   "#F78166",   # orange-red
    "stdlib_mt":   "#FF7B72",   # red
    "ideal":       "#6E7681",   # grey
    "threshold":   "#F85149",   # bright red
    "accent":      "#E3B341",   # gold
}

SOURCES = ["HashPRNG", "Hash_DRBG", "os.urandom", "MT19937 (insecure)"]
SOURCE_COLORS = [
    PALETTE["hash_prng"],
    PALETTE["hash_drbg"],
    PALETTE["os_random"],
    PALETTE["stdlib_mt"],
]


# ══════════════════════════════════════════════════════════════════
# Data generators
# ══════════════════════════════════════════════════════════════════

def _get_hash_prng(n: int) -> bytes:
    return HashPRNG(seed=b"stats_test_seed").generate_bytes(n)


def _get_hash_drbg(n: int) -> bytes:
    drbg = HashDRBG(personalization_string=b"stats_test")
    result = bytearray()
    while len(result) < n:
        chunk = min(7500, n - len(result))
        result.extend(drbg.generate(chunk))
    return bytes(result)


def _get_os_random(n: int) -> bytes:
    return os.urandom(n)


def _get_stdlib_mt(n: int) -> bytes:
    stdlib_random.seed(42)
    return bytes([stdlib_random.randint(0, 255) for _ in range(n)])


GENERATORS: dict[str, Callable[[int], bytes]] = {
    "HashPRNG":            _get_hash_prng,
    "Hash_DRBG":           _get_hash_drbg,
    "os.urandom":          _get_os_random,
    "MT19937 (insecure)":  _get_stdlib_mt,
}


# ══════════════════════════════════════════════════════════════════
# Axis styling helper
# ══════════════════════════════════════════════════════════════════

def _style_ax(ax: plt.Axes) -> None:
    ax.set_facecolor(PALETTE["bg_ax"])
    for spine in ax.spines.values():
        spine.set_edgecolor(PALETTE["spine"])
        spine.set_linewidth(0.8)
    ax.tick_params(colors=PALETTE["tick"], labelsize=8, length=3)
    ax.xaxis.label.set_color(PALETTE["text_dim"])
    ax.yaxis.label.set_color(PALETTE["text_dim"])
    ax.title.set_color(PALETTE["text"])


def _legend(ax: plt.Axes, **kwargs) -> None:
    leg = ax.legend(
        fontsize=7.5,
        facecolor="#21262D",
        edgecolor=PALETTE["spine"],
        labelcolor=PALETTE["text"],
        **kwargs,
    )
    leg.get_frame().set_linewidth(0.8)


# ══════════════════════════════════════════════════════════════════
# Individual panel renderers
# ══════════════════════════════════════════════════════════════════

def _plot_histogram(ax: plt.Axes, data: bytes, color: str, title: str) -> None:
    """Byte-value frequency histogram with ideal line and σ annotation."""
    counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    ideal = len(data) / 256

    ax.bar(range(256), counts, color=color, alpha=0.70, width=1.0, zorder=2)
    ax.axhline(ideal, color=PALETTE["ideal"], linestyle="--",
               linewidth=1.2, label=f"Ideal ({ideal:.0f})", zorder=3)

    std = counts.std()
    cv = std / ideal * 100
    ax.text(
        0.98, 0.95,
        f"σ = {std:.1f}\nCV = {cv:.2f}%",
        transform=ax.transAxes, ha="right", va="top",
        color=PALETTE["accent"], fontsize=8.5, fontfamily="monospace",
        bbox=dict(boxstyle="round,pad=0.4", facecolor="#21262D", alpha=0.85),
    )
    ax.set_title(title, fontsize=11, fontweight="bold", pad=6)
    ax.set_xlabel("Byte value (0–255)")
    ax.set_ylabel("Frequency")
    ax.set_xlim(0, 255)
    _legend(ax)
    _style_ax(ax)


def _plot_autocorr(ax: plt.Axes, all_data: dict[str, bytes]) -> None:
    """Normalised autocorrelation for lags 1–50 across all sources."""
    max_lag = 50
    for name, color in zip(SOURCES, SOURCE_COLORS):
        ac = autocorrelation(all_data[name], max_lag=max_lag)
        ax.plot(range(1, max_lag + 1), ac, color=color,
                alpha=0.9, linewidth=1.4, label=name)

    ax.axhline(0,    color="white",           linestyle="-",  linewidth=0.4, alpha=0.3)
    ax.axhline( 0.05, color=PALETTE["accent"], linestyle=":",  linewidth=1.0,
                label="±5% threshold", alpha=0.7)
    ax.axhline(-0.05, color=PALETTE["accent"], linestyle=":",  linewidth=1.0, alpha=0.7)

    ax.set_title("Autocorrelation (Lags 1–50)", fontsize=11, fontweight="bold", pad=6)
    ax.set_xlabel("Lag")
    ax.set_ylabel("Correlation coefficient")
    _legend(ax, loc="upper right")
    _style_ax(ax)


def _plot_pvalue_bars(
    ax: plt.Axes,
    p_values: list[float],
    title: str,
    ylabel: str,
) -> None:
    """Grouped bar chart for p-values with NIST threshold line."""
    x = np.arange(len(SOURCES))
    bars = ax.bar(x, p_values, color=SOURCE_COLORS, alpha=0.85,
                  edgecolor=PALETTE["spine"], width=0.55, zorder=2)

    ax.axhline(0.01, color=PALETTE["threshold"], linestyle="--",
               linewidth=1.8, label="NIST threshold (p=0.01)", zorder=3)

    ax.set_title(title, fontsize=11, fontweight="bold", pad=6)
    ax.set_ylabel(ylabel)
    ax.set_xticks(x)
    ax.set_xticklabels(
        [n.replace(" (", "\n(").replace("MT19937\n", "MT19937\n") for n in SOURCES],
        fontsize=8,
    )

    for bar, pv in zip(bars, p_values):
        colour = PALETTE["accent"] if pv >= 0.01 else PALETTE["threshold"]
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + max(p_values) * 0.02,
            f"{pv:.3f}",
            ha="center", va="bottom",
            color=colour, fontsize=8.5, fontweight="bold", fontfamily="monospace",
        )

    _legend(ax, loc="upper right")
    _style_ax(ax)


def _plot_bit_proportion(ax: plt.Axes, proportions: list[float]) -> None:
    """Bit-proportion comparison with ideal 50% line."""
    x = np.arange(len(SOURCES))
    bars = ax.bar(x, proportions, color=SOURCE_COLORS, alpha=0.85,
                  edgecolor=PALETTE["spine"], width=0.55, zorder=2)

    ax.axhline(0.5, color=PALETTE["ideal"], linestyle="--",
               linewidth=1.8, label="Ideal: 50.000%", zorder=3)
    ax.set_ylim(0.488, 0.512)

    ax.set_title("1-bit Proportion — All Sources", fontsize=11, fontweight="bold", pad=6)
    ax.set_ylabel("Proportion of 1-bits")
    ax.set_xticks(x)
    ax.set_xticklabels(
        [n.replace(" (", "\n(") for n in SOURCES], fontsize=8,
    )

    for bar, prop in zip(bars, proportions):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + 0.0003,
            f"{prop:.5f}",
            ha="center", va="bottom",
            color=PALETTE["accent"], fontsize=8.5, fontweight="bold",
            fontfamily="monospace",
        )

    _legend(ax)
    _style_ax(ax)


def _plot_entropy_heatmap(ax: plt.Axes, all_data: dict[str, bytes]) -> None:
    """
    Shannon entropy heatmap: each source × each 256-byte block.

    Colour = local entropy (bits per byte).  True random ≈ 8.0.
    """
    block_size = 256
    matrix: list[list[float]] = []

    for name in SOURCES:
        data = all_data[name]
        n_blocks = len(data) // block_size
        row: list[float] = []
        for b in range(n_blocks):
            block = data[b * block_size : (b + 1) * block_size]
            counts = np.bincount(np.frombuffer(block, dtype=np.uint8), minlength=256)
            probs = counts[counts > 0] / block_size
            entropy = float(-np.sum(probs * np.log2(probs)))
            row.append(entropy)
        matrix.append(row[:500])  # cap at 500 blocks for readability

    mat = np.array(matrix)

    cmap = LinearSegmentedColormap.from_list(
        "entropy",
        ["#FF4444", "#FF9800", "#4CAF50", "#00BCD4"],
        N=256,
    )

    im = ax.imshow(
        mat,
        aspect="auto",
        cmap=cmap,
        vmin=5.0,
        vmax=8.0,
        interpolation="nearest",
    )

    cbar = plt.colorbar(im, ax=ax, fraction=0.04, pad=0.02)
    cbar.set_label("Shannon entropy (bits/byte)", color=PALETTE["text_dim"], fontsize=8)
    cbar.ax.tick_params(colors=PALETTE["tick"], labelsize=7)

    ax.set_title("Local Entropy Heatmap (256-byte blocks)", fontsize=11,
                 fontweight="bold", pad=6)
    ax.set_yticks(range(len(SOURCES)))
    ax.set_yticklabels(SOURCES, fontsize=8)
    ax.set_xlabel("Block index")
    _style_ax(ax)


# ══════════════════════════════════════════════════════════════════
# Main dashboard
# ══════════════════════════════════════════════════════════════════

def generate_dashboard(
    sample_size: int = 100_000,
    output_path: str = "statistical_results.png",
    dpi: int = 150,
    progress_callback: Callable[[str], None] | None = None,
) -> str:
    """
    Generate the full 7-panel statistical dashboard.

    Parameters
    ----------
    sample_size : int
        Bytes to sample from each generator (default 100 000).
    output_path : str
        Destination file path (PNG recommended).
    dpi : int
        Resolution (default 150).
    progress_callback : callable, optional
        Status updates during long computation.

    Returns
    -------
    str
        Absolute path to the saved image.
    """

    def log(msg: str) -> None:
        if progress_callback:
            progress_callback(msg)

    # ── Sample data ────────────────────────────────────────────
    log("Sampling data from all generators…")
    all_data: dict[str, bytes] = {}
    for name, gen in GENERATORS.items():
        log(f"  Generating {sample_size:,} bytes — {name}")
        all_data[name] = gen(sample_size)

    # ── Compute statistics ─────────────────────────────────────
    log("Running statistical tests…")
    mb_results  = {n: monobit_test(all_data[n])    for n in SOURCES}
    chi_results = {n: chi_square_test(all_data[n]) for n in SOURCES}

    p_values_mb    = [mb_results[n]["p_value"]   for n in SOURCES]
    p_values_chi   = [chi_results[n]["p_value"]  for n in SOURCES]
    bit_proportions = [mb_results[n]["proportion"] for n in SOURCES]

    # ── Layout ─────────────────────────────────────────────────
    log("Rendering dashboard…")
    fig = plt.figure(figsize=(20, 26), facecolor=PALETTE["bg_fig"])
    fig.suptitle(
        "Hash-Based PRNG — Statistical Analysis Dashboard",
        fontsize=24, fontweight="bold", color=PALETTE["text"],
        y=0.985, fontfamily="DejaVu Sans",
    )

    # Subtitle / legend strip
    legend_handles = [
        mpatches.Patch(color=c, label=n)
        for n, c in zip(SOURCES, SOURCE_COLORS)
    ]
    fig.legend(
        handles=legend_handles,
        loc="upper center",
        bbox_to_anchor=(0.5, 0.972),
        ncol=4,
        fontsize=9,
        facecolor="#21262D",
        edgecolor=PALETTE["spine"],
        labelcolor=PALETTE["text"],
        framealpha=0.9,
    )

    gs = gridspec.GridSpec(
        4, 2,
        figure=fig,
        hspace=0.50,
        wspace=0.30,
        top=0.945, bottom=0.04,
        left=0.07, right=0.97,
    )

    ax_hist_prng  = fig.add_subplot(gs[0, 0])
    ax_hist_drbg  = fig.add_subplot(gs[0, 1])
    ax_autocorr   = fig.add_subplot(gs[1, 0])
    ax_entropy    = fig.add_subplot(gs[1, 1])
    ax_monobit    = fig.add_subplot(gs[2, 0])
    ax_chi        = fig.add_subplot(gs[2, 1])
    ax_bitprop    = fig.add_subplot(gs[3, :])

    # ── Render panels ──────────────────────────────────────────
    _plot_histogram(ax_hist_prng, all_data["HashPRNG"],
                    PALETTE["hash_prng"], "Byte Distribution — HashPRNG (SHA-256)")
    _plot_histogram(ax_hist_drbg, all_data["Hash_DRBG"],
                    PALETTE["hash_drbg"], "Byte Distribution — Hash_DRBG (NIST SP 800-90A)")
    _plot_autocorr(ax_autocorr, all_data)
    _plot_entropy_heatmap(ax_entropy, all_data)
    _plot_pvalue_bars(ax_monobit, p_values_mb,
                      "Monobit Test — p-values", "p-value (higher → more random)")
    _plot_pvalue_bars(ax_chi, p_values_chi,
                      "Chi-Square Uniformity — p-values", "p-value (higher → more uniform)")
    _plot_bit_proportion(ax_bitprop, bit_proportions)

    # ── Footer ─────────────────────────────────────────────────
    fig.text(
        0.5, 0.010,
        f"Sample size: {sample_size:,} bytes ({sample_size * 8:,} bits) per source  |  "
        "NIST pass threshold: p ≥ 0.01  |  Hash-Based PRNG Portfolio Project",
        ha="center", va="bottom",
        color=PALETTE["text_dim"], fontsize=8,
    )

    output_path = os.path.abspath(output_path)
    plt.savefig(output_path, dpi=dpi, bbox_inches="tight",
                facecolor=fig.get_facecolor())
    plt.close(fig)
    log(f"Dashboard saved → {output_path}")
    return output_path


# ══════════════════════════════════════════════════════════════════
# Full text report
# ══════════════════════════════════════════════════════════════════

def print_full_report(sample_size: int = 100_000) -> None:
    """Print a tabular statistical report to stdout."""
    print("\n" + "=" * 68)
    print("  STATISTICAL TEST REPORT")
    print(f"  Sample: {sample_size:,} bytes ({sample_size * 8:,} bits) per source")
    print("=" * 68)

    for name, gen in GENERATORS.items():
        data = gen(sample_size)
        mb   = monobit_test(data)
        chi  = chi_square_test(data)
        runs = runs_test(data)

        ok_mb   = "✓ PASS" if mb["passed"]   else "✗ FAIL"
        ok_chi  = "✓ PASS" if chi["passed"]  else "✗ FAIL"
        ok_runs = "✓ PASS" if runs["passed"] else "✗ FAIL"

        print(f"\n  [{name}]")
        print(f"    Monobit   : {ok_mb}  (p = {mb['p_value']:.6f})  "
              f"1-bit ratio = {mb['proportion']:.5f}")
        print(f"    Chi-Square: {ok_chi}  (p = {chi['p_value']:.6f})  "
              f"χ² = {chi['chi2_stat']:.2f}")
        print(f"    Runs Test : {ok_runs}  (p = {runs['p_value']:.6f})  "
              f"runs = {runs['runs_count']:,}")

    print("\n  p ≥ 0.01 → PASS (NIST threshold)")
    print("=" * 68 + "\n")


if __name__ == "__main__":
    print_full_report()
    generate_dashboard(
        sample_size=100_000,
        output_path="statistical_results.png",
        progress_callback=lambda m: print(f"  {m}"),
    )
