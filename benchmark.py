"""
Offline benchmarks for the paper: CSV exports + matplotlib figures.

Mirrors the crypto flows in encryptionCompare_v1.py (fresh keygen each round,
same libraries). ML-KEM/ECDH timings do not depend on message length in the
current app; the message field is still accepted for API parity.

Usage:
  source .venv/bin/activate
  pip install -r requirements.txt
  python benchmark.py
  python benchmark.py --runs 50 --outdir results
"""

from __future__ import annotations

import argparse
import csv
import os
import platform
import statistics
import time
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from dilithium_py.ml_dsa import ML_DSA_44
from kyber_py.ml_kem import ML_KEM_768


def measure_sign_once(message: bytes) -> dict:
    """One signing round: new ML-DSA and ECDSA keys; sign + verify both."""
    # ML-DSA
    t0 = time.perf_counter()
    pk_ml, sk_ml = ML_DSA_44.keygen()
    t_key_ml = (time.perf_counter() - t0) * 1000.0

    t0 = time.perf_counter()
    sig_ml = ML_DSA_44.sign(sk_ml, message)
    t_sign_ml = (time.perf_counter() - t0) * 1000.0

    t0 = time.perf_counter()
    ML_DSA_44.verify(pk_ml, message, sig_ml)
    t_verify_ml = (time.perf_counter() - t0) * 1000.0

    # ECDSA
    t0 = time.perf_counter()
    ecdsa_private = ec.generate_private_key(ec.SECP256R1())
    ecdsa_public = ecdsa_private.public_key()
    t_key_ec = (time.perf_counter() - t0) * 1000.0

    t0 = time.perf_counter()
    sig_ec = ecdsa_private.sign(message, ec.ECDSA(hashes.SHA256()))
    t_sign_ec = (time.perf_counter() - t0) * 1000.0

    t0 = time.perf_counter()
    ecdsa_public.verify(sig_ec, message, ec.ECDSA(hashes.SHA256()))
    t_verify_ec = (time.perf_counter() - t0) * 1000.0

    ecdsa_pk_der = ecdsa_public.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return {
        "ml_dsa_keygen_ms": t_key_ml,
        "ml_dsa_sign_ms": t_sign_ml,
        "ml_dsa_verify_ms": t_verify_ml,
        "ml_dsa_sig_bytes": len(sig_ml),
        "ml_dsa_pk_bytes": len(pk_ml),
        "ecdsa_keygen_ms": t_key_ec,
        "ecdsa_sign_ms": t_sign_ec,
        "ecdsa_verify_ms": t_verify_ec,
        "ecdsa_sig_bytes": len(sig_ec),
        "ecdsa_pk_bytes": len(ecdsa_pk_der),
    }


def measure_kem_once(_message: bytes) -> dict:
    """One KEM / ECDH round (message unused, same as Flask route)."""
    t0 = time.perf_counter()
    ek, dk = ML_KEM_768.keygen()
    t_kem_keygen = (time.perf_counter() - t0) * 1000.0

    t0 = time.perf_counter()
    _ss, ct = ML_KEM_768.encaps(ek)
    t_encap = (time.perf_counter() - t0) * 1000.0

    t0 = time.perf_counter()
    ML_KEM_768.decaps(dk, ct)
    t_decap = (time.perf_counter() - t0) * 1000.0

    ecdh_private = ec.generate_private_key(ec.SECP256R1())
    ecdh_public = ecdh_private.public_key()

    t0 = time.perf_counter()
    ephemeral_private = ec.generate_private_key(ec.SECP256R1())
    t_ecdh_keygen = (time.perf_counter() - t0) * 1000.0

    t0 = time.perf_counter()
    ephemeral_private.exchange(ec.ECDH(), ecdh_public)
    t_ecdh_xchg = (time.perf_counter() - t0) * 1000.0

    ecdh_pk_der = ecdh_public.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return {
        "ml_kem_keygen_ms": t_kem_keygen,
        "ml_kem_encap_ms": t_encap,
        "ml_kem_decap_ms": t_decap,
        "ml_kem_ct_bytes": len(ct),
        "ml_kem_pk_bytes": len(ek),
        "ecdh_keygen_ms": t_ecdh_keygen,
        "ecdh_exchange_ms": t_ecdh_xchg,
        "ecdh_pk_bytes": len(ecdh_pk_der),
    }


def mean_std(values: list[float]) -> tuple[float, float]:
    if not values:
        return 0.0, 0.0
    m = statistics.mean(values)
    s = statistics.stdev(values) if len(values) > 1 else 0.0
    return m, s


def write_sizes_csv(path: Path, sign_sample: dict, kem_sample: dict) -> None:
    rows = [
        ("ECDSA signature", sign_sample["ecdsa_sig_bytes"]),
        ("ECDSA public key (DER SPKI)", sign_sample["ecdsa_pk_bytes"]),
        ("ML-DSA-44 signature", sign_sample["ml_dsa_sig_bytes"]),
        ("ML-DSA-44 public key", sign_sample["ml_dsa_pk_bytes"]),
        ("ML-KEM-768 ciphertext", kem_sample["ml_kem_ct_bytes"]),
        ("ML-KEM-768 public key (ek)", kem_sample["ml_kem_pk_bytes"]),
        ("ECDH public key (DER SPKI)", kem_sample["ecdh_pk_bytes"]),
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["artifact", "size_bytes"])
        w.writerows(rows)


def write_timings_csv(path: Path, timing_rows: list[tuple[str, str, float, float, int]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["operation", "algorithm", "mean_ms", "stdev_ms", "n_runs"])
        for op, algo, mean_ms, std_ms, n in timing_rows:
            w.writerow([op, algo, f"{mean_ms:.4f}", f"{std_ms:.4f}", n])


# Row order must match timing_table built in run_benchmark (11 rows).
_PAPER_TIMING_ROWS: list[tuple[str, str, str, str]] = [
    (
        "Digital signatures",
        "ML-DSA-44",
        "Key pair generation",
        "Generate one ML-DSA public/secret key pair (FIPS 204, ML-DSA-44).",
    ),
    (
        "Digital signatures",
        "ML-DSA-44",
        "Sign",
        "Sign a fixed UTF-8 benchmark message (same payload every run).",
    ),
    (
        "Digital signatures",
        "ML-DSA-44",
        "Verify",
        "Verify signature under the generated public key.",
    ),
    (
        "Digital signatures",
        "ECDSA (P-256)",
        "Key pair generation",
        "Generate one ECDSA key pair on curve SECP256R1.",
    ),
    (
        "Digital signatures",
        "ECDSA (P-256)",
        "Sign",
        "Sign the same benchmark message with SHA-256 (ECDSA).",
    ),
    (
        "Digital signatures",
        "ECDSA (P-256)",
        "Verify",
        "Verify ECDSA signature under the generated public key.",
    ),
    (
        "Key agreement",
        "ML-KEM-768",
        "Key pair generation",
        "Generate ML-KEM encapsulation/decapsulation key pair (FIPS 203, ML-KEM-768).",
    ),
    (
        "Key agreement",
        "ML-KEM-768",
        "Encapsulate",
        "From receiver public key: produce ciphertext and shared secret.",
    ),
    (
        "Key agreement",
        "ML-KEM-768",
        "Decapsulate",
        "From ciphertext + decapsulation key: recover shared secret.",
    ),
    (
        "Key agreement",
        "ECDH (P-256)",
        "Ephemeral key generation",
        "Generate ephemeral SECP256R1 key pair (mirrors demo flow).",
    ),
    (
        "Key agreement",
        "ECDH (P-256)",
        "Shared secret derivation",
        "ECDH exchange between ephemeral private key and peer static public key.",
    ),
]


def write_paper_timings_csv(
    path: Path,
    timing_rows: list[tuple[str, str, float, float, int]],
) -> None:
    """Wider CSV for reports: category, scheme, what was timed, mean ± stdev."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if len(timing_rows) != len(_PAPER_TIMING_ROWS):
        raise ValueError("timing_rows length mismatch with _PAPER_TIMING_ROWS")
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(
            [
                "category",
                "scheme",
                "step",
                "what_was_measured",
                "mean_ms",
                "stdev_ms",
                "n_runs",
            ]
        )
        for meta, (op, algo, mean_ms, std_ms, n) in zip(_PAPER_TIMING_ROWS, timing_rows):
            cat, scheme, step, desc = meta
            w.writerow([cat, scheme, step, desc, f"{mean_ms:.4f}", f"{std_ms:.4f}", n])


def write_paper_sizes_csv(path: Path, sign_sample: dict, kem_sample: dict) -> None:
    """Artifact sizes with bits and short notes for report tables."""
    rows: list[tuple[str, str, str, int, int, str]] = [
        (
            "Digital signatures",
            "ECDSA (P-256)",
            "Signature",
            sign_sample["ecdsa_sig_bytes"],
            sign_sample["ecdsa_sig_bytes"] * 8,
            "DER-encoded signature object (not message length).",
        ),
        (
            "Digital signatures",
            "ECDSA (P-256)",
            "Public key",
            sign_sample["ecdsa_pk_bytes"],
            sign_sample["ecdsa_pk_bytes"] * 8,
            "SubjectPublicKeyInfo DER (SECP256R1).",
        ),
        (
            "Digital signatures",
            "ML-DSA-44",
            "Signature",
            sign_sample["ml_dsa_sig_bytes"],
            sign_sample["ml_dsa_sig_bytes"] * 8,
            "Raw ML-DSA signature bytes.",
        ),
        (
            "Digital signatures",
            "ML-DSA-44",
            "Public key",
            sign_sample["ml_dsa_pk_bytes"],
            sign_sample["ml_dsa_pk_bytes"] * 8,
            "Raw ML-DSA public key bytes.",
        ),
        (
            "Key agreement",
            "ML-KEM-768",
            "Ciphertext",
            kem_sample["ml_kem_ct_bytes"],
            kem_sample["ml_kem_ct_bytes"] * 8,
            "Output of encapsulation (on-wire style payload).",
        ),
        (
            "Key agreement",
            "ML-KEM-768",
            "Public key (ek)",
            kem_sample["ml_kem_pk_bytes"],
            kem_sample["ml_kem_pk_bytes"] * 8,
            "ML-KEM encapsulation key.",
        ),
        (
            "Key agreement",
            "ECDH (P-256)",
            "Public key (static peer)",
            kem_sample["ecdh_pk_bytes"],
            kem_sample["ecdh_pk_bytes"] * 8,
            "Peer SPKI DER; ECDH has no ciphertext comparable to ML-KEM.",
        ),
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(
            [
                "category",
                "scheme",
                "artifact",
                "size_bytes",
                "size_bits",
                "note",
            ]
        )
        for row in rows:
            w.writerow(list(row))


def write_simple_report_tables(
    out_dir: Path,
    timing_table: list[tuple[str, str, float, float, int]],
    sign_sample: dict,
    kem_sample: dict,
) -> Path:
    """
    Human-readable tables with explicit titles + three small CSVs for Word/Excel.
    timing_table row order: ML-DSA×3, ECDSA×3, ML-KEM×3, ECDH×2 (11 rows).
    """
    if len(timing_table) != 11:
        raise ValueError("expected 11 timing rows")

    n_runs = timing_table[0][4]
    meta = platform.uname()
    env_line = (
        f"Environment: {meta.system} {meta.release} | Python {platform.python_version()} "
        f"| benchmark rounds N = {n_runs}"
    )

    def row_fmt(algo: str, op: str, mean: float, std: float) -> str:
        return f"{algo:<16} {op:<26} {mean:>10.4f} {std:>10.4f} {n_runs:>6}"

    # --- TABLE I: signatures (rows 0–5) ---
    sig_lines = [
        row_fmt("ML-DSA-44", "Key pair generation", timing_table[0][2], timing_table[0][3]),
        row_fmt("ML-DSA-44", "Sign message", timing_table[1][2], timing_table[1][3]),
        row_fmt("ML-DSA-44", "Verify signature", timing_table[2][2], timing_table[2][3]),
        row_fmt("ECDSA (P-256)", "Key pair generation", timing_table[3][2], timing_table[3][3]),
        row_fmt("ECDSA (P-256)", "Sign message", timing_table[4][2], timing_table[4][3]),
        row_fmt("ECDSA (P-256)", "Verify signature", timing_table[5][2], timing_table[5][3]),
    ]

    # --- TABLE II: key agreement (rows 6–10) ---
    kem_lines = [
        row_fmt("ML-KEM-768", "Key pair generation", timing_table[6][2], timing_table[6][3]),
        row_fmt("ML-KEM-768", "Encapsulate (ciphertext)", timing_table[7][2], timing_table[7][3]),
        row_fmt("ML-KEM-768", "Decapsulate (shared secret)", timing_table[8][2], timing_table[8][3]),
        row_fmt("ECDH (P-256)", "Ephemeral key generation", timing_table[9][2], timing_table[9][3]),
        row_fmt("ECDH (P-256)", "Derive shared secret", timing_table[10][2], timing_table[10][3]),
    ]

    size_rows: list[tuple[str, str, int, int, str]] = [
        (
            "ECDSA (P-256)",
            "Signature",
            sign_sample["ecdsa_sig_bytes"],
            sign_sample["ecdsa_sig_bytes"] * 8,
            "Length of signature bytes (not your message length).",
        ),
        (
            "ECDSA (P-256)",
            "Public key",
            sign_sample["ecdsa_pk_bytes"],
            sign_sample["ecdsa_pk_bytes"] * 8,
            "DER-encoded public key.",
        ),
        (
            "ML-DSA-44",
            "Signature",
            sign_sample["ml_dsa_sig_bytes"],
            sign_sample["ml_dsa_sig_bytes"] * 8,
            "Length of lattice signature.",
        ),
        (
            "ML-DSA-44",
            "Public key",
            sign_sample["ml_dsa_pk_bytes"],
            sign_sample["ml_dsa_pk_bytes"] * 8,
            "Lattice public key bytes.",
        ),
        (
            "ML-KEM-768",
            "Ciphertext",
            kem_sample["ml_kem_ct_bytes"],
            kem_sample["ml_kem_ct_bytes"] * 8,
            "What encapsulation sends (binary; often shown as base64 in the UI).",
        ),
        (
            "ML-KEM-768",
            "Public key (ek)",
            kem_sample["ml_kem_pk_bytes"],
            kem_sample["ml_kem_pk_bytes"] * 8,
            "Receiver encapsulation key size.",
        ),
        (
            "ECDH (P-256)",
            "Peer public key",
            kem_sample["ecdh_pk_bytes"],
            kem_sample["ecdh_pk_bytes"] * 8,
            "No KEM-style ciphertext; ECDH only exchanges keys then derives a secret.",
        ),
    ]

    header = f"{'Algorithm':<16} {'Operation':<26} {'Mean (ms)':>10} {'Std dev':>10} {'N':>6}"
    sep = "-" * 80

    txt_blocks = [
        "REPORT TABLES — Post-quantum vs classical comparison (from benchmark.py)",
        env_line,
        "",
        "How to read these tables:",
        "  • Mean / Std dev = wall-clock time in milliseconds, averaged over N runs.",
        "  • Each run generates new keys (except where the operation name describes one step only).",
        "  • TABLE III sizes are from one representative key generation (sizes are fixed by the algorithm).",
        "",
        sep,
        "TABLE I — Digital signatures: how long each step takes",
        sep,
        "Compares post-quantum ML-DSA-44 (FIPS 204) with classical ECDSA on curve P-256 (FIPS 186-4).",
        "",
        header,
        sep,
        *sig_lines,
        "",
        sep,
        "TABLE II — Key agreement: how long each step takes",
        sep,
        "Compares post-quantum ML-KEM-768 (FIPS 203) with classical ECDH on P-256.",
        "Encapsulate produces a ciphertext; decapsulate recovers the shared secret. ECDH has no ciphertext.",
        "",
        header,
        sep,
        *kem_lines,
        "",
        sep,
        "TABLE III — Size of each cryptographic output (bytes and bits)",
        sep,
        "Use this table for “how big is the signature / key / ciphertext on the wire.”",
        "",
        f"{'Algorithm':<16} {'Output':<22} {'Bytes':>8} {'Bits':>10}  Note",
        sep,
    ]
    for algo, out_name, b, bits, note in size_rows:
        txt_blocks.append(f"{algo:<16} {out_name:<22} {b:>8} {bits:>10}  {note}")

    txt_blocks.extend(["", sep, "End of tables", sep])

    out_txt = out_dir / "TABLES_FOR_REPORT.txt"
    out_txt.write_text("\n".join(txt_blocks), encoding="utf-8")

    sig_data = [
        ("ML-DSA-44", "Key pair generation", timing_table[0]),
        ("ML-DSA-44", "Sign message", timing_table[1]),
        ("ML-DSA-44", "Verify signature", timing_table[2]),
        ("ECDSA (P-256)", "Key pair generation", timing_table[3]),
        ("ECDSA (P-256)", "Sign message", timing_table[4]),
        ("ECDSA (P-256)", "Verify signature", timing_table[5]),
    ]
    kem_data = [
        ("ML-KEM-768", "Key pair generation", timing_table[6]),
        ("ML-KEM-768", "Encapsulate (ciphertext)", timing_table[7]),
        ("ML-KEM-768", "Decapsulate (shared secret)", timing_table[8]),
        ("ECDH (P-256)", "Ephemeral key generation", timing_table[9]),
        ("ECDH (P-256)", "Derive shared secret", timing_table[10]),
    ]

    t1 = out_dir / "TABLE_I_signature_timings.csv"
    with t1.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["TABLE I — Digital signatures: mean time (ms) per operation"])
        w.writerow([])
        w.writerow(["Algorithm", "Operation", "Mean_ms", "Std_dev_ms", "N_runs"])
        for algo, op, r in sig_data:
            w.writerow([algo, op, f"{r[2]:.4f}", f"{r[3]:.4f}", r[4]])

    t2 = out_dir / "TABLE_II_key_agreement_timings.csv"
    with t2.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["TABLE II — Key agreement: mean time (ms) per operation"])
        w.writerow([])
        w.writerow(["Algorithm", "Operation", "Mean_ms", "Std_dev_ms", "N_runs"])
        for algo, op, r in kem_data:
            w.writerow([algo, op, f"{r[2]:.4f}", f"{r[3]:.4f}", r[4]])

    t3 = out_dir / "TABLE_III_output_sizes.csv"
    with t3.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["TABLE III — Size of each cryptographic output"])
        w.writerow([])
        w.writerow(["Algorithm", "Output", "Size_bytes", "Size_bits", "Explanation"])
        for algo, out_name, b, bits, note in size_rows:
            w.writerow([algo, out_name, b, bits, note])

    return out_txt


def write_scaling_csv(
    path: Path,
    lengths: list[int],
    ecdsa_means: list[float],
    ml_means: list[float],
    n_runs: int,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["message_length_bytes", "ecdsa_sign_mean_ms", "ml_dsa_sign_mean_ms", "n_runs_per_point"])
        for L, e, m in zip(lengths, ecdsa_means, ml_means):
            w.writerow([L, f"{e:.4f}", f"{m:.4f}", n_runs])


def plot_sizes(csv_path: Path, out_png: Path) -> None:
    labels: list[str] = []
    sizes: list[int] = []
    with csv_path.open(encoding="utf-8") as f:
        r = csv.DictReader(f)
        for row in r:
            labels.append(row["artifact"])
            sizes.append(int(row["size_bytes"]))
    fig, ax = plt.subplots(figsize=(10, 5))
    colors = ["#3d8fd1", "#3d8fd1", "#c9a227", "#c9a227", "#6b8f3a", "#6b8f3a", "#a878d1"]
    ax.bar(range(len(labels)), sizes, color=colors[: len(labels)], edgecolor="#1a222c", linewidth=0.6)
    ax.set_xticks(range(len(labels)))
    ax.set_xticklabels(labels, rotation=35, ha="right")
    ax.set_ylabel("Size (bytes)")
    ax.set_title("Artifact sizes (single representative sample)")
    ax.grid(axis="y", alpha=0.25)
    
    fig.tight_layout()
    fig.savefig(out_png, dpi=150)
    plt.close(fig)


def plot_timings(rows: list[tuple[str, str, float, float, int]], out_png: Path) -> None:
    """rows: operation, algorithm, mean_ms, stdev_ms, n"""
    labels = [f"{r[1]}\n{r[0]}" for r in rows]
    means = [r[2] for r in rows]
    stds = [r[3] for r in rows]
    colors = []
    for _op, algo, _m, _s, _n in rows:
        colors.append("#3d8fd1" if algo == "Classical" else "#c9a227")
    fig, ax = plt.subplots(figsize=(11, 5))
    x = range(len(labels))
    ax.bar(x, means, yerr=stds, capsize=3, color=colors, edgecolor="#1a222c", linewidth=0.5, ecolor="#444")
    ax.set_xticks(list(x))
    ax.set_xticklabels(labels, fontsize=8)
    ax.set_ylabel("Time (ms)")
    ax.set_title(f"Mean operation time ± stdev (n={rows[0][4]} runs per operation)")
    ax.grid(axis="y", alpha=0.25)
    fig.tight_layout()
    fig.savefig(out_png, dpi=150)
    plt.close(fig)


def plot_scaling(lengths: list[int], ecdsa_m: list[float], ml_m: list[float], out_png: Path, n_runs: int) -> None:
    fig, ax = plt.subplots(figsize=(8, 5))
    ax.plot(lengths, ecdsa_m, marker="o", label="ECDSA sign (P-256)", color="#3d8fd1", linewidth=2)
    ax.plot(lengths, ml_m, marker="s", label="ML-DSA-44 sign", color="#c9a227", linewidth=2)
    ax.set_xscale("log")
    ax.set_xlabel("Message length (bytes, log scale)")
    ax.set_ylabel("Mean sign time (ms)")
    ax.set_title(
        f"Mean sign time vs message length (n={n_runs} runs/point; fresh keygen each run, plotted: sign only)"
    )
    ax.legend()
    ax.grid(True, which="both", alpha=0.25)
    fig.tight_layout()
    fig.savefig(out_png, dpi=150)
    plt.close(fig)


def run_benchmark(
    outdir: str | Path = "results",
    runs: int = 30,
    scaling_runs: int = 15,
    lengths: str | list[int] = "10,100,1000,10000",
    no_plots: bool = False,
    quiet: bool = False,
) -> dict[str, Path | None]:
    """
    Run the full benchmark (same as CLI defaults). No user input required.

    Returns paths to written files; plot values are None if no_plots=True.
    """
    out = Path(outdir)
    out.mkdir(parents=True, exist_ok=True)

    base_msg = b"Paper benchmark default message."
    if isinstance(lengths, str):
        length_list = [int(x.strip()) for x in lengths.split(",") if x.strip()]
    else:
        length_list = list(lengths)

    sign_rows: list[dict] = []
    kem_rows: list[dict] = []
    for _ in range(runs):
        sign_rows.append(measure_sign_once(base_msg))
        kem_rows.append(measure_kem_once(base_msg))

    def col(rows: list[dict], key: str) -> list[float]:
        return [r[key] for r in rows]

    timing_table: list[tuple[str, str, float, float, int]] = [
        ("keygen", "Post-quantum", *mean_std(col(sign_rows, "ml_dsa_keygen_ms")), runs),
        ("sign", "Post-quantum", *mean_std(col(sign_rows, "ml_dsa_sign_ms")), runs),
        ("verify", "Post-quantum", *mean_std(col(sign_rows, "ml_dsa_verify_ms")), runs),
        ("keygen", "Classical", *mean_std(col(sign_rows, "ecdsa_keygen_ms")), runs),
        ("sign", "Classical", *mean_std(col(sign_rows, "ecdsa_sign_ms")), runs),
        ("verify", "Classical", *mean_std(col(sign_rows, "ecdsa_verify_ms")), runs),
        ("KEM keygen", "Post-quantum", *mean_std(col(kem_rows, "ml_kem_keygen_ms")), runs),
        ("encapsulate", "Post-quantum", *mean_std(col(kem_rows, "ml_kem_encap_ms")), runs),
        ("decapsulate", "Post-quantum", *mean_std(col(kem_rows, "ml_kem_decap_ms")), runs),
        ("ephemeral keygen", "Classical", *mean_std(col(kem_rows, "ecdh_keygen_ms")), runs),
        ("key exchange", "Classical", *mean_std(col(kem_rows, "ecdh_exchange_ms")), runs),
    ]

    sizes_csv = out / "sizes_bytes.csv"
    timings_csv = out / "timings_mean_ms.csv"
    timings_paper_csv = out / "timings_paper.csv"
    sizes_paper_csv = out / "sizes_paper.csv"
    scaling_csv = out / "sign_scaling.csv"

    write_sizes_csv(sizes_csv, sign_rows[0], kem_rows[0])
    write_timings_csv(timings_csv, timing_table)
    write_paper_timings_csv(timings_paper_csv, timing_table)
    write_paper_sizes_csv(sizes_paper_csv, sign_rows[0], kem_rows[0])
    tables_txt = write_simple_report_tables(out, timing_table, sign_rows[0], kem_rows[0])

    ecdsa_means: list[float] = []
    ml_means: list[float] = []
    for L in length_list:
        msg = os.urandom(L)
        ec_s: list[float] = []
        ml_s: list[float] = []
        for _ in range(scaling_runs):
            m = measure_sign_once(msg)
            ec_s.append(m["ecdsa_sign_ms"])
            ml_s.append(m["ml_dsa_sign_ms"])
        ecdsa_means.append(statistics.mean(ec_s))
        ml_means.append(statistics.mean(ml_s))

    write_scaling_csv(scaling_csv, length_list, ecdsa_means, ml_means, scaling_runs)

    fig_sizes = fig_timings = fig_scaling = None
    if not no_plots:
        fig_sizes = out / "fig_sizes_bytes.png"
        fig_timings = out / "fig_timings_ms.png"
        fig_scaling = out / "fig_sign_vs_message_length.png"
        plot_sizes(sizes_csv, fig_sizes)
        plot_timings(timing_table, fig_timings)
        plot_scaling(length_list, ecdsa_means, ml_means, fig_scaling, scaling_runs)

    if not quiet:
        print(f"Wrote {sizes_csv}")
        print(f"Wrote {timings_csv}")
        print(f"Wrote {timings_paper_csv}")
        print(f"Wrote {sizes_paper_csv}")
        print(f"Wrote {tables_txt}")
        print(f"Wrote {out / 'TABLE_I_signature_timings.csv'}")
        print(f"Wrote {out / 'TABLE_II_key_agreement_timings.csv'}")
        print(f"Wrote {out / 'TABLE_III_output_sizes.csv'}")
        print(f"Wrote {scaling_csv}")
        if not no_plots:
            print(f"Wrote {fig_sizes}")
            print(f"Wrote {fig_timings}")
            print(f"Wrote {fig_scaling}")

    return {
        "sizes_csv": sizes_csv,
        "timings_csv": timings_csv,
        "timings_paper_csv": timings_paper_csv,
        "sizes_paper_csv": sizes_paper_csv,
        "tables_for_report_txt": tables_txt,
        "scaling_csv": scaling_csv,
        "fig_sizes_bytes": fig_sizes,
        "fig_timings_ms": fig_timings,
        "fig_sign_scaling": fig_scaling,
    }


def main() -> None:
    p = argparse.ArgumentParser(description="PQC benchmark → CSV + plots for paper")
    p.add_argument("--runs", type=int, default=30, help="Iterations for mean timings (default 30)")
    p.add_argument("--scaling-runs", type=int, default=15, help="Runs per message length for line chart")
    p.add_argument(
        "--lengths",
        type=str,
        default="10,100,1000,10000",
        help="Comma-separated message byte lengths for scaling plot",
    )
    p.add_argument("--outdir", type=str, default="results", help="Output directory for CSV/PNG")
    p.add_argument("--no-plots", action="store_true", help="Only write CSV files")
    args = p.parse_args()

    run_benchmark(
        outdir=args.outdir,
        runs=args.runs,
        scaling_runs=args.scaling_runs,
        lengths=args.lengths,
        no_plots=args.no_plots,
        quiet=False,
    )


if __name__ == "__main__":
    main()
