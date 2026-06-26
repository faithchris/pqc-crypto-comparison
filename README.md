# Post-Quantum vs Classical Cryptography Comparison

CSIT 567 project comparing **ECDSA/ECDH** (classical) with **ML-DSA-44/ML-KEM-768** (post-quantum).

**Project site:** [faithchris.github.io/pqc-crypto-comparison](https://faithchris.github.io/pqc-crypto-comparison/)

## Features

- **Web demo** (`encryptionCompare_v1.py`) — sign/verify and key agreement in the browser
- **Benchmarks** (`benchmark.py`) — timing and size measurements, CSV exports, matplotlib figures
- **Results** — pre-generated tables and plots in `results/`

## Requirements

- Python 3.10+
- See `requirements.txt`

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run the web app

```bash
python encryptionCompare_v1.py
```

Open http://127.0.0.1:5000 in your browser.

## Run benchmarks

```bash
python benchmark.py
# or with options:
python benchmark.py --runs 50 --outdir results
```

## Project structure

```
benchmark.py              # Offline benchmarks + figures
encryptionCompare_v1.py   # Flask comparison app
templates/index.html      # Web UI
results/                  # CSV tables and PNG figures
benchmark_notebook.ipynb  # Optional Jupyter workflow
```

## Algorithms

| Task | Classical | Post-quantum |
|------|-----------|--------------|
| Signing | ECDSA (P-256) | ML-DSA-44 |
| Key agreement | ECDH (P-256) | ML-KEM-768 |

## GitHub Pages

The project paper site is `index.html` at the repo root (tables, figures, findings, references). GitHub Pages serves it automatically when **Settings → Pages → Branch: main, Folder: / (root)**.

## License

MIT
