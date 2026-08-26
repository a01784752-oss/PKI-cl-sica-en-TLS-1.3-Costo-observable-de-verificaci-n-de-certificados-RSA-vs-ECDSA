# PKI clásica en TLS 1.3: costo observable de verificación de certificados RSA vs ECDSA

## Included experiment

This repository currently contains the **real-website TLS experiment** supplied for the PKI project. It uses Python and OpenSSL to inspect certificates presented by HTTPS servers, collect elapsed-time measurements, and produce CSV summaries and plots.

**Scope:** the supplied script does not implement a controlled RSA-versus-ECDSA comparison, identify certificate algorithms in its CSVs, or isolate certificate-verification time. No local controlled benchmark, paper, or measured results were supplied with this upload.

The original Python source is preserved unchanged, under the filename `tls_experiment_websites.py`. Its comments and terminal messages are primarily in Spanish.

## What the script does

1. Locates OpenSSL and searches for a CA bundle; if none is found, it attempts a download from `https://curl.se/ca/cacert.pem`.
2. Inspects the certificates presented by each configured server.
3. Launches repeated `openssl s_client` subprocesses with an HTTP HEAD request.
4. Records elapsed time, certificate counts, size fields, subprocess return codes, and timeout markers.
5. Calculates count, mean, median, sample standard deviation, p95, minimum, and maximum.
6. Generates plots when Matplotlib is installed.

### Default configuration

| Setting | Value |
| --- | --- |
| Targets | example.com, cloudflare.com, google.com, github.com, microsoft.com, amazon.com |
| Port | 443 |
| Repetitions | 30 per target |
| Subprocess timeout | 15 seconds |
| Requested protocol | TLS 1.3, via `-tls1_3` |

These values are constants near the top of the script. The depth labels in target names are illustrative, not measurements.

## Setup and execution

**Review the limitations below before interpreting results.**

- Use Python **3.10 or later** for the source's `Path | None` and related annotations. The original header's Python 3.7+ claim is inconsistent with the code.
- Install an OpenSSL command-line executable with TLS 1.3 support and make it available on `PATH`. The original code mentions OpenSSL 4.0; that compatibility claim has not been validated during this upload.
- Provide a trusted CA bundle. The script checks for `cacert.pem` beside the script or in the working directory, among other locations.
- Matplotlib is optional for the charts. The dependency file is unpinned and has not been installation-tested.

From an activated virtual environment:

```bash
python -m pip install -r requirements.txt
openssl version
python tls_experiment_websites.py
```

The script makes real network requests when executed. It also runs its experiment at import time, so do not import it merely to inspect helper functions. Use permitted targets and conservative repetition counts.

## Generated files

Each run creates a `tls_web_experiment_<timestamp>/` directory in the working directory.

| Location | Contents |
| --- | --- |
| `results/raw_web_results.csv` | Individual measurements and timeout records |
| `results/resumen_web_estadistico.csv` | Per-site statistical summaries |
| `results/chains_detectadas.csv` | Certificate counts, size fields, and subjects |
| `plots/` | Median-latency bar chart, scatter plots, and latency boxplot |
| `logs/` | Certificate inspection and client logs |
| `certs_extraidos/` | Extracted public certificates |

Generated run directories are excluded by `.gitignore`. No benchmark results are included in this initial publication.

## Known limitations

- **DER conversion bug:** `pem_to_der_size` supplies a Python string to a subprocess configured with `text=False`. The resulting exception is caught and converted to zero, making the DER-size fields unreliable.
- **Timing scope:** the timer wraps the entire OpenSSL subprocess, including startup, connection work, and HTTP activity. It does not isolate the TLS handshake or certificate verification.
- **Failure filtering:** nonzero subprocess return codes are recorded but not excluded from the numerical summaries. Only timeouts and empty latency values are filtered.
- **Certificate depth:** `detected_depth` is calculated as the number of extracted certificates minus one. The script does not reconstruct or verify a complete certification path to determine that value.
- **Verification handling:** the code's CA-failure branch uses `["-verify_return_error", "0"]` and labels the run `insecure`. Do not treat that label as proof of the actual OpenSSL verification behavior. The normal command also does not request hostname checking explicitly or independently validate the recorded verification outcome. This script is not a certificate-security validator.
- **Protocol reporting:** the CSV stores the configured protocol flag rather than parsing the negotiated version.
- **Experimental interpretation:** differences between unrelated websites cannot establish the isolated effect of RSA versus ECDSA, certificate depth, or certificate size. The current script does not control those factors.

## Publication checks

The source passed Python syntax parsing, and a scan found no matches for the common credential patterns checked. These are limited static checks, not a security audit. No network experiment, dependency installation, or runtime compatibility test was performed during publication.

## Further work

Correct the DER conversion and verification handling, separate successful from failed connections, and define precisely what the timer measures. A controlled RSA-versus-ECDSA study would also need its own certificate/algorithm configuration, measurement method, and reproducible results.
