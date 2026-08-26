"""
tls_experiment_websites.py
Proyecto: Medición de handshakes TLS contra páginas reales

Qué hace:
- Se conecta a dominios HTTPS reales usando OpenSSL s_client.
- Detecta automáticamente la profundidad real de la cadena de certificados.
- Mide latencia de conexión TLS.
- Guarda CSVs y gráficas.

Compatible con Windows + Python 3.7+ + OpenSSL 4.0 en PATH.
No necesita cacert.pem — usa el store del sistema o descarga automáticamente.
"""

import csv
import math
import os
import platform
import re
import shutil
import socket
import ssl
import statistics
import subprocess
import sys
import tempfile
import time
import urllib.request
from datetime import datetime
from pathlib import Path

# ─── Colores ANSI ─────────────────────────────────────────────────────────────
if platform.system() == "Windows":
    os.system("color")

R   = "\033[0;31m"
G   = "\033[0;32m"
Y   = "\033[1;33m"
C   = "\033[0;36m"
B   = "\033[1m"
RST = "\033[0m"

def log(msg):  print(f"{C}[•]{RST} {msg}")
def ok(msg):   print(f"{G}[✓]{RST} {msg}")
def warn(msg): print(f"{Y}[!]{RST} {msg}")
def die(msg):  print(f"{R}[✗]{RST} {msg}", file=sys.stderr); sys.exit(1)
def hdr(msg):
    bar = "═" * 54
    print(f"\n{B}{C}{bar}{RST}")
    print(f"{B}  {msg}{RST}")
    print(f"{B}{C}{bar}{RST}")

# =============================================================================
# CONFIGURACIÓN DEL EXPERIMENTO
# =============================================================================

# Sitios reales agrupados por profundidad típica de cadena.
# El script detecta la profundidad real — estos labels son orientativos.
TARGETS = [
    {"label": "depth_1_example",    "host": "example.com",       "port": 443},
    {"label": "depth_2_cloudflare", "host": "cloudflare.com",    "port": 443},
    {"label": "depth_2_google",     "host": "google.com",        "port": 443},
    {"label": "depth_2_github",     "host": "github.com",        "port": 443},
    {"label": "depth_3_microsoft",  "host": "microsoft.com",     "port": 443},
    {"label": "depth_3_amazon",     "host": "amazon.com",        "port": 443},
]

REPETITIONS      = 30       # 20-50 es razonable contra servidores reales
TIMEOUT_SECONDS  = 15
TLS_VERSION_FLAG = "-tls1_3"   # cambia a "" para dejar que negocie libremente

# =============================================================================
# PASO 0 — Verificar dependencias y preparar CA bundle
# =============================================================================
hdr("0. Verificar dependencias")

ok(f"Python {sys.version.split()[0]}")

if shutil.which("openssl") is None:
    die("openssl no encontrado en PATH.")

res = subprocess.run(["openssl", "version"], capture_output=True, text=True)
ok(f"OpenSSL: {res.stdout.strip()}")

# ── Resolver CA bundle ────────────────────────────────────────────────────────
SCRIPT_DIR = Path(__file__).resolve().parent

def find_ca_bundle() -> Path | None:
    # 1. cacert.pem junto al script o en cwd
    candidates = [
        SCRIPT_DIR / "cacert.pem",
        Path.cwd() / "cacert.pem",
    ]
    for p in candidates:
        if p.exists() and p.stat().st_size > 10_000:
            return p

    # 2. Bundle del módulo ssl de Python (suele estar disponible)
    try:
        ssl_bundle = ssl.get_default_verify_paths().cafile
        if ssl_bundle and Path(ssl_bundle).exists():
            return Path(ssl_bundle)
    except Exception:
        pass

    # 3. Ubicaciones comunes en Windows con Git/curl
    win_candidates = [
        Path(r"C:\Program Files\Git\usr\ssl\certs\ca-bundle.crt"),
        Path(r"C:\Program Files\Git\mingw64\etc\ssl\certs\ca-bundle.crt"),
        Path(os.environ.get("CURL_CA_BUNDLE", "___none___")),
    ]
    for p in win_candidates:
        if p.exists() and p.stat().st_size > 10_000:
            return p

    return None

CA_BUNDLE = find_ca_bundle()

if CA_BUNDLE:
    ok(f"CA bundle encontrado: {CA_BUNDLE}")
    VERIFY_ARGS = ["-CAfile", str(CA_BUNDLE)]
    VERIFY_MODE = "CAfile"
else:
    warn("No encontré un CA bundle. Intentando descargarlo de curl.se...")
    try:
        ca_dest = SCRIPT_DIR / "cacert.pem"
        url = "https://curl.se/ca/cacert.pem"
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(url, context=ctx, timeout=30) as r:
            ca_dest.write_bytes(r.read())
        CA_BUNDLE = ca_dest
        VERIFY_ARGS = ["-CAfile", str(CA_BUNDLE)]
        VERIFY_MODE = "CAfile"
        ok(f"CA bundle descargado: {CA_BUNDLE} ({CA_BUNDLE.stat().st_size:,} bytes)")
    except Exception as e:
        warn(f"No pude descargar cacert.pem ({e}).")
        warn("Corriendo sin verificación de certificados (solo para demo).")
        VERIFY_ARGS = ["-verify_return_error", "0"]   # OpenSSL 4.0 compatible
        VERIFY_MODE = "insecure"

# =============================================================================
# PASO 1 — Crear directorios
# =============================================================================
hdr("1. Crear directorios de trabajo")

timestamp   = datetime.now().strftime("%Y%m%d_%H%M%S")
BASE_DIR    = Path(f"tls_web_experiment_{timestamp}")
RESULTS_DIR = BASE_DIR / "results"
PLOTS_DIR   = BASE_DIR / "plots"
LOGS_DIR    = BASE_DIR / "logs"
CERTS_DIR   = BASE_DIR / "certs_extraidos"

for d in [RESULTS_DIR, PLOTS_DIR, LOGS_DIR, CERTS_DIR]:
    d.mkdir(parents=True, exist_ok=True)
    ok(f"Creado: {d}")

RAW_CSV     = RESULTS_DIR / "raw_web_results.csv"
SUMMARY_CSV = RESULTS_DIR / "resumen_web_estadistico.csv"
CHAINS_CSV  = RESULTS_DIR / "chains_detectadas.csv"

with open(RAW_CSV, "w", newline="", encoding="utf-8") as f:
    csv.writer(f).writerow([
        "label", "host", "port", "repetition", "latency_ms",
        "detected_depth", "cert_count",
        "chain_size_pem_bytes", "chain_size_der_bytes",
        "tls_version", "verify_mode", "returncode",
    ])

with open(CHAINS_CSV, "w", newline="", encoding="utf-8") as f:
    csv.writer(f).writerow([
        "label", "host", "port",
        "detected_depth", "cert_count",
        "chain_size_pem_bytes", "chain_size_der_bytes", "subjects",
    ])

# =============================================================================
# Helpers
# =============================================================================

def openssl_run(args, input_data=None, timeout=TIMEOUT_SECONDS):
    return subprocess.run(
        ["openssl"] + args,
        input=input_data,
        capture_output=True,
        text=True,
        timeout=timeout,
        shell=False,
    )

def extract_pem_certs(text: str) -> list[str]:
    return re.findall(
        r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
        text, flags=re.DOTALL
    )

def pem_to_der_size(pem: str) -> int:
    try:
        proc = subprocess.run(
            ["openssl", "x509", "-outform", "DER"],
            input=pem, capture_output=True, text=False,
            timeout=TIMEOUT_SECONDS,
        )
        return len(proc.stdout) if proc.returncode == 0 else 0
    except Exception:
        return 0

def cert_subject(pem: str) -> str:
    try:
        proc = subprocess.run(
            ["openssl", "x509", "-noout", "-subject", "-nameopt", "RFC2253"],
            input=pem, capture_output=True, text=True,
            timeout=TIMEOUT_SECONDS,
        )
        if proc.returncode == 0:
            return proc.stdout.strip().replace("subject=", "").strip()
    except Exception:
        pass
    return "unknown"

def build_s_client_cmd(host: str, port: int, extra_flags: list[str]) -> list[str]:
    """Construye el comando s_client compatible con OpenSSL 4.0."""
    cmd = [
        "s_client",
        "-connect", f"{host}:{port}",
        "-servername", host,
    ]
    if TLS_VERSION_FLAG:
        cmd.append(TLS_VERSION_FLAG)
    cmd += VERIFY_ARGS
    cmd += extra_flags
    return cmd

# =============================================================================
# Inspección de cadena de certificados
# =============================================================================

def inspect_chain(label: str, host: str, port: int) -> dict | None:
    log(f"Inspeccionando cadena: {host}:{port}")
    try:
        proc = openssl_run(
            build_s_client_cmd(host, port, ["-showcerts"]),
            input_data="Q\n",
        )
    except subprocess.TimeoutExpired:
        warn(f"Timeout inspeccionando {host}")
        return None

    full_output = (proc.stdout or "") + "\n" + (proc.stderr or "")
    log_file = LOGS_DIR / f"inspect_{label}.log"
    log_file.write_text(full_output, encoding="utf-8", errors="ignore")

    if proc.returncode != 0:
        # En OpenSSL 4.0 algunos returncode != 0 igual devuelven los certs
        warn(f"{host}: returncode={proc.returncode} "
             f"(puede ser normal si el servidor cierra la conexión antes)")

    pems = extract_pem_certs(full_output)
    if not pems:
        warn(f"No pude extraer certificados de {host}. Revisa logs/{log_file.name}")
        return None

    pem_size = sum(len(p.encode()) for p in pems)
    der_size = sum(pem_to_der_size(p) for p in pems)
    subjects = [cert_subject(p) for p in pems]

    # depth = saltos desde servidor hasta el último cert enviado
    # server(0) + 1 intermediate = depth 1, etc.
    detected_depth = max(len(pems) - 1, 0)

    # Guardar certs individuales
    site_dir = CERTS_DIR / f"{label}_{host.replace('.', '_')}"
    site_dir.mkdir(exist_ok=True)
    for i, pem in enumerate(pems):
        (site_dir / f"cert_{i}.pem").write_text(pem + "\n", encoding="utf-8")

    with open(CHAINS_CSV, "a", newline="", encoding="utf-8") as f:
        csv.writer(f).writerow([
            label, host, port,
            detected_depth, len(pems),
            pem_size, der_size,
            " | ".join(subjects),
        ])

    ok(f"  {host}: certs={len(pems)} depth={detected_depth} "
       f"PEM={pem_size}B DER≈{der_size}B")
    for i, s in enumerate(subjects):
        log(f"    cert[{i}]: {s[:80]}")

    return {
        "label": label, "host": host, "port": port,
        "detected_depth": detected_depth,
        "cert_count": len(pems),
        "pem_size": pem_size,
        "der_size": der_size,
    }

# =============================================================================
# Medición de handshakes
# =============================================================================

def measure_site(target: dict) -> list[float]:
    label = target["label"]
    host  = target["host"]
    port  = int(target.get("port", 443))

    chain_info = inspect_chain(label, host, port)
    if chain_info is None:
        return []

    results    = []
    client_log = LOGS_DIR / f"client_{label}.log"

    # Petición HTTP mínima para cerrar la conexión limpiamente
    http_req = (
        f"HEAD / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: tls-experiment/1.0\r\n"
        f"Connection: close\r\n\r\n"
    )

    for rep in range(1, REPETITIONS + 1):
        try:
            t0 = time.perf_counter()
            cli = openssl_run(
                build_s_client_cmd(host, port, ["-quiet"]),
                input_data=http_req,
            )
            t1 = time.perf_counter()
            elapsed_ms = (t1 - t0) * 1000.0

        except subprocess.TimeoutExpired:
            warn(f"{host} rep={rep}: timeout, se omite")
            with open(RAW_CSV, "a", newline="", encoding="utf-8") as f:
                csv.writer(f).writerow([
                    label, host, port, rep, "TIMEOUT",
                    chain_info["detected_depth"], chain_info["cert_count"],
                    chain_info["pem_size"], chain_info["der_size"],
                    TLS_VERSION_FLAG, VERIFY_MODE, "TIMEOUT",
                ])
            continue

        results.append(elapsed_ms)

        with open(client_log, "a", encoding="utf-8", errors="ignore") as f:
            f.write(f"\n=== REP {rep}  rc={cli.returncode}  "
                    f"{elapsed_ms:.2f}ms ===\n{cli.stderr or ''}\n")

        with open(RAW_CSV, "a", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow([
                label, host, port, rep, round(elapsed_ms, 3),
                chain_info["detected_depth"], chain_info["cert_count"],
                chain_info["pem_size"], chain_info["der_size"],
                TLS_VERSION_FLAG, VERIFY_MODE, cli.returncode,
            ])

        if rep % 10 == 0:
            log(f"  {host}: {rep}/{REPETITIONS}  último={elapsed_ms:.1f}ms")

    return results

# =============================================================================
# PASO 2 — Medición de sitios
# =============================================================================
hdr("2. Medir sitios reales")

site_results = {}
for target in TARGETS:
    log(f"\nIniciando: {target['label']} → {target['host']}:{target.get('port',443)}")
    vals = measure_site(target)
    site_results[target["label"]] = vals
    if vals:
        med = statistics.median(vals)
        ok(f"{target['host']}: n={len(vals)}  mediana={med:.1f}ms")
    else:
        warn(f"Sin mediciones válidas para {target['host']}")

# =============================================================================
# PASO 3 — Resumen estadístico
# =============================================================================
hdr("3. Resumen estadístico")

raw_data: dict[tuple, list] = {}
meta: dict[tuple, dict]     = {}

with open(RAW_CSV, encoding="utf-8") as f:
    for row in csv.DictReader(f):
        if row["latency_ms"] in ("TIMEOUT", ""):
            continue
        key = (row["label"], row["host"])
        raw_data.setdefault(key, []).append(float(row["latency_ms"]))
        meta[key] = row

summary_rows = []
fields = [
    "label", "host", "detected_depth", "cert_count",
    "n", "mean_ms", "median_ms", "stdev_ms",
    "p95_ms", "min_ms", "max_ms",
    "pem_bytes", "der_bytes",
]

with open(SUMMARY_CSV, "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=fields)
    w.writeheader()

    sorted_keys = sorted(
        raw_data.keys(),
        key=lambda k: (int(meta[k].get("detected_depth", 0)), k[1])
    )

    print(f"\n  {'Host':22s} {'depth':>5} {'certs':>5} "
          f"{'n':>4} {'median(ms)':>10} {'p95(ms)':>9} {'DER(B)':>8}")
    print("  " + "─" * 68)

    for key in sorted_keys:
        label, host = key
        vals = raw_data[key]
        vs   = sorted(vals)
        p95  = vs[math.ceil(0.95 * len(vs)) - 1]
        m    = meta[key]

        row = {
            "label":          label,
            "host":           host,
            "detected_depth": int(m.get("detected_depth", -1)),
            "cert_count":     int(m.get("cert_count", 0)),
            "n":              len(vals),
            "mean_ms":        round(statistics.mean(vals), 3),
            "median_ms":      round(statistics.median(vals), 3),
            "stdev_ms":       round(statistics.stdev(vals) if len(vals) > 1 else 0, 3),
            "p95_ms":         round(p95, 3),
            "min_ms":         round(min(vals), 3),
            "max_ms":         round(max(vals), 3),
            "pem_bytes":      int(m.get("chain_size_pem_bytes", 0)),
            "der_bytes":      int(m.get("chain_size_der_bytes", 0)),
        }
        w.writerow(row)
        summary_rows.append(row)

        print(f"  {host:22s} {row['detected_depth']:>5} {row['cert_count']:>5} "
              f"{row['n']:>4} {row['median_ms']:>10.1f} "
              f"{row['p95_ms']:>9.1f} {row['der_bytes']:>8}")

ok(f"Resumen → {SUMMARY_CSV}")
ok(f"Cadenas → {CHAINS_CSV}")

# =============================================================================
# PASO 4 — Visualizaciones
# =============================================================================
hdr("4. Generar visualizaciones")

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    if summary_rows:
        depth_colors = {0: "#aaaaaa", 1: "#5cb8e0", 2: "#5ce07a", 3: "#e0925c", 4: "#e05c5c"}
        clr = [depth_colors.get(r["detected_depth"], "#cccccc") for r in summary_rows]
        xlabels = [f"{r['host']}\nd={r['detected_depth']}" for r in summary_rows]
        medians = [r["median_ms"] for r in summary_rows]
        depths  = [r["detected_depth"] for r in summary_rows]
        ders    = [r["der_bytes"] for r in summary_rows]

        # 1. Latencia mediana por sitio
        fig, ax = plt.subplots(figsize=(10, 5))
        bars = ax.bar(xlabels, medians, color=clr, edgecolor="white", linewidth=0.5)
        ax.bar_label(bars, fmt="%.0f ms", padding=3, fontsize=8)
        ax.set_ylabel("Latencia mediana (ms)")
        ax.set_title("Latencia mediana TLS por sitio real")
        ax.grid(True, axis="y", alpha=0.3)
        fig.tight_layout()
        out = PLOTS_DIR / "latencia_mediana_sitios.png"
        fig.savefig(out, dpi=150); plt.close(fig)
        ok(f"→ {out}")

        # 2. Scatter latencia vs tamaño DER
        fig, ax = plt.subplots(figsize=(8, 5))
        sc = ax.scatter(ders, medians, c=depths, cmap="RdYlGn_r", s=90, edgecolors="white")
        plt.colorbar(sc, ax=ax, label="Profundidad detectada")
        for r in summary_rows:
            ax.annotate(
                r["host"], (r["der_bytes"], r["median_ms"]),
                textcoords="offset points", xytext=(6, 4), fontsize=7,
            )
        ax.set_xlabel("Tamaño cadena DER (bytes)")
        ax.set_ylabel("Latencia mediana (ms)")
        ax.set_title("Latencia vs tamaño de cadena — sitios reales")
        ax.grid(True, alpha=0.3)
        fig.tight_layout()
        out = PLOTS_DIR / "scatter_latencia_vs_der.png"
        fig.savefig(out, dpi=150); plt.close(fig)
        ok(f"→ {out}")

        # 3. Scatter latencia vs profundidad
        fig, ax = plt.subplots(figsize=(7, 5))
        ax.scatter(depths, medians, s=90, color="#5c9ee0", edgecolors="white")
        for r in summary_rows:
            ax.annotate(
                r["host"], (r["detected_depth"], r["median_ms"]),
                textcoords="offset points", xytext=(6, 4), fontsize=7,
            )
        ax.set_xlabel("Profundidad detectada")
        ax.set_ylabel("Latencia mediana (ms)")
        ax.set_title("Latencia vs profundidad detectada")
        ax.set_xticks(sorted(set(depths)))
        ax.grid(True, alpha=0.3)
        fig.tight_layout()
        out = PLOTS_DIR / "scatter_latencia_vs_profundidad.png"
        fig.savefig(out, dpi=150); plt.close(fig)
        ok(f"→ {out}")

        # 4. Boxplot por sitio (raw data)
        box_data: dict[str, list] = {}
        with open(RAW_CSV, encoding="utf-8") as f:
            for row in csv.DictReader(f):
                if row["latency_ms"] not in ("TIMEOUT", ""):
                    k = f"{row['host']}\nd={row['detected_depth']}"
                    box_data.setdefault(k, []).append(float(row["latency_ms"]))
        if box_data:
            bkeys = sorted(box_data, key=lambda k: (int(k.split("d=")[1]), k))
            fig, ax = plt.subplots(figsize=(11, 5))
            bp = ax.boxplot(
                [box_data[k] for k in bkeys],
                labels=bkeys, patch_artist=True, notch=False,
            )
            for patch in bp["boxes"]:
                patch.set_facecolor("#5c9ee0"); patch.set_alpha(0.7)
            ax.set_ylabel("Latencia (ms)")
            ax.set_title("Boxplot de latencia por sitio real")
            ax.grid(True, axis="y", alpha=0.3)
            fig.tight_layout()
            out = PLOTS_DIR / "boxplot_latencia_sitios.png"
            fig.savefig(out, dpi=150); plt.close(fig)
            ok(f"→ {out}")

except ImportError:
    warn("matplotlib no disponible — generando resumen ASCII\n")
    BAR = "█"; W = 40
    max_m = max((r["median_ms"] for r in summary_rows), default=1)
    print("  ┌─ Latencia mediana por sitio ──────────────────────────────────")
    for r in summary_rows:
        v = r["median_ms"]
        n = int(round(v / max_m * W))
        bar = BAR * n + "░" * (W - n)
        print(f"  │  {r['host']:20s} d={r['detected_depth']}  {bar}  {v:.0f}ms")
    print("  └───────────────────────────────────────────────────────────────")

# =============================================================================
# PASO 5 — Conclusión
# =============================================================================
hdr("5. Conclusión")

print(f"""
  ╔══════════════════════════════════════════════════════════════╗
  ║  HALLAZGOS: TLS en sitios reales                            ║
  ╠══════════════════════════════════════════════════════════════╣""")

by_depth: dict[int, list] = {}
for r in summary_rows:
    by_depth.setdefault(r["detected_depth"], []).append(r)

for depth in sorted(by_depth):
    sites = by_depth[depth]
    meds  = [s["median_ms"] for s in sites]
    avg   = sum(meds) / len(meds)
    hosts = ", ".join(s["host"] for s in sites)
    print(f"  ║  depth={depth} ({len(sites)} sitios): avg mediana={avg:.0f}ms  [{hosts}]")

print(f"""  ╠══════════════════════════════════════════════════════════════╣
  ║  Benchmark local → evidencia principal (control total)      ║
  ║  Sitios reales   → validación práctica de cadenas TLS reales║
  ╚══════════════════════════════════════════════════════════════╝
""")

print(f"  {B}Directorio:{RST} {BASE_DIR.resolve()}\n")
print(f"  {B}Archivos:{RST}")
for f in sorted(RESULTS_DIR.iterdir()):
    print(f"    {f.name:<40s} {f.stat().st_size:>8,} bytes")
if any(PLOTS_DIR.iterdir()):
    print(f"\n  {B}Gráficas:{RST}")
    for f in sorted(PLOTS_DIR.iterdir()):
        print(f"    {f.name}")
print()
ok("Todo listo.")
