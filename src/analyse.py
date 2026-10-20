"""Tables, figure and network model for the PQ TLS paper."""
import json
from pathlib import Path

import matplotlib
import numpy as np
import pandas as pd

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
RES, FIG, TAB = ROOT / "results", ROOT / "paper" / "figures", ROOT / "paper" / "tables"
plt.rcParams.update({"font.size": 8, "font.family": "serif", "axes.spines.top": False, "axes.spines.right": False})
facts = {}

p = pd.read_csv(RES / "primitives.csv")
pm = p.groupby("op", sort=False).ns_per_op.agg(["median", lambda s: s.quantile(.75) - s.quantile(.25)])
pm.columns = ["median", "iqr"]
sizes = json.loads((RES / "primitive_sizes.json").read_text())
facts["primitives_us"] = (pm["median"] / 1000).round(1).to_dict()
rows = [{"Operation": op, "Median ($\\mu$s)": f"{r['median'] / 1000:.1f}", "IQR ($\\mu$s)": f"{r['iqr'] / 1000:.1f}"}
        for op, r in pm.iterrows()]
(TAB / "primitives.tex").write_text(
    "\\begin{table}[t]\n\\centering\n\\caption{Key-exchange primitives in Go 1.24 (\\texttt{crypto/ecdh}, \\texttt{crypto/mlkem}), "
    "15 repetitions of 2{,}000 operations. Public values: X25519 32 bytes, P-256 65 bytes, ML-KEM-768 encapsulation key "
    f"{sizes['ML-KEM-768 encapsulation key']:,} bytes and ciphertext {sizes['ML-KEM-768 ciphertext']:,} bytes.}}\n"
    "\\label{tab:prims}\n\\small\n" + pd.DataFrame(rows).to_latex(index=False, escape=False, column_format="lrr") + "\\end{table}\n")

h = pd.read_csv(RES / "handshakes.csv")
h["key"] = h.server_group + "|" + h.client_groups + "|" + h.cert + "|" + h.mtls.astype(str) + "|" + h.resume.astype(str)
g = h.groupby("key").agg(server_group=("server_group", "first"), client_groups=("client_groups", "first"),
                         cert=("cert", "first"), mtls=("mtls", "first"), resume=("resume", "first"),
                         srv=("server_cpu_ns", "median"), cli=("client_cpu_ns", "median"),
                         srv_q1=("server_cpu_ns", lambda s: s.quantile(.25)), srv_q3=("server_cpu_ns", lambda s: s.quantile(.75)),
                         ch=("client_hello_bytes", "first"), sf=("server_first_flight_bytes", "first"),
                         total=("total_bytes", "first"), flights=("flights", "first")).reset_index(drop=True)
g.to_csv(RES / "handshake_summary.csv", index=False)

def pick(sg, cg, cert, mtls, resume=False):
    x = g[(g.server_group == sg) & (g.client_groups == cg) & (g.cert == cert) & (g.mtls == mtls) & (g.resume == resume)]
    return x.iloc[0]

rows = []
for cert in ("ECDSA-P256", "Ed25519", "RSA-2048", "RSA-3072"):
    for mtls in (False, True):
        a = pick("X25519", "X25519", cert, mtls)
        b = pick("X25519MLKEM768", "X25519MLKEM768,X25519", cert, mtls)
        rows.append({"Certificate": cert, "mTLS": "yes" if mtls else "no",
                     "Server CPU, $\\mu$s": f"{a.srv / 1000:.0f} / {b.srv / 1000:.0f}",
                     "$\\Delta$ server": f"{(b.srv / a.srv - 1) * 100:+.0f}\\%",
                     "Client CPU, $\\mu$s": f"{a.cli / 1000:.0f} / {b.cli / 1000:.0f}",
                     "Bytes": f"{a.total:,} / {b.total:,}"})
        facts[f"{cert}_{'mtls' if mtls else 'tls'}"] = {"srv_x": a.srv, "srv_h": b.srv, "cli_x": a.cli, "cli_h": b.cli,
                                                          "bytes_x": int(a.total), "bytes_h": int(b.total),
                                                          "ch_x": int(a.ch), "ch_h": int(b.ch), "sf_x": int(a.sf), "sf_h": int(b.sf)}
(TAB / "handshakes.tex").write_text(
    "\\begin{table*}[t]\n\\centering\n\\caption{Full TLS 1.3 handshakes on loopback, X25519 against X25519MLKEM768 (the hybrid client "
    "also offers an X25519 share, Go's default). CPU is median process CPU time per handshake over 7 runs of 300 handshakes; "
    "bytes are the handshake records in both directions. Pairs are X25519 / X25519MLKEM768.}\n\\label{tab:hs}\n\\small\n"
    + pd.DataFrame(rows).to_latex(index=False, escape=False, column_format="llrrrr") + "\\end{table*}\n")

# Special cases.
for nm, args in {"resume_x": ("X25519", "X25519", "ECDSA-P256", True, True),
                 "resume_h": ("X25519MLKEM768", "X25519MLKEM768,X25519", "ECDSA-P256", True, True),
                 "hybrid_client_classical_server": ("X25519", "X25519MLKEM768,X25519", "ECDSA-P256", True, False),
                 "hybrid_only_client": ("X25519MLKEM768", "X25519MLKEM768", "ECDSA-P256", True, False),
                 "p256": ("P256", "P256", "ECDSA-P256", True, False)}.items():
    r = pick(*args)
    facts[nm] = {"srv": r.srv, "cli": r.cli, "ch": int(r.ch), "sf": int(r.sf), "total": int(r.total)}

# Network model: added time from extra bytes and extra CPU, per environment.
envs = [("Same host / data centre", 10e9, 0.1), ("Cross-zone", 1e9, 1.0), ("Internet, broadband", 50e6, 30.0),
        ("Mobile, constrained", 1e6, 100.0), ("Low-power IoT link", 250e3, 300.0)]
base = facts["ECDSA-P256_mtls"]
extra_bytes = base["bytes_h"] - base["bytes_x"]
extra_cpu_ms = (base["srv_h"] - base["srv_x"] + base["cli_h"] - base["cli_x"]) / 1e6
rows = []
for name, bw, rtt in envs:
    base_ms = rtt + base["bytes_x"] * 8 / bw * 1000 + (base["srv_x"] + base["cli_x"]) / 1e6
    add = extra_bytes * 8 / bw * 1000 + extra_cpu_ms
    rows.append({"Environment": name, "Bandwidth": f"{bw / 1e6:g} Mbit/s", "RTT (ms)": f"{rtt:g}",
                 "Classical (ms)": f"{base_ms:.2f}", "Added by hybrid (ms)": f"{add:.2f}", "Relative": f"{add / base_ms * 100:+.0f}\\%"})
facts["network"] = rows
facts["extra_bytes"] = extra_bytes
(TAB / "network.tex").write_text(
    "\\begin{table}[t]\n\\centering\n\\caption{Modelled cost of a full mTLS handshake (ECDSA certificates): one round trip, "
    "serialisation of the measured handshake bytes, and the measured CPU time on both sides. Only one round trip is needed in every "
    "case: the largest flight (" + f"{base['sf_h']:,}" + " bytes) fits well within a 10-segment initial congestion window.}\n"
    "\\label{tab:net}\n\\small\n\\setlength{\\tabcolsep}{4pt}\n" + pd.DataFrame(rows).to_latex(index=False, escape=False,
                                                                                                column_format="lrrrrr") + "\\end{table}\n")

# ClientHello segments for common MSS values.
mss = {"Ethernet (1460)": 1460, "IPsec/WireGuard tunnel (~1380)": 1380, "IPv6 minimum MTU (1220)": 1220}
facts["ch_segments"] = {k: {"x25519": int(np.ceil(base["ch_x"] / v)), "hybrid": int(np.ceil(base["ch_h"] / v)),
                            "hybrid_resumed": int(np.ceil(facts["resume_h"]["ch"] / v))} for k, v in mss.items()}

# Figure: per-flight bytes.
fig, ax = plt.subplots(figsize=(4.6, 2.2))
labels = ["ClientHello", "Server flight", "Client Finished\n(+ cert, mTLS)"]
fx = [int(v) for v in pick("X25519", "X25519", "ECDSA-P256", True).flights.split("|")]
fh = [int(v) for v in pick("X25519MLKEM768", "X25519MLKEM768,X25519", "ECDSA-P256", True).flights.split("|")]
xx = np.arange(3)
ax.bar(xx - 0.2, fx, 0.4, color="#9ecae1", label="X25519")
ax.bar(xx + 0.2, fh, 0.4, color="#1f4e79", label="X25519MLKEM768")
ax.axhline(1460, color="grey", lw=0.6, ls=":")
ax.text(2.45, 1500, "one 1460-byte segment", fontsize=6, ha="right", color="grey")
ax.set_xticks(xx)
ax.set_xticklabels(labels, fontsize=7)
ax.set_ylabel("Bytes")
ax.legend(fontsize=6, frameon=False)
fig.tight_layout()
fig.savefig(FIG / "flights.pdf")
(RES / "facts.json").write_text(json.dumps(facts, indent=1, default=float))
print(json.dumps({k: v for k, v in facts.items() if k in ("ECDSA-P256_mtls", "ECDSA-P256_tls", "resume_x", "resume_h",
                                                          "hybrid_client_classical_server", "hybrid_only_client", "ch_segments",
                                                          "extra_bytes")}, indent=1, default=float))
for r in rows: print(r)
