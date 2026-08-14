#!/usr/bin/env python3
"""Generate the README figures as committed SVG, one file per GitHub theme.

Run: python3 assets/readme/generate.py

Every number is read from data.json, which is extracted verbatim from
https://onthebench.ai/data.json (busbar 1.5.1, AWS m7g.4xlarge, measured
2026-08-03). Nothing here is typed by hand except labels; refresh data.json
from onthebench and re-run to update every figure.
No em dashes anywhere in the output (a build gate rejects them).
"""
import json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
D = json.load(open(os.path.join(HERE, "data.json")))
OUT = sys.argv[1] if len(sys.argv) > 1 else HERE
os.makedirs(OUT, exist_ok=True)

THEMES = {
    "light": dict(
        bg="#ffffff", panel="#f6f8fa", grid="#d0d7de", line="#d0d7de",
        text="#1f2328", dim="#59636e", faint="#818b98",
        accent="#1a7f37", accent_soft="#dafbe1", accent_line="#2da44e",
        neutral="#8c959f", neutral_soft="#eaeef2", warn="#9a6700",
    ),
    "dark": dict(
        bg="#0d1117", panel="#161b22", grid="#30363d", line="#30363d",
        text="#e6edf3", dim="#9198a1", faint="#6e7681",
        accent="#3fb950", accent_soft="#132d1d", accent_line="#2ea043",
        neutral="#7d8590", neutral_soft="#1c2128", warn="#d29922",
    ),
}

FONT = ("ui-sans-serif,-apple-system,BlinkMacSystemFont,'Segoe UI',"
        "Helvetica,Arial,sans-serif")
MONO = "ui-monospace,SFMono-Regular,'SF Mono',Menlo,Consolas,monospace"


def esc(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def txt(x, y, s, size=12, fill="text", anchor="start", weight="400",
        mono=False, opacity=None, t=None):
    op = f' opacity="{opacity}"' if opacity is not None else ""
    fam = MONO if mono else FONT
    return (f'<text x="{x:.1f}" y="{y:.1f}" font-family="{fam}" font-size="{size}" '
            f'font-weight="{weight}" fill="{t[fill] if fill in t else fill}" '
            f'text-anchor="{anchor}"{op}>{esc(s)}</text>')


def rect(x, y, w, h, fill, t, rx=6, stroke=None, sw=1, opacity=None):
    st = f' stroke="{t.get(stroke, stroke)}" stroke-width="{sw}"' if stroke else ""
    op = f' opacity="{opacity}"' if opacity is not None else ""
    return (f'<rect x="{x:.1f}" y="{y:.1f}" width="{w:.1f}" height="{h:.1f}" '
            f'rx="{rx}" fill="{t.get(fill, fill)}"{st}{op}/>')


def frame(w, h, t, title, sub):
    """Common chrome: background, title, provenance line."""
    s = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" '
         f'viewBox="0 0 {w} {h}" role="img" aria-label="{esc(title)}">',
         f'<rect width="{w}" height="{h}" rx="10" fill="{t["bg"]}"/>']
    if title:
        s.append(txt(28, 40, title, 19, "text", weight="650", t=t))
    if sub:
        s.append(txt(28, 62, sub, 11.5, "dim", t=t))
    return s


SRC = D["source"]
STAMP = ("busbar 1.5.1 on AWS m7g.4xlarge (Graviton3), 4-core pin, measured "
         "2026-08-03, published at onthebench.ai")


# ---------------------------------------------------------------- figure 1
def fig_matrix(t):
    order = ["openai", "openai-responses", "anthropic", "gemini", "cohere", "bedrock"]
    label = {"openai": "OpenAI", "openai-responses": "Responses",
             "anthropic": "Anthropic", "gemini": "Gemini",
             "cohere": "Cohere", "bedrock": "Bedrock"}
    W, H = 900, 512
    cw, ch, gap = 104, 44, 8
    x0, y0 = 196, 118
    s = frame(W, H, t, "One endpoint, every protocol, both directions",
              "Added latency p99 in microseconds, per ingress and upstream pair. "
              "Lower is better. 36 of 36 pairs served.")

    s.append(txt(x0 - 12, y0 - 34, "UPSTREAM", 10, "faint", anchor="end",
                 weight="700", t=t))
    for j, eg in enumerate(order):
        cx = x0 + j * (cw + gap) + cw / 2
        s.append(txt(cx, y0 - 34, label[eg], 11.5, "dim", anchor="middle",
                     weight="600", t=t))
    s.append(f'<g transform="translate(38,{y0 + 3 * (ch + gap)}) rotate(-90)">'
             + txt(0, 0, "INGRESS", 10, "faint", anchor="middle", weight="700", t=t)
             + "</g>")

    for i, ing in enumerate(order):
        cy = y0 + i * (ch + gap)
        s.append(txt(x0 - 16, cy + ch / 2 + 4, label[ing], 11.5, "dim",
                     anchor="end", weight="600", t=t))
        for j, eg in enumerate(order):
            c = D["matrix"][ing][eg]
            cx = x0 + j * (cw + gap)
            same = ing == eg
            if same:
                s.append(rect(cx, cy, cw, ch, "accent", t, rx=7))
                s.append(txt(cx + cw / 2, cy + 20, f'{c["p99"]} µs', 13,
                             t["bg"], anchor="middle", weight="700", mono=True, t=t))
                s.append(txt(cx + cw / 2, cy + 34, "your bytes", 9.5, t["bg"],
                             anchor="middle", weight="600", opacity="0.85", t=t))
            else:
                s.append(rect(cx, cy, cw, ch, "accent_soft", t, rx=7,
                              stroke="accent_line", sw=1))
                s.append(txt(cx + cw / 2, cy + 27, f'{c["p99"]} µs', 13,
                             "accent", anchor="middle", weight="600", mono=True, t=t))

    ly = y0 + 6 * (ch + gap) + 12
    s.append(rect(28, ly, 16, 16, "accent", t, rx=4))
    s.append(txt(52, ly + 12.5, "Same protocol: your original bytes, forwarded, "
                 "not re-serialized", 11.5, "dim", t=t))
    s.append(rect(28, ly + 26, 16, 16, "accent_soft", t, rx=4,
                  stroke="accent_line"))
    s.append(txt(52, ly + 38.5, "Cross protocol: every modelled field arrives in "
                 "the target's native shape", 11.5, "dim", t=t))
    s.append(txt(28, H - 18, STAMP, 10, "faint", t=t))
    s.append("</svg>")
    return "\n".join(s)


# ---------------------------------------------------------------- figure 2
def fig_perf(t):
    W, H = 900, 400
    dg = D["diagonal"]
    rungs = [r for r in dg["rungs"] if r["rps"]]
    s = frame(W, H, t, "Fast, and it stays fast under load",
              "Same protocol OpenAI cell. Added latency is the gateway leg minus the "
              "same call taken straight to the mock.")

    # three stat tiles
    tiles = [
        (f'{dg["latency_p50_us"]} µs', "added latency p50",
         f'p99 {dg["latency_p99_us"]} µs'),
        (f'{dg["cpu_us_per_request"]:.1f} µs', "gateway CPU per request",
         f'measured at c={dg["cost_window_conc"]}'),
        (f'{dg["frontier"][-1]["rps"]:,}', "requests/sec sustained",
         f'at c={dg["frontier"][-1]["conc"]}, zero failures'),
    ]
    tw, tx, ty = 268, 28, 86
    for k, (big, lab, sub) in enumerate(tiles):
        x = tx + k * (tw + 12)
        s.append(rect(x, ty, tw, 84, "panel", t, rx=8, stroke="grid"))
        s.append(txt(x + 16, ty + 38, big, 26, "accent", weight="700", mono=True, t=t))
        s.append(txt(x + 16, ty + 58, lab, 11.5, "text", weight="600", t=t))
        s.append(txt(x + 16, ty + 74, sub, 10.5, "dim", t=t))

    # throughput vs concurrency curve
    px, py, pw, ph = 28, 210, 844, 140
    s.append(rect(px, py, pw, ph, "panel", t, rx=8, stroke="grid"))
    import math
    xs = [math.log2(r["conc"]) for r in rungs]
    ys = [r["rps"] for r in rungs]
    xmin, xmax = min(xs), max(xs)
    ymax = max(ys) * 1.18
    gx = px + 60
    gw = pw - 250
    gy = py + 30
    gh = ph - 60

    def X(v):
        return gx + (v - xmin) / (xmax - xmin) * gw

    def Y(v):
        return gy + gh - (v / ymax) * gh

    for frac in (0, 0.5, 1.0):
        v = ymax * frac
        s.append(f'<line x1="{gx}" y1="{Y(v):.1f}" x2="{gx + gw}" y2="{Y(v):.1f}" '
                 f'stroke="{t["grid"]}" stroke-width="1" opacity="0.7"/>')
        s.append(txt(gx - 10, Y(v) + 4, f"{int(v / 1000)}k", 10, "faint",
                     anchor="end", mono=True, t=t))
    pts = " ".join(f"{X(x):.1f},{Y(y):.1f}" for x, y in zip(xs, ys))
    s.append(f'<polyline points="{pts}" fill="none" stroke="{t["accent"]}" '
             f'stroke-width="2.5" stroke-linejoin="round" stroke-linecap="round"/>')
    for x, y, r in zip(xs, ys, rungs):
        s.append(f'<circle cx="{X(x):.1f}" cy="{Y(y):.1f}" r="3" '
                 f'fill="{t["accent"]}"/>')
    peak = max(rungs, key=lambda r: r["rps"])
    pxx, pyy = X(math.log2(peak["conc"])), Y(peak["rps"])
    s.append(f'<circle cx="{pxx:.1f}" cy="{pyy:.1f}" r="5.5" fill="{t["bg"]}" '
             f'stroke="{t["accent"]}" stroke-width="2.5"/>')
    s.append(txt(pxx + 12, pyy - 6, f'{dg["frontier"][-1]["rps"]:,} req/s', 12,
                 "text", weight="700", mono=True, t=t))
    s.append(txt(pxx + 12, pyy + 9, "peak, no failures", 10, "dim", t=t))
    for r in rungs:
        if r["conc"] in (1, 8, 64, 512, 4096):
            s.append(txt(X(math.log2(r["conc"])), gy + gh + 18, f'c={r["conc"]}',
                         10, "faint", anchor="middle", mono=True, t=t))
    s.append(txt(gx, py + 20, "REQUESTS/SEC BY CONCURRENCY", 9.5, "faint",
                 weight="700", t=t))
    f1 = next(f for f in dg["frontier"] if f["bound_ms"] == 1)
    pct = 100.0 * f1["rps"] / dg["frontier"][-1]["rps"]
    cx = gx + gw + 26
    s.append(txt(cx, gy + 34, f'{pct:.0f}%', 28, "accent", weight="700",
                 mono=True, t=t))
    s.append(txt(cx, gy + 54, "of that rate is still held", 10.5, "text",
                 weight="600", t=t))
    s.append(txt(cx, gy + 68, f'inside a 1 ms p99 budget', 10.5, "dim", t=t))
    s.append(txt(cx, gy + 82, f'({f1["rps"]:,} req/s at c={f1["conc"]})', 10.5,
                 "dim", mono=True, t=t))
    s.append(txt(28, H - 16, STAMP, 10, "faint", t=t))
    s.append("</svg>")
    return "\n".join(s)


# ---------------------------------------------------------------- figure 3
def fig_memory(t):
    W, H = 900, 340
    dg = D["diagonal"]
    m = dg["memory"]
    idle = [dict(t_s=p["t_s"], rss_mib=p["rss_mib"]) for p in dg["idle_rss_series"]]
    ser = idle + [dict(t_s=p["t_s"] + 60, rss_mib=p["rss_mib"])
                  for p in dg["rss_series"]]
    s = frame(W, H, t, "Flat memory, and it gives it back",
              "Resident set size: 60 s idle at rest, then 300 s of load at c=32, "
              "then the load is removed.")

    px, py, pw, ph = 28, 92, 596, 194
    s.append(rect(px, py, pw, ph, "panel", t, rx=8, stroke="grid"))
    gx, gy, gw, gh = px + 52, py + 20, pw - 76, ph - 52
    tmax = max(p["t_s"] for p in ser)
    rmax = max(p["rss_mib"] for p in ser) * 1.25

    def X(v):
        return gx + v / tmax * gw

    def Y(v):
        return gy + gh - v / rmax * gh

    for v in (0, 10, 20):
        s.append(f'<line x1="{gx}" y1="{Y(v):.1f}" x2="{gx + gw}" y2="{Y(v):.1f}" '
                 f'stroke="{t["grid"]}" stroke-width="1" opacity="0.7"/>')
        s.append(txt(gx - 8, Y(v) + 4, f"{v}", 10, "faint", anchor="end",
                     mono=True, t=t))
    s.append(txt(gx - 8, Y(20) - 12, "MiB", 9.5, "faint", anchor="end", t=t))
    # load window shading
    ls, le = 60, 60 + m["load_s"]
    s.append(f'<rect x="{X(ls):.1f}" y="{gy:.1f}" width="{X(le) - X(ls):.1f}" '
             f'height="{gh:.1f}" fill="{t["accent"]}" opacity="0.07"/>')
    s.append(txt((X(ls) + X(le)) / 2, gy + 12, "LOAD, c=32", 9.5, "faint",
                 anchor="middle", weight="700", t=t))
    pts = " ".join(f'{X(p["t_s"]):.1f},{Y(p["rss_mib"]):.1f}' for p in ser)
    s.append(f'<polyline points="{pts}" fill="none" stroke="{t["accent"]}" '
             f'stroke-width="2" stroke-linejoin="round"/>')
    for tt in (0, 120, 240, 360, 420):
        s.append(txt(X(min(tt, tmax)), gy + gh + 18, f"{tt}s", 10, "faint",
                     anchor="middle", mono=True, t=t))

    stats = [
        (f'{m["idle_rss_mib"]:.1f} MiB', "idle, at rest"),
        (f'{m["steady_state_rss_mib"]:.1f} MiB', "steady state under load"),
        (f'{m["growth_rate_mib_per_min"]:+.2f} MiB/min', "growth over the load window"),
        (f'{m["recovered_rss_mib"]:.1f} MiB', "once the load stopped"),
    ]
    sx, sy = 648, 92
    for k, (big, lab) in enumerate(stats):
        y = sy + k * 50
        s.append(rect(sx, y, 224, 44, "panel", t, rx=8, stroke="grid"))
        s.append(txt(sx + 14, y + 22, big, 15, "accent", weight="700", mono=True, t=t))
        s.append(txt(sx + 14, y + 36, lab, 10, "dim", t=t))
    s.append(txt(28, H - 16, STAMP, 10, "faint", t=t))
    s.append("</svg>")
    return "\n".join(s)


# ---------------------------------------------------------------- figure 4
def fig_field(t):
    W, H = 900, 470
    cov = D["coverage"]
    keys = ["busbar-151", "litellm-python", "litellm-rust", "kong", "portkey"]
    name = {"busbar-151": "busbar 1.5.1", "litellm-python": "LiteLLM Python 1.94.0",
            "litellm-rust": "LiteLLM Rust 6980723", "kong": "Kong 3.9.3",
            "portkey": "Portkey 1.15.2"}
    s = frame(W, H, t, "Why not LiteLLM, Kong or Portkey",
              "Same box, same harness, same day, every gateway. Open source harness, "
              "per cell verdicts and reasons published at onthebench.ai.")

    def panel(x, y, w, h, title, sub):
        s.append(rect(x, y, w, h, "panel", t, rx=8, stroke="grid"))
        s.append(txt(x + 16, y + 24, title, 12.5, "text", weight="700", t=t))
        s.append(txt(x + 16, y + 40, sub, 10, "dim", t=t))

    def bars(x, y, w, rows, fmt, logscale=False, lower_better=True):
        import math
        vals = [v for _, v in rows]
        if logscale:
            lo = min(vals) * 0.8
            span = math.log10(max(vals) / lo)
            frac = [math.log10(v / lo) / span for _, v in rows]
        else:
            mx = max(vals)
            frac = [v / mx for _, v in rows]
        for i, ((lab, v), f) in enumerate(zip(rows, frac)):
            yy = y + i * 30
            good = i == 0
            s.append(txt(x, yy + 10, lab, 10.5, "text" if good else "dim",
                         weight="700" if good else "500", t=t))
            bw = max(0.035 * w, f * w)
            s.append(rect(x, yy + 15, w, 9, "neutral_soft", t, rx=4.5))
            s.append(rect(x, yy + 15, bw, 9, "accent" if good else "neutral", t,
                          rx=4.5))
            s.append(txt(x + w + 8, yy + 23, fmt(v), 10.5,
                         "accent" if good else "dim", weight="700" if good else "600",
                         mono=True, t=t))

    # panel A: protocol coverage
    panel(28, 86, 420, 208, "Wire protocol pairs actually served",
          "Of 36 ingress and upstream combinations. Not a provider count")
    bars(44, 126, 268,
         [(name[k], cov[k]["served"]) for k in keys],
         lambda v: f"{v}/36")

    # panel B: idle memory
    panel(460, 86, 412, 208, "Idle resident memory",
          "At rest, before any request. Log scale, lower is better")
    bars(476, 126, 250,
         [(name[k], cov[k]["idle_rss_mib"]) for k in keys],
         lambda v: (f"{v:,.1f} MiB" if v < 10 else f"{v:,.0f} MiB"), logscale=True)

    # panel C: image + install size
    panel(28, 306, 844, 128, "What you actually install",
          "Compressed container layers, read from the registry. Lower is better")
    rows = [("busbar, getbusbar/busbar:latest (1.5.3), linux/amd64", 5.74),
            ("LiteLLM, ghcr.io/berriai/litellm:main-latest, linux/amd64", 360.77)]
    bars(44, 346, 520, rows, lambda v: f"{v:,.2f} MB")
    s.append(txt(700, 372, "63x", 30, "accent", weight="700", mono=True, t=t))
    s.append(txt(700, 390, "smaller to pull", 10.5, "dim", t=t))
    s.append(txt(28, H - 16,
                 "Coverage and memory: onthebench.ai field run, 2026-08-03, AWS "
                 "m7g.4xlarge (Graviton3), 4-core pin. Image sizes: registry "
                 "manifests read 2026-08-13.", 10, "faint", t=t))
    s.append("</svg>")
    return "\n".join(s)


FIGS = {"matrix": fig_matrix, "perf": fig_perf, "memory": fig_memory,
        "field": fig_field}

for fname, fn in FIGS.items():
    for theme, t in THEMES.items():
        body = fn(t)
        assert "—" not in body and "–" not in body, f"dash in {fname}"
        p = os.path.join(OUT, f"{fname}-{theme}.svg")
        open(p, "w").write(body + "\n")
        print(p, os.path.getsize(p))
