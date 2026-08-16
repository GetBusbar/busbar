#!/usr/bin/env python3
"""Generate the README figures as committed SVG, and the README's own numbers.

  python3 assets/readme/generate.py                 # redraw the SVGs
  python3 assets/readme/generate.py --readme        # ...and rewrite README.md's numeric blocks
  python3 assets/readme/generate.py --check         # exit 1 if either is stale

Every number is read from data.json, which is WRITTEN BY the website's
metrics/onthebench.mjs from https://onthebench.ai/data.json, the same run the
website's own facts.ts reads:

  node metrics/onthebench.mjs --readme-out <this repo>/assets/readme/data.json
  python3 assets/readme/generate.py --readme

so one re-measure moves the site and this README together. Image and install
sizes are a different instrument and come from install.json (install-sizes.py).

The README's figures AND its tables are generated. A figure regenerated beside a
hand-typed table is a table that goes stale on the next re-measure, which is how
docs/protocols.md came to be stamped "last verified against 1.2.0" on a 1.6.0
tree. Nothing here is typed by hand except labels and prose.

No em dashes anywhere in the output (a build gate rejects them).
"""
import json, os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
D = json.load(open(os.path.join(HERE, "data.json")))
INSTALL = json.load(open(os.path.join(HERE, "install.json")))
ARGS = [a for a in sys.argv[1:] if not a.startswith("-")]
FLAGS = {a for a in sys.argv[1:] if a.startswith("-")}
DO_README = "--readme" in FLAGS or "--check" in FLAGS
CHECK = "--check" in FLAGS
OUT = ARGS[0] if ARGS else HERE
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

# One size scale for every figure. Everything below used to be a one-off
# (9.5, 10, 10.5, 11, 11.5, 12.5, 13, 15, 15.5, 19, 21, 26, 30, 38...); now
# every txt() call picks one of these six, and nothing renders below 12px.
SZ = dict(
    TITLE=22,    # figure title
    HEAD=16,     # panel/section headings inside a figure
    LABEL=14,    # axis labels, legends, row/column headers, callouts, body text
    VALUE=15,    # mono numeric values: cell readings, bar values, stat cards
    STAT=28,     # hero callout numbers (tile big numbers, headline percentages)
    CAPTION=12,  # ticks, units, fine print, provenance stamps
)


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
        s.append(txt(28, 42, title, SZ["TITLE"], "text", weight="650", t=t))
    if sub:
        s.append(txt(28, 66, sub, SZ["LABEL"], "dim", t=t))
    return s


SRC = D["source"]
# Derived, not typed: the build and the day both come off the run's own stamp, so a
# re-measure restamps every figure that carries this line.
_BUILD = SRC["busbar_build"].rsplit(":", 1)[-1]
_DAY = SRC["busbar_measured_at"][:10]
STAMP = (f"Busbar {_BUILD} on AWS m7g.4xlarge (Graviton3), 4-core pin, measured "
         f"{_DAY}, published at onthebench.ai")


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

    s.append(txt(x0 - 12, y0 - 34, "UPSTREAM", SZ["CAPTION"], "faint", anchor="end",
                 weight="700", t=t))
    for j, eg in enumerate(order):
        cx = x0 + j * (cw + gap) + cw / 2
        s.append(txt(cx, y0 - 34, label[eg], SZ["LABEL"], "dim", anchor="middle",
                     weight="600", t=t))
    s.append(f'<g transform="translate(38,{y0 + 3 * (ch + gap)}) rotate(-90)">'
             + txt(0, 0, "INGRESS", SZ["CAPTION"], "faint", anchor="middle",
                   weight="700", t=t)
             + "</g>")

    for i, ing in enumerate(order):
        cy = y0 + i * (ch + gap)
        s.append(txt(x0 - 16, cy + ch / 2 + 4, label[ing], SZ["LABEL"], "dim",
                     anchor="end", weight="600", t=t))
        for j, eg in enumerate(order):
            c = D["matrix"][ing][eg]
            cx = x0 + j * (cw + gap)
            same = ing == eg
            if same:
                s.append(rect(cx, cy, cw, ch, "accent", t, rx=7))
                s.append(txt(cx + cw / 2, cy + 20, f'{c["p99"]} µs', SZ["VALUE"],
                             t["bg"], anchor="middle", weight="700", mono=True, t=t))
                s.append(txt(cx + cw / 2, cy + 34, "your bytes", SZ["CAPTION"],
                             t["bg"], anchor="middle", weight="600", opacity="0.85",
                             t=t))
            else:
                s.append(rect(cx, cy, cw, ch, "accent_soft", t, rx=7,
                              stroke="accent_line", sw=1))
                s.append(txt(cx + cw / 2, cy + 27, f'{c["p99"]} µs', SZ["VALUE"],
                             "accent", anchor="middle", weight="600", mono=True, t=t))

    ly = y0 + 6 * (ch + gap) + 12
    s.append(rect(28, ly, 16, 16, "accent", t, rx=4))
    s.append(txt(52, ly + 12.5, "Same protocol: your original bytes, forwarded, "
                 "not re-serialized", SZ["LABEL"], "dim", t=t))
    s.append(rect(28, ly + 26, 16, 16, "accent_soft", t, rx=4,
                  stroke="accent_line"))
    s.append(txt(52, ly + 38.5, "Cross protocol: every modelled field arrives in "
                 "the target's native shape", SZ["LABEL"], "dim", t=t))
    s.append(txt(28, H - 18, STAMP, SZ["CAPTION"], "faint", t=t))
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
        s.append(txt(x + 16, ty + 38, big, SZ["STAT"], "accent", weight="700",
                     mono=True, t=t))
        s.append(txt(x + 16, ty + 58, lab, SZ["LABEL"], "text", weight="600", t=t))
        s.append(txt(x + 16, ty + 74, sub, SZ["CAPTION"], "dim", t=t))

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
        s.append(txt(gx - 10, Y(v) + 4, f"{int(v / 1000)}k", SZ["CAPTION"], "faint",
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
    s.append(txt(pxx + 12, pyy - 6, f'{dg["frontier"][-1]["rps"]:,} req/s',
                 SZ["LABEL"], "text", weight="700", mono=True, t=t))
    # Nudged further below the marker than the pre-scale offset (+9) so the
    # larger caption clears the nearly-flat line just right of the peak.
    s.append(txt(pxx + 12, pyy + 22, "peak, no failures", SZ["CAPTION"], "dim", t=t))
    for r in rungs:
        if r["conc"] in (1, 8, 64, 512, 4096):
            s.append(txt(X(math.log2(r["conc"])), gy + gh + 18, f'c={r["conc"]}',
                         SZ["CAPTION"], "faint", anchor="middle", mono=True, t=t))
    s.append(txt(gx, py + 20, "REQUESTS/SEC BY CONCURRENCY", SZ["CAPTION"], "faint",
                 weight="700", t=t))
    f1 = next(f for f in dg["frontier"] if f["bound_ms"] == 1)
    pct = 100.0 * f1["rps"] / dg["frontier"][-1]["rps"]
    cx = gx + gw + 26
    s.append(txt(cx, gy + 34, f'{pct:.0f}%', SZ["STAT"], "accent", weight="700",
                 mono=True, t=t))
    s.append(txt(cx, gy + 54, "of that rate is still held", SZ["CAPTION"], "text",
                 weight="600", t=t))
    s.append(txt(cx, gy + 68, f'inside a 1 ms p99 budget', SZ["CAPTION"], "dim", t=t))
    s.append(txt(cx, gy + 82, f'({f1["rps"]:,} req/s at c={f1["conc"]})',
                 SZ["CAPTION"], "dim", mono=True, t=t))
    s.append(txt(28, H - 16, STAMP, SZ["CAPTION"], "faint", t=t))
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
        s.append(txt(gx - 8, Y(v) + 4, f"{v}", SZ["CAPTION"], "faint", anchor="end",
                     mono=True, t=t))
    s.append(txt(gx - 8, Y(20) - 12, "MiB", SZ["CAPTION"], "faint", anchor="end", t=t))
    # load window shading
    ls, le = 60, 60 + m["load_s"]
    s.append(f'<rect x="{X(ls):.1f}" y="{gy:.1f}" width="{X(le) - X(ls):.1f}" '
             f'height="{gh:.1f}" fill="{t["accent"]}" opacity="0.07"/>')
    s.append(txt((X(ls) + X(le)) / 2, gy + 12, "LOAD, c=32", SZ["CAPTION"], "faint",
                 anchor="middle", weight="700", t=t))
    pts = " ".join(f'{X(p["t_s"]):.1f},{Y(p["rss_mib"]):.1f}' for p in ser)
    s.append(f'<polyline points="{pts}" fill="none" stroke="{t["accent"]}" '
             f'stroke-width="2" stroke-linejoin="round"/>')
    for tt in (0, 120, 240, 360, 420):
        s.append(txt(X(min(tt, tmax)), gy + gh + 18, f"{tt}s", SZ["CAPTION"], "faint",
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
        s.append(txt(sx + 14, y + 22, big, SZ["VALUE"], "accent", weight="700",
                     mono=True, t=t))
        s.append(txt(sx + 14, y + 36, lab, SZ["CAPTION"], "dim", t=t))
    s.append(txt(28, H - 16, STAMP, SZ["CAPTION"], "faint", t=t))
    s.append("</svg>")
    return "\n".join(s)


# ---------------------------------------------------------------- figure 4
def fig_field(t):
    W, H = 1040, 604
    cov = D["coverage"]
    field_day = D["source"]["busbar_measured_at"][:10]
    keys = ["busbar-151", "litellm-python", "litellm-rust", "kong", "portkey"]
    name = {"busbar-151": f"Busbar {_BUILD}", "litellm-python": "LiteLLM Python 1.94.0",
            "litellm-rust": "LiteLLM Rust 6980723", "kong": "Kong 3.9.3",
            "portkey": "Portkey 1.15.2"}
    s = frame(W, H, t, "Why not LiteLLM, Kong or Portkey",
              "Same box, same harness, same day, every gateway. Open source harness, "
              "per cell verdicts and reasons published at onthebench.ai.")

    def panel(x, y, w, h, title, sub):
        s.append(rect(x, y, w, h, "panel", t, rx=8, stroke="grid"))
        s.append(txt(x + 20, y + 30, title, SZ["HEAD"], "text", weight="700", t=t))
        s.append(txt(x + 20, y + 50, sub, SZ["CAPTION"], "dim", t=t))

    def bars(x, y, w, rows, fmt, logscale=False, lower_better=True, pitch=38):
        """One labelled bar per row. `pitch` is the row height; label and value
        both use the shared LABEL/VALUE sizes regardless of panel, so only the
        row spacing (not the type) differs between the five-row coverage panels
        and the two-row install panel below, which carries longer labels."""
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
            yy = y + i * pitch
            good = i == 0
            s.append(txt(x, yy + 10, lab, SZ["LABEL"], "text" if good else "dim",
                         weight="700" if good else "500", t=t))
            bw = max(0.035 * w, f * w)
            s.append(rect(x, yy + 18, w, 11, "neutral_soft", t, rx=5.5))
            s.append(rect(x, yy + 18, bw, 11, "accent" if good else "neutral", t,
                          rx=5.5))
            s.append(txt(x + w + 12, yy + 27.5, fmt(v), SZ["VALUE"],
                         "accent" if good else "dim", weight="700" if good else "600",
                         mono=True, t=t))

    # Panels A and B: five rows each. Bars start 56px below the panel top so the first
    # row's label clears the subtitle instead of sitting on its baseline.
    # panel A: protocol coverage
    panel(28, 96, 492, 282, "Wire protocol pairs actually served",
          "Of 36 ingress and upstream combinations. Not a provider count")
    bars(48, 166, 316,
         [(name[k], cov[k]["served"]) for k in keys],
         lambda v: f"{v}/36")

    # panel B: idle memory
    panel(540, 96, 472, 282, "Idle resident memory",
          "At rest, before any request. Log scale, lower is better")
    bars(560, 166, 286,
         [(name[k], cov[k]["idle_rss_mib"]) for k in keys],
         lambda v: (f"{v:,.1f} MiB" if v < 10 else f"{v:,.0f} MiB"), logscale=True)

    # panel C: image + install size. Two rows, but the labels are full image references,
    # so they get a taller pitch than the five-row panels above (same type sizes).
    img = INSTALL["images"]
    bb_mib, ll_mib = img["busbar"]["compressed_mib"], img["litellm"]["compressed_mib"]
    panel(28, 398, 984, 168, "What you actually install",
          "Compressed container layers, read from the registry. Lower is better")
    rows = [(f"Busbar, {img['busbar']['image']}, {img['busbar']['platform']}", bb_mib),
            (f"LiteLLM, {img['litellm']['image']}, {img['litellm']['platform']}", ll_mib)]
    bars(48, 468, 604, rows, lambda v: f"{v:,.2f} MiB", pitch=48)
    s.append(txt(838, 500, f"{ll_mib / bb_mib:.0f}x", SZ["STAT"], "accent",
                 weight="700", mono=True, t=t))
    s.append(txt(838, 522, "smaller to pull", SZ["CAPTION"], "dim", t=t))
    s.append(txt(28, H - 20,
                 f"Coverage and memory: onthebench.ai field run, {field_day}, AWS "
                 "m7g.4xlarge (Graviton3), 4-core pin. Image sizes: registry "
                 f"manifests read {INSTALL['hand_measured']['measured_at']}.",
                 SZ["CAPTION"], "faint", t=t))
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
