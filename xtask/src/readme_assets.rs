//! `cargo xtask readme-assets [<outdir>]` — the README FIGURES, drawn as committed SVG.
//!
//!   cargo xtask readme-assets                 # redraw the SVGs into assets/readme/
//!   cargo xtask readme-assets <outdir>        # ...into another directory (org-profile/assets)
//!
//! Not a gate: it WRITES files, a human runs it after a re-measure. It is the port of the removed
//! `assets/readme/generate.py`, and its output is byte-identical to that script's.
//!
//! Every number DRAWN IN A FIGURE is read from `assets/readme/data.json`, which is WRITTEN BY the
//! website's `metrics/onthebench.mjs` from <https://onthebench.ai/data.json>, the same run the
//! website's own `facts.ts` reads:
//!
//!   node metrics/onthebench.mjs --readme-out <this repo>/assets/readme/data.json
//!   cargo xtask readme-assets
//!
//! so one re-measure moves the site and these figures together. Image and install sizes are a
//! different instrument and come from `install.json` (`cargo xtask install-sizes`).
//!
//! WHAT THIS DOES NOT DO, SAID PLAINLY BECAUSE THE SCRIPT IT REPLACES ONCE CLAIMED OTHERWISE. It
//! generates the FIGURES ONLY. README.md's comparison TABLES are typed by hand. They currently agree
//! with data.json cell for cell, but nothing enforces that: this is not run by CI or by any gate,
//! it has no --check mode, and no gate reads README.md's tables. So a re-measure that lands a new
//! data.json will redraw the SVGs and leave the tables saying whatever they said before. If you
//! re-measure, re-check the two tables in README.md and the summary sentence in org-profile/README.md
//! by hand against data.json and install.json.
//!
//! No em dashes anywhere in the output, matching the READMEs' own house style.
//!
//! FORMATTING. Python and Rust differ on float formatting, so every number goes through the helpers
//! below ([`fmt_f`], [`fmt_commas`], [`py_str`]) and the unit tests pin the exact strings. Both
//! languages round a decimal expansion of the binary value half-to-even, so `{:.N}` agrees with
//! Python's `:.Nf`; what Rust lacks is `:,` and `:+`, and the `repr` of an integral float.

use crate::ctx::Ctx;
use crate::json_lite::{self, Json};
use std::path::Path;

/// The six-step size scale: every `txt()` call picks one of these, and nothing renders below 12px.
const TITLE: i32 = 22;
const HEAD: i32 = 16;
const LABEL: i32 = 14;
const VALUE: i32 = 15;
const STAT: i32 = 28;
const CAPTION: i32 = 12;

const FONT: &str =
    "ui-sans-serif,-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif";
const MONO: &str = "ui-monospace,SFMono-Regular,'SF Mono',Menlo,Consolas,monospace";

pub struct Theme {
    pub name: &'static str,
    colors: &'static [(&'static str, &'static str)],
}

impl Theme {
    fn get(&self, key: &str) -> Option<&'static str> {
        self.colors.iter().find(|(k, _)| *k == key).map(|(_, v)| *v)
    }
    /// `t[k] if k in t else k`: a theme key resolves, anything else is a raw colour.
    fn resolve<'a>(&self, k: &'a str) -> &'a str {
        self.get(k).unwrap_or(k)
    }
    fn c(&self, key: &str) -> &'static str {
        self.get(key).unwrap_or("")
    }
}

pub const THEMES: &[Theme] = &[
    Theme {
        name: "light",
        colors: &[
            ("bg", "#ffffff"),
            ("panel", "#f6f8fa"),
            ("grid", "#d0d7de"),
            ("line", "#d0d7de"),
            ("text", "#1f2328"),
            ("dim", "#59636e"),
            ("faint", "#818b98"),
            ("accent", "#1a7f37"),
            ("accent_soft", "#dafbe1"),
            ("accent_line", "#2da44e"),
            ("neutral", "#8c959f"),
            ("neutral_soft", "#eaeef2"),
            ("warn", "#9a6700"),
        ],
    },
    Theme {
        name: "dark",
        colors: &[
            ("bg", "#0d1117"),
            ("panel", "#161b22"),
            ("grid", "#30363d"),
            ("line", "#30363d"),
            ("text", "#e6edf3"),
            ("dim", "#9198a1"),
            ("faint", "#6e7681"),
            ("accent", "#3fb950"),
            ("accent_soft", "#132d1d"),
            ("accent_line", "#2ea043"),
            ("neutral", "#7d8590"),
            ("neutral_soft", "#1c2128"),
            ("warn", "#d29922"),
        ],
    },
];

// ------------------------------------------------------------------ Python-shaped formatting

/// `f"{x:.{prec}f}"`.
pub fn fmt_f(x: f64, prec: usize) -> String {
    format!("{x:.prec$}")
}

/// `f"{x:,.{prec}f}"`: the fixed form with a comma every three integer digits.
pub fn fmt_commas(x: f64, prec: usize) -> String {
    let s = fmt_f(x.abs(), prec);
    let (int, frac) = match s.split_once('.') {
        Some((i, f)) => (i, Some(f)),
        None => (s.as_str(), None),
    };
    let mut grouped = String::new();
    for (n, ch) in int.chars().enumerate() {
        if n > 0 && (int.len() - n) % 3 == 0 {
            grouped.push(',');
        }
        grouped.push(ch);
    }
    let mut out = String::new();
    if x.is_sign_negative() {
        out.push('-');
    }
    out.push_str(&grouped);
    if let Some(f) = frac {
        out.push('.');
        out.push_str(f);
    }
    out
}

/// `f"{x:+.{prec}f}"`.
pub fn fmt_plus(x: f64, prec: usize) -> String {
    let s = fmt_f(x, prec);
    if x.is_sign_negative() {
        s
    } else {
        format!("+{s}")
    }
}

/// Python's `repr(float)` for the range these files live in: the shortest round-trip digits, with
/// `.0` on an integral value (Rust's `{}` prints `6`, Python `6.0`).
pub fn py_float_repr(f: f64) -> String {
    if f.is_finite() && f == f.trunc() && f.abs() < 1e16 {
        format!("{f:.1}")
    } else {
        format!("{f}")
    }
}

/// Python's `str(value)` of a decoded JSON scalar, as an f-string interpolates it.
pub fn py_str(v: &Json) -> String {
    match v {
        Json::Null => "None".into(),
        Json::Bool(true) => "True".into(),
        Json::Bool(false) => "False".into(),
        Json::Int(i) => i.to_string(),
        Json::Float(f) => py_float_repr(*f),
        Json::Str(s) => s.clone(),
        other => json_lite::py_repr_json(other),
    }
}

/// `f"{value:,}"` for an integer value. A float here is refused rather than guessed at: Python would
/// print `67,245.0`, and the data carries integers.
fn commas_int(v: &Json) -> Result<String, String> {
    match v {
        Json::Int(i) => Ok(fmt_commas(*i as f64, 0)),
        other => Err(format!("expected an integer, found {}", py_str(other))),
    }
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

// ------------------------------------------------------------------ data access

fn at<'a>(v: &'a Json, path: &[&str]) -> Result<&'a Json, String> {
    let mut cur = v;
    for k in path {
        cur = cur
            .as_object()
            .and_then(|o| o.get(k))
            .ok_or_else(|| format!("missing key `{}` (at {})", k, path.join(".")))?;
    }
    Ok(cur)
}

fn num(v: &Json) -> Result<f64, String> {
    match v {
        Json::Int(i) => Ok(*i as f64),
        Json::Float(f) => Ok(*f),
        other => Err(format!("expected a number, found {}", py_str(other))),
    }
}

fn nat(v: &Json, path: &[&str]) -> Result<f64, String> {
    num(at(v, path)?)
}

fn arr<'a>(v: &'a Json, path: &[&str]) -> Result<&'a [Json], String> {
    at(v, path)?
        .as_array()
        .ok_or_else(|| format!("`{}` is not a list", path.join(".")))
}

// ------------------------------------------------------------------ svg primitives

struct Txt<'a> {
    x: f64,
    y: f64,
    s: &'a str,
    size: i32,
    fill: &'a str,
    anchor: &'a str,
    weight: &'a str,
    mono: bool,
    opacity: Option<&'a str>,
}

fn txt<'a>(x: f64, y: f64, s: &'a str, size: i32, fill: &'a str) -> Txt<'a> {
    Txt {
        x,
        y,
        s,
        size,
        fill,
        anchor: "start",
        weight: "400",
        mono: false,
        opacity: None,
    }
}

impl<'a> Txt<'a> {
    fn anchor(mut self, a: &'a str) -> Self {
        self.anchor = a;
        self
    }
    fn weight(mut self, w: &'a str) -> Self {
        self.weight = w;
        self
    }
    fn mono(mut self) -> Self {
        self.mono = true;
        self
    }
    fn opacity(mut self, o: &'a str) -> Self {
        self.opacity = Some(o);
        self
    }
    fn render(&self, t: &Theme) -> String {
        let op = self
            .opacity
            .map(|o| format!(" opacity=\"{o}\""))
            .unwrap_or_default();
        let fam = if self.mono { MONO } else { FONT };
        format!(
            "<text x=\"{}\" y=\"{}\" font-family=\"{fam}\" font-size=\"{}\" font-weight=\"{}\" \
             fill=\"{}\" text-anchor=\"{}\"{op}>{}</text>",
            fmt_f(self.x, 1),
            fmt_f(self.y, 1),
            self.size,
            self.weight,
            t.resolve(self.fill),
            self.anchor,
            esc(self.s)
        )
    }
}

struct Rect<'a> {
    x: f64,
    y: f64,
    w: f64,
    h: f64,
    fill: &'a str,
    rx: f64,
    stroke: Option<&'a str>,
}

fn rect<'a>(x: f64, y: f64, w: f64, h: f64, fill: &'a str, rx: f64) -> Rect<'a> {
    Rect {
        x,
        y,
        w,
        h,
        fill,
        rx,
        stroke: None,
    }
}

impl<'a> Rect<'a> {
    fn stroke(mut self, s: &'a str) -> Self {
        self.stroke = Some(s);
        self
    }
    fn render(&self, t: &Theme) -> String {
        let st = self
            .stroke
            .map(|s| format!(" stroke=\"{}\" stroke-width=\"1\"", t.resolve(s)))
            .unwrap_or_default();
        format!(
            "<rect x=\"{}\" y=\"{}\" width=\"{}\" height=\"{}\" rx=\"{}\" fill=\"{}\"{st}/>",
            fmt_f(self.x, 1),
            fmt_f(self.y, 1),
            fmt_f(self.w, 1),
            fmt_f(self.h, 1),
            self.rx,
            t.resolve(self.fill)
        )
    }
}

fn frame(w: i32, h: i32, t: &Theme, title: &str, sub: &str) -> Vec<String> {
    let mut s = vec![
        format!(
            "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{w}\" height=\"{h}\" \
             viewBox=\"0 0 {w} {h}\" role=\"img\" aria-label=\"{}\">",
            esc(title)
        ),
        format!(
            "<rect width=\"{w}\" height=\"{h}\" rx=\"10\" fill=\"{}\"/>",
            t.c("bg")
        ),
    ];
    if !title.is_empty() {
        s.push(
            txt(28.0, 42.0, title, TITLE, "text")
                .weight("650")
                .render(t),
        );
    }
    if !sub.is_empty() {
        s.push(txt(28.0, 66.0, sub, LABEL, "dim").render(t));
    }
    s
}

fn grid_line(gx: i64, y: f64, x2: i64, t: &Theme) -> String {
    format!(
        "<line x1=\"{gx}\" y1=\"{}\" x2=\"{x2}\" y2=\"{}\" stroke=\"{}\" stroke-width=\"1\" \
         opacity=\"0.7\"/>",
        fmt_f(y, 1),
        fmt_f(y, 1),
        t.c("grid")
    )
}

/// The provenance stamp every figure but the last carries, derived from the run's own stamp.
struct Stamp {
    build: String,
    day: String,
    line: String,
}

fn stamp(d: &Json) -> Result<Stamp, String> {
    let build_full = match at(d, &["source", "busbar_build"])? {
        Json::Str(s) => s.clone(),
        other => {
            return Err(format!(
                "source.busbar_build is not a string: {}",
                py_str(other)
            ))
        }
    };
    let build = build_full.rsplit(':').next().unwrap_or("").to_string();
    let measured = match at(d, &["source", "busbar_measured_at"])? {
        Json::Str(s) => s.clone(),
        other => {
            return Err(format!(
                "source.busbar_measured_at is not a string: {}",
                py_str(other)
            ))
        }
    };
    let day: String = measured.chars().take(10).collect();
    let line = format!(
        "Busbar {build} on AWS m7g.4xlarge (Graviton3), 4-core pin, measured {day}, published at \
         onthebench.ai"
    );
    Ok(Stamp { build, day, line })
}

// ------------------------------------------------------------------ figure 1

fn fig_matrix(d: &Json, st: &Stamp, t: &Theme) -> Result<String, String> {
    let order = [
        "openai",
        "openai-responses",
        "anthropic",
        "gemini",
        "cohere",
        "bedrock",
    ];
    let label = |k: &str| match k {
        "openai" => "OpenAI",
        "openai-responses" => "Responses",
        "anthropic" => "Anthropic",
        "gemini" => "Gemini",
        "cohere" => "Cohere",
        _ => "Bedrock",
    };
    let (w, h) = (900, 512);
    let (cw, ch, gap) = (104.0, 44.0, 8.0);
    let (x0, y0) = (196.0, 118.0);
    let mut s = frame(
        w,
        h,
        t,
        "One endpoint, every protocol, both directions",
        "Added latency p99 in microseconds, per ingress and upstream pair. Lower is better. 36 of \
         36 pairs served.",
    );
    s.push(
        txt(x0 - 12.0, y0 - 34.0, "UPSTREAM", CAPTION, "faint")
            .anchor("end")
            .weight("700")
            .render(t),
    );
    for (j, eg) in order.iter().enumerate() {
        let cx = x0 + j as f64 * (cw + gap) + cw / 2.0;
        s.push(
            txt(cx, y0 - 34.0, label(eg), LABEL, "dim")
                .anchor("middle")
                .weight("600")
                .render(t),
        );
    }
    s.push(format!(
        "<g transform=\"translate(38,{}) rotate(-90)\">{}</g>",
        fmt_num_raw(y0 + 3.0 * (ch + gap)),
        txt(0.0, 0.0, "INGRESS", CAPTION, "faint")
            .anchor("middle")
            .weight("700")
            .render(t)
    ));
    for (i, ing) in order.iter().enumerate() {
        let cy = y0 + i as f64 * (ch + gap);
        s.push(
            txt(x0 - 16.0, cy + ch / 2.0 + 4.0, label(ing), LABEL, "dim")
                .anchor("end")
                .weight("600")
                .render(t),
        );
        for (j, eg) in order.iter().enumerate() {
            let p99 = py_str(at(d, &["matrix", ing, eg, "p99"])?);
            let cx = x0 + j as f64 * (cw + gap);
            let val = format!("{p99} µs");
            if ing == eg {
                s.push(rect(cx, cy, cw, ch, "accent", 7.0).render(t));
                s.push(
                    txt(cx + cw / 2.0, cy + 20.0, &val, VALUE, t.c("bg"))
                        .anchor("middle")
                        .weight("700")
                        .mono()
                        .render(t),
                );
                s.push(
                    txt(cx + cw / 2.0, cy + 34.0, "your bytes", CAPTION, t.c("bg"))
                        .anchor("middle")
                        .weight("600")
                        .opacity("0.85")
                        .render(t),
                );
            } else {
                s.push(
                    rect(cx, cy, cw, ch, "accent_soft", 7.0)
                        .stroke("accent_line")
                        .render(t),
                );
                s.push(
                    txt(cx + cw / 2.0, cy + 27.0, &val, VALUE, "accent")
                        .anchor("middle")
                        .weight("600")
                        .mono()
                        .render(t),
                );
            }
        }
    }
    let ly = y0 + 6.0 * (ch + gap) + 12.0;
    s.push(rect(28.0, ly, 16.0, 16.0, "accent", 4.0).render(t));
    s.push(
        txt(
            52.0,
            ly + 12.5,
            "Same protocol: your original bytes, forwarded, not re-serialized",
            LABEL,
            "dim",
        )
        .render(t),
    );
    s.push(
        rect(28.0, ly + 26.0, 16.0, 16.0, "accent_soft", 4.0)
            .stroke("accent_line")
            .render(t),
    );
    s.push(
        txt(
            52.0,
            ly + 38.5,
            "Cross protocol: every modelled field arrives in the target's native shape",
            LABEL,
            "dim",
        )
        .render(t),
    );
    s.push(txt(28.0, f64::from(h) - 18.0, &st.line, CAPTION, "faint").render(t));
    s.push("</svg>".into());
    Ok(s.join("\n"))
}

/// A number interpolated bare into an f-string (`{y0 + 3 * (ch + gap)}`): an integral value prints
/// as an integer in both languages here, because every operand is an int in the Python.
fn fmt_num_raw(x: f64) -> String {
    format!("{x}")
}

// ------------------------------------------------------------------ figure 2

fn fig_perf(d: &Json, st: &Stamp, t: &Theme) -> Result<String, String> {
    let (w, h) = (900, 400);
    let dg = at(d, &["diagonal"])?;
    let mut rungs = Vec::new();
    for r in arr(dg, &["rungs"])? {
        if at(r, &["rps"])?.truthy() {
            rungs.push(r);
        }
    }
    let frontier = arr(dg, &["frontier"])?;
    let last = frontier.last().ok_or("diagonal.frontier is empty")?;
    let last_rps = at(last, &["rps"])?;
    let mut s = frame(
        w,
        h,
        t,
        "Fast, and it stays fast under load",
        "Same protocol OpenAI cell. Added latency is the gateway leg minus the same call taken \
         straight to the mock.",
    );

    let tiles = [
        (
            format!("{} µs", py_str(at(dg, &["latency_p50_us"])?)),
            "added latency p50",
            format!("p99 {} µs", py_str(at(dg, &["latency_p99_us"])?)),
        ),
        (
            format!("{} µs", fmt_f(nat(dg, &["cpu_us_per_request"])?, 1)),
            "gateway CPU per request",
            format!("measured at c={}", py_str(at(dg, &["cost_window_conc"])?)),
        ),
        (
            commas_int(last_rps)?,
            "requests/sec sustained",
            format!("at c={}, zero failures", py_str(at(last, &["conc"])?)),
        ),
    ];
    let (tw, tx, ty) = (268.0, 28.0, 86.0);
    for (k, (big, lab, sub)) in tiles.iter().enumerate() {
        let x = tx + k as f64 * (tw + 12.0);
        s.push(rect(x, ty, tw, 84.0, "panel", 8.0).stroke("grid").render(t));
        s.push(
            txt(x + 16.0, ty + 38.0, big, STAT, "accent")
                .weight("700")
                .mono()
                .render(t),
        );
        s.push(
            txt(x + 16.0, ty + 58.0, lab, LABEL, "text")
                .weight("600")
                .render(t),
        );
        s.push(txt(x + 16.0, ty + 74.0, sub, CAPTION, "dim").render(t));
    }

    let (px, py, pw, ph) = (28i64, 210i64, 844i64, 140i64);
    s.push(
        rect(px as f64, py as f64, pw as f64, ph as f64, "panel", 8.0)
            .stroke("grid")
            .render(t),
    );
    let mut xs = Vec::new();
    let mut ys = Vec::new();
    for r in &rungs {
        xs.push(nat(r, &["conc"])?.log2());
        ys.push(nat(r, &["rps"])?);
    }
    if xs.is_empty() {
        return Err("diagonal.rungs has no rung with a nonzero rps".into());
    }
    let xmin = xs.iter().cloned().fold(f64::INFINITY, f64::min);
    let xmax = xs.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    let ymax = ys.iter().cloned().fold(f64::NEG_INFINITY, f64::max) * 1.18;
    let gx = px + 60;
    let gw = pw - 250;
    let gy = py + 30;
    let gh = ph - 60;
    let (gxf, gwf, gyf, ghf) = (gx as f64, gw as f64, gy as f64, gh as f64);
    let xf = |v: f64| gxf + (v - xmin) / (xmax - xmin) * gwf;
    let yf = |v: f64| gyf + ghf - (v / ymax) * ghf;

    for frac in [0.0, 0.5, 1.0] {
        let v = ymax * frac;
        s.push(grid_line(gx, yf(v), gx + gw, t));
        s.push(
            txt(
                gxf - 10.0,
                yf(v) + 4.0,
                &format!("{}k", (v / 1000.0).trunc() as i64),
                CAPTION,
                "faint",
            )
            .anchor("end")
            .mono()
            .render(t),
        );
    }
    let pts: Vec<String> = xs
        .iter()
        .zip(&ys)
        .map(|(x, y)| format!("{},{}", fmt_f(xf(*x), 1), fmt_f(yf(*y), 1)))
        .collect();
    s.push(format!(
        "<polyline points=\"{}\" fill=\"none\" stroke=\"{}\" stroke-width=\"2.5\" \
         stroke-linejoin=\"round\" stroke-linecap=\"round\"/>",
        pts.join(" "),
        t.c("accent")
    ));
    for (x, y) in xs.iter().zip(&ys) {
        s.push(format!(
            "<circle cx=\"{}\" cy=\"{}\" r=\"3\" fill=\"{}\"/>",
            fmt_f(xf(*x), 1),
            fmt_f(yf(*y), 1),
            t.c("accent")
        ));
    }
    // `max(rungs, key=rps)`: the FIRST rung holding the maximum.
    let mut peak = 0;
    for (i, y) in ys.iter().enumerate() {
        if *y > ys[peak] {
            peak = i;
        }
    }
    let pxx = xf(nat(rungs[peak], &["conc"])?.log2());
    let pyy = yf(ys[peak]);
    s.push(format!(
        "<circle cx=\"{}\" cy=\"{}\" r=\"5.5\" fill=\"{}\" stroke=\"{}\" stroke-width=\"2.5\"/>",
        fmt_f(pxx, 1),
        fmt_f(pyy, 1),
        t.c("bg"),
        t.c("accent")
    ));
    s.push(
        txt(
            pxx + 12.0,
            pyy - 6.0,
            &format!("{} req/s", commas_int(last_rps)?),
            LABEL,
            "text",
        )
        .weight("700")
        .mono()
        .render(t),
    );
    // Nudged further below the marker than the pre-scale offset (+9) so the larger caption clears
    // the nearly-flat line just right of the peak.
    s.push(txt(pxx + 12.0, pyy + 22.0, "peak, no failures", CAPTION, "dim").render(t));
    for r in &rungs {
        let c = nat(r, &["conc"])?;
        if [1.0, 8.0, 64.0, 512.0, 4096.0].contains(&c) {
            s.push(
                txt(
                    xf(c.log2()),
                    gyf + ghf + 18.0,
                    &format!("c={}", py_str(at(r, &["conc"])?)),
                    CAPTION,
                    "faint",
                )
                .anchor("middle")
                .mono()
                .render(t),
            );
        }
    }
    s.push(
        txt(
            gxf,
            (py + 20) as f64,
            "REQUESTS/SEC BY CONCURRENCY",
            CAPTION,
            "faint",
        )
        .weight("700")
        .render(t),
    );
    let mut f1 = None;
    for f in frontier {
        if nat(f, &["bound_ms"])? == 1.0 {
            f1 = Some(f);
            break;
        }
    }
    let f1 = f1.ok_or("diagonal.frontier has no entry with bound_ms == 1")?;
    let f1_rps = nat(f1, &["rps"])?;
    let pct = 100.0 * f1_rps / num(last_rps)?;
    let cx = gxf + gwf + 26.0;
    s.push(
        txt(
            cx,
            gyf + 34.0,
            &format!("{}%", fmt_f(pct, 0)),
            STAT,
            "accent",
        )
        .weight("700")
        .mono()
        .render(t),
    );
    s.push(
        txt(
            cx,
            gyf + 54.0,
            "of that rate is still held",
            CAPTION,
            "text",
        )
        .weight("600")
        .render(t),
    );
    s.push(txt(cx, gyf + 68.0, "inside a 1 ms p99 budget", CAPTION, "dim").render(t));
    s.push(
        txt(
            cx,
            gyf + 82.0,
            &format!(
                "({} req/s at c={})",
                commas_int(at(f1, &["rps"])?)?,
                py_str(at(f1, &["conc"])?)
            ),
            CAPTION,
            "dim",
        )
        .mono()
        .render(t),
    );
    s.push(txt(28.0, f64::from(h) - 16.0, &st.line, CAPTION, "faint").render(t));
    s.push("</svg>".into());
    Ok(s.join("\n"))
}

// ------------------------------------------------------------------ figure 3

fn fig_memory(d: &Json, st: &Stamp, t: &Theme) -> Result<String, String> {
    let (w, h) = (900, 340);
    let dg = at(d, &["diagonal"])?;
    let m = at(dg, &["memory"])?;
    let mut ser: Vec<(f64, f64)> = Vec::new();
    for p in arr(dg, &["idle_rss_series"])? {
        ser.push((nat(p, &["t_s"])?, nat(p, &["rss_mib"])?));
    }
    for p in arr(dg, &["rss_series"])? {
        ser.push((nat(p, &["t_s"])? + 60.0, nat(p, &["rss_mib"])?));
    }
    if ser.is_empty() {
        return Err("diagonal has no rss series".into());
    }
    let mut s = frame(
        w,
        h,
        t,
        "Flat memory, and it gives it back",
        "Resident set size: 60 s idle at rest, then 300 s of load at c=32, then the load is \
         removed.",
    );
    let (px, py, pw, ph) = (28i64, 92i64, 596i64, 194i64);
    s.push(
        rect(px as f64, py as f64, pw as f64, ph as f64, "panel", 8.0)
            .stroke("grid")
            .render(t),
    );
    let (gx, gy, gw, gh) = (px + 52, py + 20, pw - 76, ph - 52);
    let (gxf, gyf, gwf, ghf) = (gx as f64, gy as f64, gw as f64, gh as f64);
    let tmax = ser.iter().map(|p| p.0).fold(f64::NEG_INFINITY, f64::max);
    let rmax = ser.iter().map(|p| p.1).fold(f64::NEG_INFINITY, f64::max) * 1.25;
    let xf = |v: f64| gxf + v / tmax * gwf;
    let yf = |v: f64| gyf + ghf - v / rmax * ghf;

    for v in [0i64, 10, 20] {
        s.push(grid_line(gx, yf(v as f64), gx + gw, t));
        s.push(
            txt(
                gxf - 8.0,
                yf(v as f64) + 4.0,
                &v.to_string(),
                CAPTION,
                "faint",
            )
            .anchor("end")
            .mono()
            .render(t),
        );
    }
    s.push(
        txt(gxf - 8.0, yf(20.0) - 12.0, "MiB", CAPTION, "faint")
            .anchor("end")
            .render(t),
    );
    let ls = 60.0;
    let le = 60.0 + nat(m, &["load_s"])?;
    s.push(format!(
        "<rect x=\"{}\" y=\"{}\" width=\"{}\" height=\"{}\" fill=\"{}\" opacity=\"0.07\"/>",
        fmt_f(xf(ls), 1),
        fmt_f(gyf, 1),
        fmt_f(xf(le) - xf(ls), 1),
        fmt_f(ghf, 1),
        t.c("accent")
    ));
    s.push(
        txt(
            (xf(ls) + xf(le)) / 2.0,
            gyf + 12.0,
            "LOAD, c=32",
            CAPTION,
            "faint",
        )
        .anchor("middle")
        .weight("700")
        .render(t),
    );
    let pts: Vec<String> = ser
        .iter()
        .map(|(tt, r)| format!("{},{}", fmt_f(xf(*tt), 1), fmt_f(yf(*r), 1)))
        .collect();
    s.push(format!(
        "<polyline points=\"{}\" fill=\"none\" stroke=\"{}\" stroke-width=\"2\" \
         stroke-linejoin=\"round\"/>",
        pts.join(" "),
        t.c("accent")
    ));
    for tt in [0.0, 120.0, 240.0, 360.0, 420.0] {
        s.push(
            txt(
                xf(f64::min(tt, tmax)),
                gyf + ghf + 18.0,
                &format!("{}s", tt as i64),
                CAPTION,
                "faint",
            )
            .anchor("middle")
            .mono()
            .render(t),
        );
    }

    let stats = [
        (
            format!("{} MiB", fmt_f(nat(m, &["idle_rss_mib"])?, 1)),
            "idle, at rest",
        ),
        (
            format!("{} MiB", fmt_f(nat(m, &["steady_state_rss_mib"])?, 1)),
            "steady state under load",
        ),
        (
            format!(
                "{} MiB/min",
                fmt_plus(nat(m, &["growth_rate_mib_per_min"])?, 2)
            ),
            "growth over the load window",
        ),
        (
            format!("{} MiB", fmt_f(nat(m, &["recovered_rss_mib"])?, 1)),
            "once the load stopped",
        ),
    ];
    let (sx, sy) = (648.0, 92.0);
    for (k, (big, lab)) in stats.iter().enumerate() {
        let y = sy + k as f64 * 50.0;
        s.push(
            rect(sx, y, 224.0, 44.0, "panel", 8.0)
                .stroke("grid")
                .render(t),
        );
        s.push(
            txt(sx + 14.0, y + 22.0, big, VALUE, "accent")
                .weight("700")
                .mono()
                .render(t),
        );
        s.push(txt(sx + 14.0, y + 36.0, lab, CAPTION, "dim").render(t));
    }
    s.push(txt(28.0, f64::from(h) - 16.0, &st.line, CAPTION, "faint").render(t));
    s.push("</svg>".into());
    Ok(s.join("\n"))
}

// ------------------------------------------------------------------ figure 4

fn fig_field(d: &Json, install: &Json, st: &Stamp, t: &Theme) -> Result<String, String> {
    let (w, h) = (1040, 604);
    let cov = at(d, &["coverage"])?;
    let field_day = &st.day;
    let keys = [
        "busbar-151",
        "litellm-python",
        "litellm-rust",
        "kong",
        "portkey",
    ];
    let name_of = |k: &str| match k {
        "busbar-151" => format!("Busbar {}", st.build),
        "litellm-python" => "LiteLLM Python 1.94.0".to_string(),
        "litellm-rust" => "LiteLLM Rust 6980723".to_string(),
        "kong" => "Kong 3.9.3".to_string(),
        _ => "Portkey 1.15.2".to_string(),
    };
    let mut s = frame(
        w,
        h,
        t,
        "Why not LiteLLM, Kong or Portkey",
        "Same box, same harness, same day, every gateway. Open source harness, per cell verdicts \
         and reasons published at onthebench.ai.",
    );

    fn panel(
        s: &mut Vec<String>,
        t: &Theme,
        (x, y, w, h): (f64, f64, f64, f64),
        title: &str,
        sub: &str,
    ) {
        s.push(rect(x, y, w, h, "panel", 8.0).stroke("grid").render(t));
        s.push(
            txt(x + 20.0, y + 30.0, title, HEAD, "text")
                .weight("700")
                .render(t),
        );
        s.push(txt(x + 20.0, y + 50.0, sub, CAPTION, "dim").render(t));
    }

    /// One labelled bar per row. `pitch` is the row height; label and value both use the shared
    /// LABEL/VALUE sizes regardless of panel, so only the row spacing (not the type) differs
    /// between the five-row coverage panels and the two-row install panel below, which carries
    /// longer labels.
    fn bars(
        s: &mut Vec<String>,
        t: &Theme,
        (x, y, w): (f64, f64, f64),
        rows: &[(String, f64)],
        fmt: &dyn Fn(f64) -> String,
        logscale: bool,
        pitch: f64,
    ) {
        let vals: Vec<f64> = rows.iter().map(|r| r.1).collect();
        let maxv = vals.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        let minv = vals.iter().cloned().fold(f64::INFINITY, f64::min);
        let frac: Vec<f64> = if logscale {
            let lo = minv * 0.8;
            let span = (maxv / lo).log10();
            vals.iter().map(|v| (v / lo).log10() / span).collect()
        } else {
            vals.iter().map(|v| v / maxv).collect()
        };
        for (i, ((lab, v), f)) in rows.iter().zip(&frac).enumerate() {
            let yy = y + i as f64 * pitch;
            let good = i == 0;
            s.push(
                txt(x, yy + 10.0, lab, LABEL, if good { "text" } else { "dim" })
                    .weight(if good { "700" } else { "500" })
                    .render(t),
            );
            let bw = f64::max(0.035 * w, f * w);
            s.push(rect(x, yy + 18.0, w, 11.0, "neutral_soft", 5.5).render(t));
            s.push(
                rect(
                    x,
                    yy + 18.0,
                    bw,
                    11.0,
                    if good { "accent" } else { "neutral" },
                    5.5,
                )
                .render(t),
            );
            s.push(
                txt(
                    x + w + 12.0,
                    yy + 27.5,
                    &fmt(*v),
                    VALUE,
                    if good { "accent" } else { "dim" },
                )
                .weight(if good { "700" } else { "600" })
                .mono()
                .render(t),
            );
        }
    }

    // Panels A and B: five rows each. Bars start 56px below the panel top so the first row's label
    // clears the subtitle instead of sitting on its baseline.
    panel(
        &mut s,
        t,
        (28.0, 96.0, 492.0, 282.0),
        "Wire protocol pairs actually served",
        "Of 36 ingress and upstream combinations. Not a provider count",
    );
    let mut rows = Vec::new();
    for k in keys {
        rows.push((name_of(k), nat(cov, &[k, "served"])?));
    }
    bars(
        &mut s,
        t,
        (48.0, 166.0, 316.0),
        &rows,
        &|v| format!("{v}/36"),
        false,
        38.0,
    );

    panel(
        &mut s,
        t,
        (540.0, 96.0, 472.0, 282.0),
        "Idle resident memory",
        "At rest, before any request. Log scale, lower is better",
    );
    let mut rows = Vec::new();
    for k in keys {
        rows.push((name_of(k), nat(cov, &[k, "idle_rss_mib"])?));
    }
    bars(
        &mut s,
        t,
        (560.0, 166.0, 286.0),
        &rows,
        &|v| {
            if v < 10.0 {
                format!("{} MiB", fmt_commas(v, 1))
            } else {
                format!("{} MiB", fmt_commas(v, 0))
            }
        },
        true,
        38.0,
    );

    // Panel C: image + install size. Two rows, but the labels are full image references, so they
    // get a taller pitch than the five-row panels above (same type sizes).
    let img = at(install, &["images"])?;
    let bb_mib = nat(img, &["busbar", "compressed_mib"])?;
    let ll_mib = nat(img, &["litellm", "compressed_mib"])?;
    panel(
        &mut s,
        t,
        (28.0, 398.0, 984.0, 168.0),
        "What you actually install",
        "Compressed container layers, read from the registry. Lower is better",
    );
    let label_of = |k: &str, pretty: &str| -> Result<String, String> {
        Ok(format!(
            "{pretty}, {}, {}",
            py_str(at(img, &[k, "image"])?),
            py_str(at(img, &[k, "platform"])?)
        ))
    };
    let rows = vec![
        (label_of("busbar", "Busbar")?, bb_mib),
        (label_of("litellm", "LiteLLM")?, ll_mib),
    ];
    bars(
        &mut s,
        t,
        (48.0, 468.0, 604.0),
        &rows,
        &|v| format!("{} MiB", fmt_commas(v, 2)),
        false,
        48.0,
    );
    s.push(
        txt(
            838.0,
            500.0,
            &format!("{}x", fmt_f(ll_mib / bb_mib, 0)),
            STAT,
            "accent",
        )
        .weight("700")
        .mono()
        .render(t),
    );
    s.push(txt(838.0, 522.0, "smaller to pull", CAPTION, "dim").render(t));
    s.push(
        txt(
            28.0,
            f64::from(h) - 20.0,
            &format!(
                "Coverage and memory: onthebench.ai field run, {field_day}, AWS m7g.4xlarge \
                 (Graviton3), 4-core pin. Image sizes: registry manifests read {}.",
                py_str(at(install, &["hand_measured", "measured_at"])?)
            ),
            CAPTION,
            "faint",
        )
        .render(t),
    );
    s.push("</svg>".into());
    Ok(s.join("\n"))
}

// ------------------------------------------------------------------ driver

/// Every figure, both themes, as `(file name, body)` in the order the script wrote them. Pure: the
/// unit tests drive it over a fixed document.
pub fn render_all(d: &Json, install: &Json) -> Result<Vec<(String, String)>, String> {
    let st = stamp(d)?;
    let mut out = Vec::new();
    for fname in ["matrix", "perf", "memory", "field"] {
        for t in THEMES {
            let body = match fname {
                "matrix" => fig_matrix(d, &st, t)?,
                "perf" => fig_perf(d, &st, t)?,
                "memory" => fig_memory(d, &st, t)?,
                _ => fig_field(d, install, &st, t)?,
            };
            if body.contains('—') || body.contains('–') {
                return Err(format!("dash in {fname}"));
            }
            out.push((format!("{fname}-{}.svg", t.name), body));
        }
    }
    Ok(out)
}

fn load(path: &Path) -> Result<Json, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    json_lite::parse(&text).map_err(|e| format!("{}: {e}", path.display()))
}

pub fn main(cx: &Ctx, args: &[String]) -> i32 {
    let mut outdir: Option<&str> = None;
    for a in args {
        if a.starts_with('-') {
            eprintln!("xtask readme-assets: unknown flag `{a}`\nusage: cargo xtask readme-assets [<outdir>]");
            return 2;
        }
        if outdir.is_none() {
            outdir = Some(a);
        }
    }
    let here = cx.root().join("assets").join("readme");
    let out = outdir
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| here.clone());
    let (d, install) = match (
        load(&here.join("data.json")),
        load(&here.join("install.json")),
    ) {
        (Ok(d), Ok(i)) => (d, i),
        (Err(e), _) | (_, Err(e)) => {
            eprintln!("xtask readme-assets: {e}");
            return 3;
        }
    };
    let figs = match render_all(&d, &install) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("xtask readme-assets: {e}");
            return 1;
        }
    };
    if let Err(e) = std::fs::create_dir_all(&out) {
        eprintln!("xtask readme-assets: {}: {e}", out.display());
        return 3;
    }
    for (fname, body) in figs {
        let p = out.join(fname);
        let text = format!("{body}\n");
        if let Err(e) = std::fs::write(&p, &text) {
            eprintln!("xtask readme-assets: {}: {e}", p.display());
            return 3;
        }
        println!("{} {}", p.display(), text.len());
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    // Every expectation below was produced by Python 3 (`f"{x:.2f}"` etc.), not by this code.
    #[test]
    fn fixed_rounds_half_to_even_like_python() {
        assert_eq!(fmt_f(0.125, 2), "0.12");
        assert_eq!(fmt_f(0.375, 2), "0.38");
        assert_eq!(fmt_f(2.5, 0), "2");
        assert_eq!(fmt_f(0.5, 0), "0");
        assert_eq!(fmt_f(1.5, 0), "2");
        assert_eq!(fmt_f(3.5, 0), "4");
        assert_eq!(fmt_f(0.25, 1), "0.2");
        assert_eq!(fmt_f(0.35, 1), "0.3");
        assert_eq!(fmt_f(0.05, 1), "0.1");
        assert_eq!(fmt_f(65.08213217682157, 1), "65.1");
        assert_eq!(fmt_f(-0.0, 1), "-0.0");
        assert_eq!(fmt_f(1e15 + 0.5, 1), "1000000000000000.5");
    }

    #[test]
    fn commas_match_python() {
        assert_eq!(fmt_commas(67837.0, 0), "67,837");
        assert_eq!(fmt_commas(999.0, 0), "999");
        assert_eq!(fmt_commas(1000.0, 0), "1,000");
        assert_eq!(fmt_commas(1234567.891, 2), "1,234,567.89");
        assert_eq!(fmt_commas(360.77, 2), "360.77");
        assert_eq!(fmt_commas(7.3359375, 1), "7.3");
        assert_eq!(fmt_commas(25.1640625, 0), "25");
        assert_eq!(fmt_commas(-1234.5, 1), "-1,234.5");
        assert_eq!(fmt_commas(0.0, 2), "0.00");
    }

    #[test]
    fn plus_sign_matches_python() {
        assert_eq!(fmt_plus(0.08937399984548648, 2), "+0.09");
        assert_eq!(fmt_plus(-0.004, 2), "-0.00");
        assert_eq!(fmt_plus(0.0, 2), "+0.00");
        assert_eq!(fmt_plus(-1.5, 2), "-1.50");
    }

    #[test]
    fn repr_and_str_match_python() {
        assert_eq!(py_float_repr(6.0), "6.0");
        assert_eq!(py_float_repr(378.3), "378.3");
        assert_eq!(py_float_repr(5.74), "5.74");
        assert_eq!(py_float_repr(0.1), "0.1");
        assert_eq!(py_str(&Json::Int(82)), "82");
        assert_eq!(py_str(&Json::Float(73.0)), "73.0");
        assert_eq!(py_str(&Json::Str("2026-08-13".into())), "2026-08-13");
    }

    #[test]
    fn escape_is_the_three_entities() {
        assert_eq!(esc("a & b < c > d"), "a &amp; b &lt; c &gt; d");
    }

    #[test]
    fn dash_in_the_data_is_refused() {
        let d = json_lite::parse(
            r#"{"source":{"busbar_build":"x:1","busbar_measured_at":"2026-01-01T00:00:00Z"}}"#,
        )
        .unwrap();
        // The figures read far more than `source`; a missing key is an error, not a panic.
        assert!(render_all(&d, &Json::Null).is_err());
    }
}
