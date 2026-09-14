#!/usr/bin/env python3
"""
analyze_afl.py -- Post-hoc analysis of AFL++ fuzzing campaigns.
 
Summarizes one or more AFL++ output directories (fuzzer_stats, plot_data,
crashes/, hangs/) into a comparison table and a Markdown report. If you
point it at the target binary as well, it replays every crashing input
through the binary and classifies/dedupes findings by their ASan/UBSan
signature -- AFL's own "unique_crashes" counter is a rough heuristic
(based on its coverage bitmap), so the number of files in crashes/ is
usually a big overcount of the number of *distinct* bugs.
 
Works with both AFL++ output layouts:
  <out>/default/{fuzzer_stats,plot_data,queue,crashes,hangs}   (current)
  <out>/{fuzzer_stats,plot_data,queue,crashes,hangs}            (older/-M/-S)
 
Usage
-----
  python3 analyze_afl.py \\
      --run mystack=out_mystack \\
      --run stlstack=out_stlstack \\
      --run mystack_buggy=out_mystack_buggy \\
      --binary mystack=build/mystack_afl_asan \\
      --binary stlstack=build/stlstack_afl_asan \\
      --binary mystack_buggy=build/mystack_buggy_afl_asan \\
      --out analysis_report
 
--binary is optional per run; without it you still get the fuzzer_stats /
plot_data comparison, just no crash-signature triage for that run.
 
Output (written under --out, default "analysis_report"):
  report.md          human-readable summary + comparison table
  comparison.csv      the same comparison table, for spreadsheets
  <run>_signatures.csv   one row per distinct crash signature, with count
  execs_per_sec.png, paths_over_time.png, crash_counts.png   (if matplotlib installed)
"""

import argparse
import csv
import re
import signal
import subprocess
import sys
from collections import counter
from pathlib import Path

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    HAVE_MPL = True
except:
    HAVE_MPL = False


# --------------------------------------------------------------------------
# Locating and parsing AFL++ output
# --------------------------------------------------------------------------

def resolve_afl_dir(path: Path) -> Path:
    """AFL++ nests everything under <out>/default/ in single-instance mode
    (and under <out>/<fuzzer_id>/ with -M/-S). Accept either the parent
    out dir or the exact instance dir."""
    if (path / "fuzzer_stats").exists():
        return path
    if (path / "default" / "fuzzer_stats").exists():
        return path / "default"
    # -M/-S runs: pick the first subdir that has fuzzer_stats
    for sub in sorted(path.glob("*")):
        if (sub / "fuzzer_stats").exists():
            return sub
    raise FileNotFoundError(
        f"No fuzzer_stats found under {path} (checked {path}, {path}/default, and subdirs). "
        "Is this a real AFL++ output directory?"
    )


def parse_fuzzer_stats(afl_dir: Path) -> dict:
    stats = {}
    with open(afl_dir / "fuzzer_stats") as f:
        for line in f:
            if ":" not in line:
                continue
            key, val = line.split(":", 1)
            stats[ley.strip()] = val.strip()
    return stats


def parse_plot_data(afl_dir: Path) -> list:
    """Returns a list of dicts, one per sampled row, with numeric values
    coerced to int/float where possible. Column names come from AFL++'s
    own header line so this survives version differences."""
    plot_path = afl_dir / "plot_data"
    if not plot_path.exists():
        return []
    rows = []
    with open(plot_path) as f:
        header_line = f.readline().lstrip("#").strip()
        fieldnames = [h.strip() for h in header_line.split(",")]
        reader = csv.DictReader(f, fieldnames=fieldnames)
        for row in reader:
            parsed = {}
            for k, v in row.items():
                if v is None:
                    continue
                v = v.strip()
                try:
                    parsed[k] = int(v)
                except ValueError:
                    try:
                        parsed[k] = float(v)
                    except ValueError:
                        parsed[k] = v
            rows.append(parsed)
    return rows


def list_findings(afl_dir: Path, subdir: str) -> list:
    d = afl_dir / subdir
    if not d.exists():
        return []
    return sorted(p for p in d.iterdir() if p.is_file() and p.name != "README.txt")


# --------------------------------------------------------------------------
# Crash replay and signature extraction
# --------------------------------------------------------------------------

SIG_PATTERNS = [
    # ASan: "ERROR: AddressSanitizer: heap-buffer-overflow ... in FixedStack<...>::push(...)"
    (re.compile(r"AddressSanitizer:\s*(\S+).*?\n.*?\bin\s+([^\n]+)", re.S),
     lambda m: f"ASan:{m.group(1)} in {m.group(2).strip()[:80]}"),
    # UBSan: "runtime error: <description>" -- report the description (truncated cleanly),
    # not the file:line prefix, since the prefix varies by libstdc++ version/path.
    (re.compile(r"runtime error:\s*([^\n]+)"),
     lambda m: f"UBSan: {m.group(1).strip()[:100]}"),
]
 
 
def extract_signature(stderr_text: str, returncode: int, sig_name: str) -> str:
    for pattern, fmt in SIG_PATTERNS:
        m = pattern.search(stderr_text)
        if m:
            return fmt(m)
    if sig_name:
        return f"signal:{sig_name} (no sanitizer text captured)"
    return f"exit_code:{returncode} (no sanitizer text captured)"
 
 
def replay(binary: Path, input_file: Path, timeout: float) -> dict:
    try:
        proc = subprocess.run(
            [str(binary)],
            stdin=open(input_file, "rb"),
            capture_output=True,
            timeout=timeout,
        )
        rc = proc.returncode
        stderr = proc.stderr.decode("utf-8", errors="replace")
        sig_name = ""
        if rc < 0:
            try:
                sig_name = signal.Signals(-rc).name
            except ValueError:
                sig_name = f"signal_{-rc}"
        return {
            "file": input_file.name,
            "returncode": rc,
            "signal": sig_name,
            "crashed": rc != 0,
            "signature": extract_signature(stderr, rc, sig_name) if rc != 0 else "",
            "stderr_excerpt": stderr[:400],
        }
    except subprocess.TimeoutExpired:
        return {
            "file": input_file.name,
            "returncode": None,
            "signal": "TIMEOUT",
            "crashed": True,
            "signature": "TIMEOUT (treated as hang, not classified)",
            "stderr_excerpt": "",
        }
 
 
# --------------------------------------------------------------------------
# Per-run analysis
# --------------------------------------------------------------------------
 
def analyze_run(name: str, out_path: Path, binary: Path, timeout: float) -> dict:
    afl_dir = resolve_afl_dir(out_path)
    stats = parse_fuzzer_stats(afl_dir)
    plot = parse_plot_data(afl_dir)
    crash_files = list_findings(afl_dir, "crashes")
    hang_files = list_findings(afl_dir, "hangs")
 
    result = {
        "name": name,
        "afl_dir": str(afl_dir),
        "stats": stats,
        "plot": plot,
        "n_crash_files": len(crash_files),
        "n_hang_files": len(hang_files),
        "signatures": None,
        "replayed": None,
    }
 
    if binary is not None and crash_files:
        if not binary.exists():
            print(f"  [!] --binary for '{name}' does not exist: {binary} -- skipping replay", file=sys.stderr)
        else:
            replayed = [replay(binary, f, timeout) for f in crash_files]
            result["replayed"] = replayed
            sig_counts = Counter(r["signature"] for r in replayed if r["crashed"])
            result["signatures"] = sig_counts
 
    return result
 
 
def fmt_seconds(sec) -> str:
    try:
        sec = float(sec)
    except (TypeError, ValueError):
        return "n/a"
    h, rem = divmod(int(sec), 3600)
    m, s = divmod(rem, 60)
    return f"{h}h{m:02d}m{s:02d}s"
 
 
def comparison_row(r: dict) -> dict:
    s = r["stats"]
    start = s.get("start_time")
    last_crash = s.get("last_crash")
    last_update = s.get("last_update")
    ttfc = None
    if start and last_crash and last_crash != "0":
        try:
            ttfc = int(last_crash) - int(start)
        except ValueError:
            ttfc = None
    if r["n_crash_files"] == 0:
        ttfc_display = "n/a (no crashes)"
    elif ttfc is not None:
        ttfc_display = fmt_seconds(ttfc)
    else:
        ttfc_display = "unknown (see fuzzer_stats: last_crash)"
 
    if r["n_crash_files"] == 0:
        replayed_display = 0
        distinct_display = 0
    elif r["replayed"] is not None:
        replayed_display = r["n_crash_files"]
        distinct_display = len(r["signatures"])
    else:
        replayed_display = "n/a (no --binary)"
        distinct_display = "n/a (no --binary)"
 
    row = {
        "run": r["name"],
        "run_time": fmt_seconds(s.get("run_time", (int(last_update) - int(start)) if start and last_update else None)),
        "total_execs": s.get("execs_done", "n/a"),
        "execs_per_sec": s.get("execs_per_sec", "n/a"),
        "corpus_paths": s.get("corpus_count", "n/a"),
        "afl_unique_crashes": s.get("unique_crashes", str(r["n_crash_files"])),
        "afl_unique_hangs": s.get("unique_hangs", str(r["n_hang_files"])),
        "time_to_first_crash": ttfc_display,
        "replayed_crash_files": replayed_display,
        "distinct_signatures": distinct_display,
    }
    return row
 
 
# --------------------------------------------------------------------------
# Report generation
# --------------------------------------------------------------------------
 
def write_comparison_csv(rows: list, out_dir: Path):
    path = out_dir / "comparison.csv"
    fieldnames = list(rows[0].keys()) if rows else []
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    return path
 
 
def write_signature_csvs(results: list, out_dir: Path):
    written = []
    for r in results:
        if r["signatures"] is None:
            continue
        path = out_dir / f"{r['name']}_signatures.csv"
        with open(path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["signature", "count", "example_file"])
            examples = {}
            for rep in r["replayed"]:
                if rep["crashed"] and rep["signature"] not in examples:
                    examples[rep["signature"]] = rep["file"]
            for sig, count in r["signatures"].most_common():
                writer.writerow([sig, count, examples.get(sig, "")])
        written.append(path)
    return written
 
 
def make_plots(results: list, out_dir: Path):
    if not HAVE_MPL:
        print("[i] matplotlib not installed -- skipping charts (pip install matplotlib to enable)")
        return []
    written = []
 
    # execs_per_sec over time
    fig, ax = plt.subplots(figsize=(8, 5))
    any_data = False
    for r in results:
        rows = r["plot"]
        if not rows:
            continue
        t0 = rows[0].get("# unix_time") or rows[0].get("unix_time")
        xs, ys = [], []
        for row in rows:
            t = row.get("# unix_time", row.get("unix_time"))
            eps = row.get("execs_per_sec")
            if t is None or eps is None:
                continue
            xs.append((t - t0) / 60.0)
            ys.append(eps)
        if xs:
            ax.plot(xs, ys, label=r["name"])
            any_data = True
    if any_data:
        ax.set_xlabel("Minutes since start")
        ax.set_ylabel("execs/sec")
        ax.set_title("Execution speed over time")
        ax.legend()
        p = out_dir / "execs_per_sec.png"
        fig.savefig(p, dpi=120, bbox_inches="tight")
        written.append(p)
    plt.close(fig)
 
    # corpus paths (coverage proxy) over time
    fig, ax = plt.subplots(figsize=(8, 5))
    any_data = False
    for r in results:
        rows = r["plot"]
        if not rows:
            continue
        t0 = rows[0].get("# unix_time") or rows[0].get("unix_time")
        xs, ys = [], []
        for row in rows:
            t = row.get("# unix_time", row.get("unix_time"))
            paths = row.get("corpus_count", row.get("paths_total"))
            if t is None or paths is None:
                continue
            xs.append((t - t0) / 60.0)
            ys.append(paths)
        if xs:
            ax.plot(xs, ys, label=r["name"])
            any_data = True
    if any_data:
        ax.set_xlabel("Minutes since start")
        ax.set_ylabel("Corpus entries found")
        ax.set_title("Coverage growth over time")
        ax.legend()
        p = out_dir / "paths_over_time.png"
        fig.savefig(p, dpi=120, bbox_inches="tight")
        written.append(p)
    plt.close(fig)
 
    # crash counts: AFL-reported vs distinct-after-replay
    fig, ax = plt.subplots(figsize=(8, 5))
    names = [r["name"] for r in results]
    afl_counts = [r["n_crash_files"] for r in results]
    distinct_counts = [len(r["signatures"]) if r["signatures"] is not None else 0 for r in results]
    x = range(len(names))
    width = 0.35
    ax.bar([i - width / 2 for i in x], afl_counts, width, label="crash files (AFL)")
    ax.bar([i + width / 2 for i in x], distinct_counts, width, label="distinct signatures (replayed)")
    ax.set_xticks(list(x))
    ax.set_xticklabels(names)
    ax.set_ylabel("Count")
    ax.set_title("Crash files vs. distinct bugs")
    ax.legend()
    p = out_dir / "crash_counts.png"
    fig.savefig(p, dpi=120, bbox_inches="tight")
    written.append(p)
    plt.close(fig)
 
    return written
 
 
def write_report_md(results: list, rows: list, out_dir: Path, plot_files: list):
    lines = []
    lines.append("# AFL++ Campaign Analysis\n")
 
    lines.append("## Comparison\n")
    if rows:
        headers = list(rows[0].keys())
        lines.append("| " + " | ".join(headers) + " |")
        lines.append("| " + " | ".join("---" for _ in headers) + " |")
        for row in rows:
            lines.append("| " + " | ".join(str(row[h]) for h in headers) + " |")
    lines.append("")
 
    if plot_files:
        lines.append("## Charts\n")
        for p in plot_files:
            lines.append(f"![{p.stem}]({p.name})")
        lines.append("")
 
    for r in results:
        lines.append(f"## Run: {r['name']}\n")
        lines.append(f"- AFL output dir: `{r['afl_dir']}`")
        lines.append(f"- Crash files: {r['n_crash_files']}, hang files: {r['n_hang_files']}")
        if r["signatures"] is not None:
            lines.append(f"- Distinct crash signatures after replay: {len(r['signatures'])}")
            lines.append("")
            lines.append("| signature | count |")
            lines.append("| --- | --- |")
            for sig, count in r["signatures"].most_common():
                lines.append(f"| {sig} | {count} |")
        elif r["n_crash_files"] > 0:
            lines.append("- No `--binary` given for this run, so crashes were not replayed/classified. "
                          "Re-run with `--binary "
                          f"{r['name']}=<path to instrumented binary>` to see distinct bug signatures "
                          "instead of raw AFL crash-file counts.")
        else:
            lines.append("- No crashes reported by AFL++ for this run.")
        lines.append("")
 
    report_path = out_dir / "report.md"
    report_path.write_text("\n".join(lines))
    return report_path
 
 
# --------------------------------------------------------------------------
 
def parse_kv_args(pairs):
    """Turns ['name=path', ...] into {'name': Path('path'), ...}."""
    out = {}
    for pair in pairs or []:
        if "=" not in pair:
            raise argparse.ArgumentTypeError(f"expected name=path, got: {pair}")
        name, path = pair.split("=", 1)
        out[name] = Path(path)
    return out
 
 
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run", action="append", required=True, metavar="NAME=OUT_DIR",
                     help="AFL++ output dir for a campaign, e.g. mystack=out_mystack. Repeatable.")
    ap.add_argument("--binary", action="append", metavar="NAME=BINARY_PATH",
                     help="Instrumented/ASan binary to replay that run's crashes against. "
                          "NAME must match a --run name. Repeatable, optional per run.")
    ap.add_argument("--out", default="analysis_report", help="Directory to write the report into.")
    ap.add_argument("--timeout", type=float, default=5.0, help="Per-crash replay timeout in seconds (default 5).")
    args = ap.parse_args()
 
    runs = parse_kv_args(args.run)
    binaries = parse_kv_args(args.binary)
    unknown = set(binaries) - set(runs)
    if unknown:
        ap.error(f"--binary given for unknown run name(s): {', '.join(unknown)}")
 
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
 
    results = []
    for name, out_path in runs.items():
        print(f"[i] Analyzing run '{name}' ({out_path}) ...")
        try:
            r = analyze_run(name, out_path, binaries.get(name), args.timeout)
        except FileNotFoundError as e:
            print(f"  [!] {e}", file=sys.stderr)
            continue
        if r["replayed"] is not None:
            n = sum(1 for x in r["replayed"] if x["crashed"])
            print(f"  Replayed {len(r['replayed'])} crash file(s): {n} reproduced, "
                  f"{len(r['signatures'])} distinct signature(s).")
        results.append(r)
 
    if not results:
        print("[!] No runs could be analyzed. Check your --run paths.", file=sys.stderr)
        sys.exit(1)
 
    rows = [comparison_row(r) for r in results]
    csv_path = write_comparison_csv(rows, out_dir)
    sig_paths = write_signature_csvs(results, out_dir)
    plot_paths = make_plots(results, out_dir)
    report_path = write_report_md(results, rows, out_dir, plot_paths)
 
    print(f"\n[i] Wrote:")
    print(f"    {report_path}")
    print(f"    {csv_path}")
    for p in sig_paths:
        print(f"    {p}")
    for p in plot_paths:
        print(f"    {p}")
 
 
if __name__ == "__main__":
    main()