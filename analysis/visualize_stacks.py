#!/usr/bin/env python3
"""
visualize_stacks.py -- show the actual stacks AFL++ tried to build, and
quantify how well it explored the space of stack states.
 
This shells out to the `stack_trace` tool (built via `make tools`) for
every testcase it's given, so the decoding of raw AFL bytes into
push/pop/top operations is done by the exact same StackOpFactory the
real fuzzing harness uses -- see include/stack_op_factory.hpp. Nothing
in this script re-implements or guesses at the byte encoding.
 
Usage
-----
  # Show individual traces (up to --limit) for files in an AFL queue dir,
  # plus aggregate stats computed over ALL of them:
  python3 analysis/visualize_stacks.py --target mystack \\
      --tool build/stack_trace --dir out_mystack/default/queue --limit 10
 
  # Just the aggregate stats, no per-file traces:
  python3 analysis/visualize_stacks.py --target stlstack \\
      --tool build/stack_trace --dir out_stlstack/default/queue --stats-only
 
  # One specific file in full detail (e.g. a crash, or a seed):
  python3 analysis/visualize_stacks.py --target mystack \\
      --tool build/stack_trace --file corpus/seed_overflow
 
The --dir mode works on any directory of raw testcase files: an AFL
queue/, crashes/, hangs/, or just your corpus/ / corpus_stl/ seed dirs.
 
What the aggregate stats mean
------------------------------
- "reached a FULL stack": AFL generated a byte sequence with enough
  successful pushes in a row (for mystack, 16) to fill the stack before
  a pop/top interrupted it. This is the harder of the two edge cases to
  reach purely by mutation, since it requires a run of consecutive
  "push-selecting" bytes with no "pop"/"top" byte breaking the streak.
- "attempted pop/top on an EMPTY stack": AFL generated a sequence that
  tries to pop or read the top before ever pushing enough onto the
  stack (or after popping everything back off). This is the shallower
  edge case -- often just the very first byte.
- The depth histogram shows, across every testcase, how deep each one's
  stack got before whatever happened next (a pop, a rejection, or EOF).
  A histogram concentrated near 0-2 suggests AFL mostly isn't finding
  its way to deep/full states without help (e.g. from the seed_overflow
  seed); a histogram with real mass out near capacity suggests it is.
"""

import argparse
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

SUMMARY_RE = re.compile(r"^-- summary: (.*)$")


def parse_summary(line: str) -> dict:
    d = {}
    for kv in line.split():
        if "=" in kv:
            k, v = kv.split("=", 1)
            d[k] = v
    return d


def run_trace(tool: str, target: str, path: Path, timeout: float):
    proc = subprocess.run(
        [tool, "--target", target, "--file", str(path)],
        capture_output=True,
        text=True,
        timeout=timeout
    )
    return proc.stdout, proc.stderr, proc.returncode

def collect_files(d: Path, sort_by: str):
    files = [p for p in d.iterdir() if p.is_file() and p.name != "README.txt"]
    if sort_by == "size":
        files.sort(key=lambda p: p.stat().st_size)
    else:
        files.sort(key=lambda p: p.name)
    return files
 
 
def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument(
        "--tool", required=True, help="Path to the compiled stack_trace binary (make tools)."
    )
    ap.add_argument("--target", required=True, choices=["mystack", "stlstack"])
    group = ap.add_mutually_exclusive_group(required=True)
    group.add_argument("--dir", help="Directory of testcases (AFL queue/crashes/hangs, or a corpus dir).")
    group.add_argument("--file", help="A single testcase file to trace in detail.")
    ap.add_argument(
        "--limit",
        type=int,
        default=10,
        help="Max number of full per-file traces to print in --dir mode (default 10). "
        "Aggregate stats are always computed over every file, regardless of this limit.",
    )
    ap.add_argument(
        "--stats-only", action="store_true", help="Skip per-file traces; print only aggregate stats."
    )
    ap.add_argument("--sort", choices=["name", "size"], default="name")
    ap.add_argument("--timeout", type=float, default=5.0, help="Per-file replay timeout (default 5s).")
    args = ap.parse_args()
 
    tool = Path(args.tool)
    if not tool.exists():
        print(f"[!] {tool} not found. Build it first: make tools", file=sys.stderr)
        sys.exit(1)
 
    if args.file:
        files = [Path(args.file)]
        limit = 1
        if not files[0].exists():
            print(f"[!] {files[0]} does not exist.", file=sys.stderr)
            sys.exit(1)
    else:
        d = Path(args.dir)
        if not d.is_dir():
            print(f"[!] {d} is not a directory.", file=sys.stderr)
            sys.exit(1)
        files = collect_files(d, args.sort)
        limit = args.limit
        if not files:
            print(f"[!] No testcase files found in {d}.", file=sys.stderr)
            sys.exit(1)
 
    shown = 0
    agg = Counter()
    max_size_seen = 0
    size_histogram = Counter()
    n_reached_full = 0
    n_attempted_empty_pop = 0
    n_attempted_empty_top = 0
    n_files = 0
    n_errors = 0
 
    for f in files:
        try:
            out, err, rc = run_trace(str(tool), args.target, f, args.timeout)
        except subprocess.TimeoutExpired:
            print(f"[!] {f.name}: timed out after {args.timeout}s, skipping", file=sys.stderr)
            n_errors += 1
            continue
 
        summary = {}
        for line in out.splitlines():
            m = SUMMARY_RE.match(line)
            if m:
                summary = parse_summary(m.group(1))
 
        if not summary:
            print(f"[!] {f.name}: stack_trace produced no summary line (rc={rc}) -- "
                  f"it may have crashed itself. stderr: {err.strip()[:200]}", file=sys.stderr)
            n_errors += 1
            continue
 
        n_files += 1
        for k in ("pushes", "pops", "tops"):
            agg[k] += int(summary.get(k, 0))
        max_size = int(summary.get("max_size", 0))
        max_size_seen = max(max_size_seen, max_size)
        size_histogram[max_size] += 1
        if summary.get("reached_full") == "yes":
            n_reached_full += 1
        if int(summary.get("rejected_empty_pop", 0)) > 0 or int(summary.get("ub_would_pop", 0)) > 0:
            n_attempted_empty_pop += 1
        if int(summary.get("rejected_empty_top", 0)) > 0 or int(summary.get("ub_would_top", 0)) > 0:
            n_attempted_empty_top += 1
 
        if not args.stats_only and shown < limit:
            print(f"=== {f.name} ({f.stat().st_size} byte(s)) ===")
            print(out.rstrip())
            print()
            shown += 1
 
    if n_files == 0:
        print("[!] No testcases were successfully traced.", file=sys.stderr)
        sys.exit(1)
 
    if not args.stats_only and len(files) > limit and not args.file:
        print(f"... ({len(files) - limit} more file(s) not shown; stats below cover all of them; "
              f"raise --limit to see more traces) ...\n")
 
    print("==================== Aggregate stats ====================")
    print(f"Testcases analyzed: {n_files}" + (f" ({n_errors} skipped due to errors)" if n_errors else ""))
    print(f"Total ops across all testcases: pushes={agg['pushes']} pops={agg['pops']} tops={agg['tops']}")
    if args.target == "stlstack":
        print(
            "Reached a FULL stack:                n/a -- std::stack has no fixed capacity, "
            "so this concept doesn't apply to this target (see README)."
        )
    else:
        print(
            f"Reached a FULL stack:              {n_reached_full:5d} / {n_files} "
            f"({100 * n_reached_full / n_files:5.1f}%)"
        )
    print(
        f"Attempted pop on an EMPTY stack:   {n_attempted_empty_pop:5d} / {n_files} "
        f"({100 * n_attempted_empty_pop / n_files:5.1f}%)"
    )
    print(
        f"Attempted top on an EMPTY stack:   {n_attempted_empty_top:5d} / {n_files} "
        f"({100 * n_attempted_empty_top / n_files:5.1f}%)"
    )
    print(f"Max stack depth observed anywhere:  {max_size_seen}")
    print("\nMax-depth-reached histogram (one testcase can only contribute to one bucket):")
    width = max(size_histogram.values()) if size_histogram else 1
    scale = 50.0 / width if width > 50 else 1.0
    for depth in sorted(size_histogram):
        count = size_histogram[depth]
        bar = "#" * max(1, int(count * scale)) if count else ""
        print(f"  depth {depth:3d}: {count:5d}  {bar}")
 
 
if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        # Happens when output is piped into something like `head` that
        # closes the pipe early -- not an error worth a traceback.
        try:
            sys.stdout.close()
        except Exception:
            pass
        sys.exit(0)