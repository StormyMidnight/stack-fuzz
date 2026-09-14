# Stack Fuzzing Experiment: Exception-Safe Stack vs. std::stack, under AFL++

## What's here

- `include/mystack.hpp` — `FixedStack<T, Capacity>`, a fixed-capacity stack
  that throws `StackFullException` on a full push and `StackEmptyException`
  on an empty pop/top. Compile with `-DINJECT_BUG` to plant a deliberate
  off-by-one heap overflow in `push()`, used to sanity-check your fuzzing
  setup.
- `include/stl_stack_wrapper.hpp` — wraps `std::stack<int>` the way an
  unguarded/naive caller would: push always succeeds (no fixed capacity),
  and pop()/top() do **not** check for emptiness, so calling them on an
  empty stack is undefined behavior rather than an exception.
- `harness/mystack_fuzz.cpp`, `harness/stlstack_fuzz.cpp` — AFL++ stdin
  targets. Both use the *same* byte-stream encoding so the two campaigns
  are directly comparable:
  - `byte % 4 == 0` → `pop()`
  - `byte % 4 == 1` → `top()`
  - `byte % 4 == 2 or 3` → `push(byte)`
- `corpus/`, `corpus_stl/` — identical starter seeds for each target
  (a normal push/pop/top mix, an alternating sequence, a run of pushes
  that overflows a 16-slot capacity, and a bare empty-pop/top).
- `Makefile` — three build modes: `plain` (sanity build), `asan`
  (ASan+UBSan, no AFL instrumentation — useful for quick manual checks),
  `afl` / `afl-asan` (AFL++-instrumented, the latter with sanitizers).

Everything here has been compiled and run in a sandbox without AFL++ or
network access, to confirm the code itself is correct before you point a
fuzzer at it (see "What I verified" below). You'll need AFL++ installed
locally to actually run `afl-fuzz`.

## Why ASan/UBSan matters for this comparison

This is the central subtlety of the experiment: **`FixedStack` fails via a
caught C++ exception, but `std::stack` used without checks fails via
undefined behavior — not an exception.** Undefined behavior is not
guaranteed to crash. On an optimized, non-sanitized build, an empty
`pop()`/`top()` on `std::stack` may read/write invalid memory and keep
right on running, producing garbage output but no observable fault. AFL++
only registers a "crash" when the process actually dies (SIGSEGV, SIGABRT,
etc.), so a plain build can make the STL misuse look perfectly safe when
it isn't.

That's why the `Makefile` has an `afl-asan` target and why the sanitizer
flags include `-fno-sanitize-recover=all`: without that flag, ASan/UBSan
print a report and the process **keeps running with exit code 0** — I hit
this myself while testing (see below) and had to add the flag so a
detected fault actually aborts the process. Build and fuzz with `afl-asan`,
not plain `afl`, or you risk a false "no bugs found" result for the STL
target.

## Building

```bash
# Sanity build (plain g++, no AFL, no sanitizers)
make plain

# Manual ASan/UBSan check (no AFL instrumentation, just run binaries by hand)
make asan

# AFL++-instrumented, no sanitizer (requires AFL++ installed)
make afl

# AFL++-instrumented WITH ASan/UBSan (the one to actually fuzz with)
make afl-asan
```

`afl`/`afl-asan` require `afl-clang-fast++` on your `PATH` (part of
AFL++). If you built AFL++ from source, that's usually
`AFLplusplus/afl-clang-fast++`.

## Running AFL++

```bash
# Exception-safe custom stack
afl-fuzz -i corpus -o out_mystack -- ./build/mystack_afl_asan

# Unguarded STL stack
afl-fuzz -i corpus_stl -o out_stlstack -- ./build/stlstack_afl_asan

# Validate your setup: this build has the planted bug and SHOULD
# produce a crash quickly
afl-fuzz -i corpus -o out_mystack_buggy -- ./build/mystack_buggy_afl_asan
```

Run each campaign for a fixed, equal wall-clock time (e.g. 30–60 min) so
your comparison is fair. `afl-fuzz` writes crashing inputs to
`out_*/default/crashes/`.

## Analyzing the results: `analysis/analyze_afl.py`

Once you have `out_mystack/`, `out_stlstack/`, and (optionally)
`out_mystack_buggy/` from real `afl-fuzz` runs, generate a full comparison
report:

```bash
pip install -r analysis/requirements.txt   # optional, only needed for charts

python3 analysis/analyze_afl.py \
    --run mystack=out_mystack \
    --run stlstack=out_stlstack \
    --run mystack_buggy=out_mystack_buggy \
    --binary mystack=build/mystack_afl_asan \
    --binary stlstack=build/stlstack_afl_asan \
    --binary mystack_buggy=build/mystack_buggy_afl_asan \
    --out analysis_report
```

This parses `fuzzer_stats` and `plot_data` from each run (handles both the
`<out>/default/...` and `<out>/...` layouts) and writes, into
`analysis_report/`:

- **`report.md`** — a comparison table across all runs (runtime, total
  execs, execs/sec, corpus size, AFL-reported crash/hang counts, time to
  first crash) plus a per-run breakdown.
- **`comparison.csv`** — the same table, for a spreadsheet.
- **`<run>_signatures.csv`** — one row per *distinct* crash, with a count
  and an example input file (only produced if you pass `--binary` for
  that run).
- **`execs_per_sec.png`, `paths_over_time.png`, `crash_counts.png`** — if
  `matplotlib` is installed.

**Why `--binary` matters:** AFL's own `unique_crashes` counter (and the
number of files in `crashes/`) is based on its coverage bitmap, which
routinely produces many files for what is really the *same* underlying
bug reached via slightly different byte sequences. If you pass
`--binary NAME=path`, the script replays every crashing input through the
actual instrumented binary, captures its ASan/UBSan output, and groups
crashes by that signature — so `crash_counts.png` directly shows you "AFL
crash files" vs. "actual distinct bugs" side by side, which is usually a
much more honest number to report than AFL's raw crash count.

I validated the script's parsing and replay/signature logic against
synthetic AFL output before shipping it (not against a real `afl-fuzz`
run, since I don't have AFL++ or network access here) — worth doing a
quick sanity pass yourself against your real output before trusting it
for your write-up.

## What I verified (in this sandbox, without AFL++)

- `mystack_asan` run against every seed exits 0 with no sanitizer output —
  every `StackFullException`/`StackEmptyException` is caught as intended.
- `stlstack_asan` run against the empty-pop/top seed triggers a UBSan
  "misaligned address" report and, with `-fno-sanitize-recover=all`,
  aborts (exit 1) — confirming the unguarded STL usage really does fail
  on invalid memory access rather than throwing.
- `mystack_buggy_asan` (the `-DINJECT_BUG` build) run against the 20-push
  overflow seed triggers a clean ASan heap-buffer-overflow report at the
  exact `push()` line and aborts. Note: I originally implemented
  `FixedStack`'s buffer as an embedded `std::array` member, and the
  injected off-by-one silently corrupted the adjacent `top_` member
  instead of tripping ASan, because ASan's stack/heap redzones don't
  extend *between members of the same object*. Switching to a
  heap-allocated buffer (`std::unique_ptr<T[]>`) fixed this, since heap
  allocations get an exact-size redzone. That's a real, useful thing to
  mention in your write-up: **ASan's detection power depends on how a
  buffer is allocated, not just whether an OOB access happens.**

## Analysis framework — what to actually measure and discuss

Your assignment asks you to analyze how well AFL does at fuzzing a stack.
Concretely, that likely means covering:

**1. Coverage and time-to-first-crash**
- Compare `out_mystack/default/plot_data` vs `out_stlstack/default/plot_data`
  (edges found, execs/sec, time to first crash) using `afl-plot` or by
  hand.
- Use `out_mystack_buggy` as your positive control: if AFL++ can't find
  the deliberately planted bug quickly, something is wrong with your
  harness/corpus, not with AFL's general ability.

**2. Why a stack is an interesting (and awkward) fuzz target**
- A stack's failure states are *reachable only through specific operation
  sequences*, not through any single byte value. Reaching "full" requires
  `Capacity` consecutive successful pushes; reaching "empty-then-pop"
  requires the very next byte after start (or after enough pops) to be a
  pop/top. Discuss whether AFL's coverage-guided mutation actually needs
  to "discover" these sequences, or whether they're already close enough
  to the seeds that mutation finds them trivially — this is worth
  measuring by trying campaigns **with and without** the
  `seed_overflow`/`seed_underflow` seeds and comparing time-to-crash.
- The op-encoding matters a lot: because 2 of 4 byte outcomes are "push"
  and each byte carries its own push value, AFL's bitflip/havoc mutations
  land on valid operations with reasonably high probability, unlike a
  format with magic numbers or checksums. That's part of why a stack is
  considered a comparatively fuzzer-friendly (if simple) target.

**3. The exception-safe vs. UB asymmetry (this is the heart of the
   comparison)**
- `FixedStack` is designed so that AFL should find **zero** genuine
  crashes across arbitrary inputs (barring `INJECT_BUG`) — every failure
  path is a handled exception. A successful fuzzing campaign here is one
  that produces no crashes despite high coverage, which is a different
  (and easy to under-appreciate) kind of "success" than finding bugs.
- `std::stack` used without checks is not comparable apples-to-apples: it
  has no fixed capacity, so there's no analog of `StackFullException` to
  fuzz for at all — only the empty-pop/top case is comparable. Discuss
  this asymmetry explicitly; it's a legitimate limitation of using
  `std::stack` as a "control," not a bug in your experiment.
- Discuss the sanitizer dependency described above: without ASan/UBSan
  (and without `-fno-sanitize-recover=all`), the STL misuse may look
  indistinguishable from safe code under AFL, which says more about your
  build flags than about either stack implementation.

**4. Interesting AFL++ command-line flags to try and report on**
- `-D` (deterministic fuzzing stage) vs skipping it, for effect on a
  small, simple input space like this.
- `-x` with a dictionary of the 4 meaningful byte values (0/1/2/3, or
  really any 4 mod-4 classes) to see if it changes convergence speed on
  such a small alphabet.
- `-p` power schedules (e.g. `fast` vs `explore`) and their effect on
  time-to-crash for `mystack_buggy`.
- `AFL_HANG_TMOUT`/`-t` — not expected to matter much here since this
  target never hangs, worth confirming and noting as a negative result.
- Parallel fuzzing (`-M`/`-S` multiple instances) and whether it
  meaningfully speeds up discovery of the empty-pop UB in `stlstack`,
  given how shallow that bug is (reachable in 1–2 bytes).

## Seeing the actual stacks AFL builds: `tools/stack_trace.cpp` + `analysis/visualize_stacks.py`

Both harnesses decode their stdin into a sequence of push/pop/top
operations via a shared factory, `StackOpFactory::decode()` in
`include/stack_op_factory.hpp`. `tools/stack_trace.cpp` is a small CLI
built on that *same* factory: given any single testcase file (a corpus
seed, an AFL queue entry, a crash, anything), it replays the decoded
operations and prints, step by step, exactly what stack state AFL's
bytes actually built -- because it's built on the identical decoding
logic the real harness uses, there's no risk of the visualizer silently
drifting out of sync with what AFL was actually exercising.

Build it with:

```bash
make tools    # produces build/stack_trace
```

Use it directly on one file:

```bash
./build/stack_trace --target mystack  --file corpus/seed_overflow
./build/stack_trace --target stlstack --file out_stlstack/default/crashes/id:000000,...
```

Sample output (`mystack`, a 20-push seed against a 16-slot capacity):

```
20 byte(s) decoded into 20 operation(s)
op 1: PUSH 2 -> [2] (size 1/16)
op 2: PUSH 2 -> [2, 2] (size 2/16)
...
op 16: PUSH 2 -> [2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2] (size 16/16)
op 17: PUSH 2 -> REJECTED: StackFullException: cannot push, capacity 16 reached
...
-- summary: pushes=20 pops=0 tops=0 rejected_full=4 rejected_empty_pop=0 rejected_empty_top=0 max_size=16 reached_full=yes final_size=16
```

For `stlstack`, the tool intentionally does **not** actually call
`pop()`/`top()` on an empty stack (that's undefined behavior, and this
tool is meant to be safe to run over an entire queue directory without
segfaulting partway through) -- it prints a note instead and moves on.
That's a deliberate, clearly-labeled divergence from the real harness,
which *does* call it unguarded so AFL/ASan can find it.

### Analyzing a whole queue: `analysis/visualize_stacks.py`

This is the "how well did AFL do at building stacks" analysis. Point it
at an AFL queue/crashes directory (or your `corpus`/`corpus_stl` seed
dirs) and it shells out to `stack_trace` for every file:

```bash
# Show individual traces (up to --limit) plus aggregate stats over ALL files:
python3 analysis/visualize_stacks.py --target mystack \
    --tool build/stack_trace --dir out_mystack/default/queue --limit 10

# Just the aggregate stats, no per-file traces (better for a big queue):
python3 analysis/visualize_stacks.py --target stlstack \
    --tool build/stack_trace --dir out_stlstack/default/queue --stats-only

# One specific file in full detail:
python3 analysis/visualize_stacks.py --target mystack \
    --tool build/stack_trace --file corpus/seed_overflow
```

It reports: how many testcases reached a genuinely **full** stack (for
`mystack` only -- `std::stack` has no fixed capacity, so this is
reported as n/a for `stlstack`), how many attempted a pop/top on an
**empty** stack, the max depth seen anywhere, and a histogram of
max-depth-reached across every testcase. I validated this against a
synthetic 200-file "queue" of random byte strings (since I don't have a
real `afl-fuzz` run to point it at here) and it surfaced exactly the
result you'd expect: pure random mutation reached a full 16-slot stack
in only ~0.5% of testcases (it needs 16 consecutive "push-selecting"
bytes with no interrupting pop/top), while about a third of testcases
trivially hit the empty-pop/empty-top case (reachable in a single
byte). That gap is itself a good data point for your "how well does AFL
explore a stack's state space" write-up -- and a real `afl-fuzz` run,
guided by coverage feedback and your seed corpus, should very plausibly
do much better at reaching "full" than raw random mutation does, which
is a comparison worth actually running and including.

## Notes / assumptions I made

- Capacity fixed at 16 in both harnesses — small enough that AFL should
  reach "full" easily, but big enough to not be trivially reached by
  every seed. Change `kCapacity` in `harness/mystack_fuzz.cpp` if you
  want a different tradeoff.
- Byte-stream op encoding (`% 4`) rather than a more structured format —
  keeps the input space simple and fuzzer-friendly, which is usually what
  you want for a first AFL++ target.
- I did not wire up FuzzTest or any other fuzzer here since you only
  mentioned AFL++ this time; let me know if you also want a FuzzTest
  harness for comparison the way we did in the earlier AFL++ vs FuzzTest
  project.
# test change