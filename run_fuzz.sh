#!/usr/bin/env bash
# run_fuzz.sh -- build the AFL++-instrumented stack binaries and launch
# afl-fuzz against both targets (mystack, stlstack), using an AFL++
# install that lives in a completely different directory.
#
# Run this FROM your stack-fuzz project directory (the one with the
# Makefile, include/, harness/, corpus/, corpus_stl/ in it):
#
#   ./run_fuzz.sh build  ~/AFLplusplus
#   ./run_fuzz.sh run    ~/AFLplusplus
#   ./run_fuzz.sh status
#   ./run_fuzz.sh stop
#
# "build" compiles the AFL++-instrumented, ASan/UBSan-enabled binaries.
# "run" launches one afl-fuzz process per target IN THE BACKGROUND (so
#   they keep going if your shell disconnects), logging to logs/*.log
#   and tracking PIDs in .fuzz_pids so "status"/"stop" can find them.
# "status" shows whether each fuzzer is still alive and tails its stats.
# "stop" kills all fuzzers this script started.
#
# Optional: pass a duration in seconds as a 3rd argument to "run" to
# auto-stop after that long (uses afl-fuzz's own -V flag), e.g.:
#   ./run_fuzz.sh run ~/AFLplusplus 3600      # run for 1 hour

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

PID_FILE="$SCRIPT_DIR/.fuzz_pids"
LOG_DIR="$SCRIPT_DIR/logs"

# name -> (build target suffix, corpus dir, output dir)
TARGETS=(mystack stlstack mystack_buggy)
declare -A CORPUS_DIR=(
    [mystack]="corpus"
    [mystack_buggy]="corpus"
    [stlstack]="corpus_stl"
)
declare -A OUT_DIR=(
    [mystack]="out_mystack"
    [mystack_buggy]="out_mystack_buggy"
    [stlstack]="out_stlstack"
)

usage() {
    echo "Usage:"
    echo "  $0 build <path-to-AFLplusplus-dir>"
    echo "  $0 run   <path-to-AFLplusplus-dir> [duration_seconds]"
    echo "  $0 status"
    echo "  $0 stop"
    exit 1
}

require_afl_dir() {
    local afl_dir="$1"
    if [ ! -x "$afl_dir/afl-clang-fast++" ]; then
        echo "[!] $afl_dir/afl-clang-fast++ not found or not executable." >&2
        echo "    Point this at the directory containing your built AFL++ binaries" >&2
        echo "    (the one with afl-fuzz, afl-clang-fast++, etc. directly inside it)." >&2
        exit 1
    fi
    if [ ! -x "$afl_dir/afl-fuzz" ]; then
        echo "[!] $afl_dir/afl-fuzz not found or not executable." >&2
        exit 1
    fi
}

cmd_build() {
    local afl_dir="${1:-}"
    [ -z "$afl_dir" ] && usage
    afl_dir="$(cd "$afl_dir" && pwd)"
    require_afl_dir "$afl_dir"

    echo "[i] Building AFL++-instrumented ASan/UBSan binaries using $afl_dir/afl-clang-fast++ ..."
    make afl-asan AFLXX="$afl_dir/afl-clang-fast++"

    for t in "${TARGETS[@]}"; do
        if [ ! -x "build/${t}_afl_asan" ]; then
            echo "[!] Expected build/${t}_afl_asan but it wasn't produced -- check the make output above." >&2
            exit 1
        fi
    done
    echo "[i] Build OK: $(ls build/*_afl_asan | tr '\n' ' ')"
}

cmd_run() {
    local afl_dir="${1:-}"
    local duration="${2:-}"
    [ -z "$afl_dir" ] && usage
    afl_dir="$(cd "$afl_dir" && pwd)"
    require_afl_dir "$afl_dir"

    for t in "${TARGETS[@]}"; do
        if [ ! -x "build/${t}_afl_asan" ]; then
            echo "[!] build/${t}_afl_asan not found. Run '$0 build $afl_dir' first." >&2
            exit 1
        fi
    done

    if [ -f "$PID_FILE" ] && kill -0 "$(head -1 "$PID_FILE" | cut -d: -f2)" 2>/dev/null; then
        echo "[!] $PID_FILE exists and at least one listed PID is still alive." >&2
        echo "    Run '$0 stop' first, or remove $PID_FILE if that's stale." >&2
        exit 1
    fi
    : > "$PID_FILE"
    mkdir -p "$LOG_DIR"

    local v_flag=()
    if [ -n "$duration" ]; then
        v_flag=(-V "$duration")
        echo "[i] Each fuzzer will auto-stop after ${duration}s (afl-fuzz -V)."
    fi

    for t in "${TARGETS[@]}"; do
        local corpus="${CORPUS_DIR[$t]}"
        local out="${OUT_DIR[$t]}"
        local log="$LOG_DIR/${t}.log"

        if [ -d "$out" ]; then
            echo "[i] $out already exists -- afl-fuzz will attempt to resume that campaign."
        fi

        echo "[i] Launching afl-fuzz for '$t' (corpus=$corpus, out=$out, log=$log) ..."
        AFL_SKIP_CPUFREQ=1 AFL_NO_UI=1 AFL_AUTORESUME=1 \
            nohup "$afl_dir/afl-fuzz" -i "$corpus" -o "$out" "${v_flag[@]}" \
            -- "./build/${t}_afl_asan" > "$log" 2>&1 &
        local pid=$!
        disown "$pid" 2>/dev/null || true
        echo "$t:$pid" >> "$PID_FILE"
        sleep 1
        if ! kill -0 "$pid" 2>/dev/null; then
            echo "[!] '$t' fuzzer died immediately -- check $log:" >&2
            tail -n 20 "$log" >&2
        else
            echo "    started, pid $pid"
        fi
    done

    echo ""
    echo "[i] All fuzzers launched in the background. They'll keep running after"
    echo "    you log out of this shell. Check on them with:"
    echo "      $0 status"
    echo "    Stop them with:"
    echo "      $0 stop"
}

cmd_status() {
    if [ ! -f "$PID_FILE" ]; then
        echo "[i] No $PID_FILE found -- nothing appears to have been launched by this script."
        exit 0
    fi
    while IFS=: read -r t pid; do
        [ -z "$t" ] && continue
        local out="${OUT_DIR[$t]:-out_$t}"
        if kill -0 "$pid" 2>/dev/null; then
            echo "== $t (pid $pid, RUNNING) =="
        else
            echo "== $t (pid $pid, NOT RUNNING) =="
        fi
        local stats="$out/default/fuzzer_stats"
        [ -f "$stats" ] || stats="$out/fuzzer_stats"
        if [ -f "$stats" ]; then
            grep -E "^(execs_done|execs_per_sec|corpus_count|unique_crashes|unique_hangs|run_time)" "$stats" | sed 's/^/    /'
        else
            echo "    (no fuzzer_stats yet at $stats)"
        fi
        echo ""
    done < "$PID_FILE"
}

cmd_stop() {
    if [ ! -f "$PID_FILE" ]; then
        echo "[i] No $PID_FILE found -- nothing to stop."
        exit 0
    fi
    while IFS=: read -r t pid; do
        [ -z "$t" ] && continue
        if kill -0 "$pid" 2>/dev/null; then
            echo "[i] Stopping '$t' (pid $pid) ..."
            kill "$pid" 2>/dev/null || true
        else
            echo "[i] '$t' (pid $pid) already stopped."
        fi
    done < "$PID_FILE"
    rm -f "$PID_FILE"
}

main() {
    local sub="${1:-}"
    [ -z "$sub" ] && usage
    shift
    case "$sub" in
        build)  cmd_build "$@" ;;
        run)    cmd_run "$@" ;;
        status) cmd_status "$@" ;;
        stop)   cmd_stop "$@" ;;
        *) usage ;;
    esac
}

main "$@"