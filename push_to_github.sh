#!/usr/bin/env bash
# push_to_github.sh -- initialize a git repo for this project and push it
# to GitHub.
#
# Two ways to use it:
#
#   1) You have the GitHub CLI (`gh`) installed and logged in:
#        ./push_to_github.sh --create stack-fuzz --private
#      This creates the GitHub repo for you and pushes in one step.
#
#   2) You already created an (empty) repo on github.com yourself and
#      just want this script to init/commit/push to it:
#        ./push_to_github.sh --remote-url git@github.com:USER/stack-fuzz.git
#      or
#        ./push_to_github.sh --remote-url https://github.com/USER/stack-fuzz.git
#
# Either way it will:
#   - run `git init` if this isn't already a repo (safe to re-run -- it
#     won't re-init or discard existing history)
#   - write a .gitignore covering build/, out_*/, logs/, etc. if one
#     doesn't already exist
#   - stage and commit everything currently in the directory (skips the
#     commit step if there's nothing new to commit)
#   - add/update the "origin" remote and push to it
#
# It does NOT store, print, or embed any credentials/tokens. Auth is
# whatever your git/gh/ssh setup already uses (ssh key, credential
# helper, gh's own stored token, etc.) -- if that's not set up yet,
# git/gh will prompt you the normal way when you push.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

BRANCH="main"
COMMIT_MSG="Initial commit"
REMOTE_URL=""
CREATE_NAME=""
VISIBILITY="private" # only used with --create

usage() {
    cat <<EOF
Usage:
  $0 --create <repo-name> [--private|--public] [--branch main] [--message "..."]
  $0 --remote-url <git-url> [--branch main] [--message "..."]
 
Options:
  --create NAME       Create a new GitHub repo named NAME using the 'gh' CLI
                       and push to it. Requires 'gh' installed and logged in
                       (run 'gh auth login' first if needed).
  --private            With --create: make the new repo private (default).
  --public             With --create: make the new repo public.
  --remote-url URL     Push to an existing (already-created, empty) GitHub
                       repo at this URL instead of creating one.
                       e.g. git@github.com:you/stack-fuzz.git
  --branch NAME        Branch to push to (default: main).
  --message "..."      Commit message for the initial commit
                       (default: "Initial commit"). Only used if there are
                       changes to commit.
  -h, --help           Show this help.
EOF
    exit 1
}

while [ $# -gt 0 ]; do
    case "$1" in
        --create)      CREATE_NAME="$2"; shift 2 ;;
        --private)     VISIBILITY="private"; shift ;;
        --public)      VISIBILITY="public"; shift ;;
        --remote-url)  REMOTE_URL="$2"; shift 2 ;;
        --branch)      BRANCH="$2"; shift 2 ;;
        --message)     COMMIT_MSG="$2"; shift 2 ;;
        -h|--help)     usage ;;
        *) echo "[!] Unknown argument: $1" >&2; usage ;;
    esac
done

if [ -z "$CREATE_NAME" ] && [ -z "$REMOTE_URL" ]; then
    echo "[!] You must pass either --create <name> or --remote-url <url>." >&2
    usage
fi
if [ -n "$CREATE_NAME" ] && [ -n "$REMOTE_URL" ]; then
    echo "[!] Pass only one of --create or --remote-url, not both." >&2
    usage
fi
 
command -v git >/dev/null 2>&1 || { echo "[!] git is not installed / not on PATH." >&2; exit 1; }
 
# --- .gitignore -----------------------------------------------------------
if [ ! -f .gitignore ]; then
    echo "[i] Writing .gitignore ..."
    cat > .gitignore <<'GITIGNORE'
# Build artifacts
build/
 
# AFL++ output directories (one per fuzzing campaign)
out_*/
 
# run_fuzz.sh background-job bookkeeping
logs/
.fuzz_pids
 
# analyze_afl.py output
analysis_report/
test_analysis_report/
test_out/
 
# misc
*.o
*.core
core
__pycache__/
*.pyc
.DS_Store
GITIGNORE
else
    echo "[i] .gitignore already exists -- leaving it as-is."
fi
 
# --- git init ---------------------------------------------------------------
if [ -d .git ]; then
    echo "[i] Already a git repo (.git exists) -- skipping 'git init'."
else
    echo "[i] Running 'git init' ..."
    git init
fi
 
# Make sure we're on the branch we intend to push (handles both a fresh
# repo, where the initial branch may be 'master' or 'main' depending on
# git's default, and an existing repo already on some other branch).
current_branch="$(git symbolic-ref --short -q HEAD || true)"
if [ -z "$current_branch" ]; then
    # No commits yet -- set the initial branch name directly.
    git symbolic-ref HEAD "refs/heads/$BRANCH"
elif [ "$current_branch" != "$BRANCH" ]; then
    echo "[i] Currently on branch '$current_branch', switching/renaming to '$BRANCH' ..."
    git branch -M "$BRANCH"
fi
 
# --- stage + commit ---------------------------------------------------------
git add -A
if git diff --cached --quiet; then
    echo "[i] Nothing to commit (working tree matches last commit, or this is empty)."
else
    echo "[i] Committing ..."
    git commit -m "$COMMIT_MSG"
fi
 
# --- remote + push -----------------------------------------------------------
if [ -n "$CREATE_NAME" ]; then
    command -v gh >/dev/null 2>&1 || { echo "[!] --create requires the 'gh' CLI, which isn't installed/on PATH. Install it, or use --remote-url instead with a repo you create manually on github.com." >&2; exit 1; }
    if ! gh auth status >/dev/null 2>&1; then
        echo "[!] 'gh' is installed but not logged in. Run 'gh auth login' first, then re-run this script." >&2
        exit 1
    fi
 
    if git remote get-url origin >/dev/null 2>&1; then
        echo "[i] 'origin' remote already set (to $(git remote get-url origin)) -- pushing there instead of creating a new repo."
        echo "[i] Pushing to origin/$BRANCH ..."
        git push -u origin "$BRANCH"
    else
        echo "[i] Creating GitHub repo '$CREATE_NAME' ($VISIBILITY) and pushing via gh ..."
        gh repo create "$CREATE_NAME" "--$VISIBILITY" --source=. --remote=origin --push
    fi
else
    if git remote get-url origin >/dev/null 2>&1; then
        existing="$(git remote get-url origin)"
        if [ "$existing" != "$REMOTE_URL" ]; then
            echo "[i] Updating 'origin' remote from $existing to $REMOTE_URL ..."
            git remote set-url origin "$REMOTE_URL"
        else
            echo "[i] 'origin' remote already set to $REMOTE_URL."
        fi
    else
        echo "[i] Adding 'origin' remote: $REMOTE_URL"
        git remote add origin "$REMOTE_URL"
    fi
    echo "[i] Pushing to origin/$BRANCH ..."
    git push -u origin "$BRANCH"
fi
 
echo "[i] Done."
echo "[i] Remote: $(git remote get-url origin)"
echo "[i] Branch: $BRANCH"