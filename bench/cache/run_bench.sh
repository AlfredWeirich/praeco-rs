#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

PRAECO_BIN="${PRAECO_BIN:-$REPO_ROOT/target/release/praeco-rs}"
DURATION="${DURATION:-10s}"
CONNECTIONS="${CONNECTIONS:-32}"
THREADS="${THREADS:-4}"
DB_DELAY_MS="${DB_DELAY_MS:-10}"
STAMPEDE_CONCURRENCY="${STAMPEDE_CONCURRENCY:-32}"

GW_URL="http://127.0.0.1:18080"
ADMIN_URL="http://127.0.0.1:18090"
BACKEND_URL="http://127.0.0.1:18081"

TMP_DIR="$(mktemp -d)"
BACKEND_PID=""
PRAECO_PID=""

cleanup() {
    local code=$?
    if [[ -n "$PRAECO_PID" ]] && kill -0 "$PRAECO_PID" 2>/dev/null; then
        kill -TERM "$PRAECO_PID" 2>/dev/null || true
        wait "$PRAECO_PID" 2>/dev/null || true
    fi
    if [[ -n "$BACKEND_PID" ]] && kill -0 "$BACKEND_PID" 2>/dev/null; then
        kill -TERM "$BACKEND_PID" 2>/dev/null || true
        wait "$BACKEND_PID" 2>/dev/null || true
    fi
    rm -rf "$TMP_DIR"
    exit "$code"
}
trap cleanup EXIT INT TERM

for bin in wrk python3 curl; do
    if ! command -v "$bin" >/dev/null 2>&1; then
        echo "Missing required tool: $bin" >&2
        exit 1
    fi
done

for port in 18080 18081 18090; do
    if python3 -c "import socket,sys; s=socket.socket(); sys.exit(0 if s.connect_ex(('127.0.0.1',$port))==0 else 1)" 2>/dev/null; then
        echo "Error: 127.0.0.1:$port is already in use (another benchmark or service running?)." >&2
        exit 1
    fi
done

for port in 18080 18081 18090; do
    if lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then
        echo "Port $port is already in use; stop the existing process first." >&2
        exit 1
    fi
done

if [[ "${1:-}" == "--build" || ! -x "$PRAECO_BIN" ]]; then
    echo "Building praeco-rs release binary..."
    cargo build --release -p praeco-rs --manifest-path "$REPO_ROOT/Cargo.toml"
fi

wait_for_http() {
    local url="$1"
    local name="$2"
    for _ in $(seq 1 50); do
        if curl -sf "$url" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.1
    done
    echo "Timed out waiting for $name at $url" >&2
    exit 1
}

start_praeco() {
    local cfg="$1"
    local log_file="$2"
    if [[ -n "$PRAECO_PID" ]] && kill -0 "$PRAECO_PID" 2>/dev/null; then
        kill -TERM "$PRAECO_PID" 2>/dev/null || true
        wait "$PRAECO_PID" 2>/dev/null || true
        PRAECO_PID=""
    fi
    RUST_LOG=warn "$PRAECO_BIN" "$cfg" >"$log_file" 2>&1 &
    PRAECO_PID=$!
    wait_for_http "$ADMIN_URL/healthz" "praeco-rs ($cfg)"
}

reset_backend_stats() {
    curl -sf -X POST "$BACKEND_URL/__reset" >/dev/null
}

read_db_queries() {
    curl -sf "$BACKEND_URL/__stats" | python3 -c 'import json,sys; print(json.load(sys.stdin)["db_queries"])'
}

warmup_and_verify_cache() {
    local label="$1"
    local method="$2"
    local path="$3"
    local extra_header="${4:-}"
    local body="${5:-}"

    local h1="$TMP_DIR/h1.txt"
    local h2="$TMP_DIR/h2.txt"

    if [[ "$method" == "POST" ]]; then
        curl -sS -D "$h1" -o /dev/null -X POST -H "Content-Type: application/json" -d "$body" "$GW_URL$path"
        curl -sS -D "$h2" -o /dev/null -X POST -H "Content-Type: application/json" -d "$body" "$GW_URL$path"
    elif [[ -n "$extra_header" ]]; then
        curl -sS -D "$h1" -o /dev/null -H "$extra_header" "$GW_URL$path"
        curl -sS -D "$h2" -o /dev/null -H "$extra_header" "$GW_URL$path"
    else
        curl -sS -D "$h1" -o /dev/null "$GW_URL$path"
        curl -sS -D "$h2" -o /dev/null "$GW_URL$path"
    fi

    local c1 c2
    c1=$(grep -i '^x-praeco-cache:' "$h1" | awk '{print $2}' | tr -d '\r' || true)
    c2=$(grep -i '^x-praeco-cache:' "$h2" | awk '{print $2}' | tr -d '\r' || true)
    echo "  Warm-up [$label]: call1=${c1:-none}, call2=${c2:-none}"
    if [[ "$c2" != "HIT" ]]; then
        echo "Expected x-praeco-cache: HIT on warm-up #2 for $label, got '${c2:-none}'" >&2
        exit 1
    fi
}

run_wrk_scenario() {
    local out_json="$1"
    local url="$2"
    shift 2
    local raw_out="$TMP_DIR/wrk_raw.txt"
    wrk -t "$THREADS" -c "$CONNECTIONS" -d "$DURATION" --latency "$@" "$url" | tee "$raw_out"
    local db_q
    db_q="$(read_db_queries)"
    python3 - "$raw_out" "$out_json" "$db_q" <<'PY'
import json, re, sys
raw = open(sys.argv[1]).read()
rps_m = re.search(r"Requests/sec:\s+([0-9.]+)", raw)
lat_m = re.search(r"^\s*Latency\s+([0-9.]+[a-zA-Z]+)", raw, re.M)
p99_m = re.search(r"^\s*99%\s+([0-9.]+[a-zA-Z]+)", raw, re.M)
err_m = re.search(r"Non-2xx or 3xx responses:\s+([0-9]+)", raw)
data = {
    "rps": float(rps_m.group(1)) if rps_m else 0.0,
    "avg_lat": lat_m.group(1) if lat_m else "?",
    "p99_lat": p99_m.group(1) if p99_m else "?",
    "db_queries": int(sys.argv[3]),
    "non_2xx": int(err_m.group(1)) if err_m else 0,
}
open(sys.argv[2], "w").write(json.dumps(data))
PY
}

echo "=== Praeco Cache A/B Benchmark ==="
echo "Parameters: duration=$DURATION, connections=$CONNECTIONS, threads=$THREADS, db_delay_ms=$DB_DELAY_MS"
echo

python3 "$SCRIPT_DIR/mock_db_backend.py" --host 127.0.0.1 --port 18081 --db-delay-ms "$DB_DELAY_MS" >"$TMP_DIR/backend.log" 2>&1 &
BACKEND_PID=$!
wait_for_http "$BACKEND_URL/__stats" "mock_db_backend"

# ---------------------------------------------------------------------------
# Phase 1: Baseline WITHOUT Cache
# ---------------------------------------------------------------------------
echo ">>> Phase 1: Baseline WITHOUT Cache (config_no_cache.toml)"
start_praeco "$SCRIPT_DIR/config_no_cache.toml" "$TMP_DIR/praeco_nocache.log"

echo "[1/3] GET /api/products?category=fruit&limit=25 (plain)"
reset_backend_stats
run_wrk_scenario "$TMP_DIR/no_get_plain.json" "$GW_URL/api/products?category=fruit&limit=25"

echo "[2/3] GET /api/products?category=fruit&limit=25 (Accept-Encoding: gzip)"
reset_backend_stats
run_wrk_scenario "$TMP_DIR/no_get_gzip.json" "$GW_URL/api/products?category=fruit&limit=25" -H "Accept-Encoding: gzip"

echo "[3/3] POST /api/query (JSON query)"
reset_backend_stats
run_wrk_scenario "$TMP_DIR/no_post.json" "$GW_URL/api/query" -s "$SCRIPT_DIR/wrk_post.lua"

# ---------------------------------------------------------------------------
# Phase 2: WITH Response Cache + Lazy Precompression
# ---------------------------------------------------------------------------
echo
echo ">>> Phase 2: WITH Cache (config_with_cache.toml)"
start_praeco "$SCRIPT_DIR/config_with_cache.toml" "$TMP_DIR/praeco_cache.log"

echo "[1/3] GET /api/products?category=fruit&limit=25 (plain)"
reset_backend_stats
warmup_and_verify_cache "GET plain" GET "/api/products?category=fruit&limit=25"
run_wrk_scenario "$TMP_DIR/yes_get_plain.json" "$GW_URL/api/products?category=fruit&limit=25"

echo "[2/3] GET /api/products?category=fruit&limit=25 (Accept-Encoding: gzip)"
reset_backend_stats
warmup_and_verify_cache "GET gzip" GET "/api/products?category=fruit&limit=25" "Accept-Encoding: gzip"
run_wrk_scenario "$TMP_DIR/yes_get_gzip.json" "$GW_URL/api/products?category=fruit&limit=25" -H "Accept-Encoding: gzip"

echo "[3/3] POST /api/query (JSON query)"
reset_backend_stats
warmup_and_verify_cache "POST query" POST "/api/query" "" '{"category":"fruit","limit":25}'
run_wrk_scenario "$TMP_DIR/yes_post.json" "$GW_URL/api/query" -s "$SCRIPT_DIR/wrk_post.lua"

# ---------------------------------------------------------------------------
# Phase 3: Mutation Invalidation + Singleflight Stampede Check
# ---------------------------------------------------------------------------
echo
echo ">>> Phase 3: Mutation Invalidation + ${STAMPEDE_CONCURRENCY}-client Singleflight Stampede"
curl -sf -X POST "$GW_URL/api/mutate" >/dev/null
reset_backend_stats
PIDS=()
for i in $(seq 1 "$STAMPEDE_CONCURRENCY"); do
    curl -sS -D "$TMP_DIR/stampede_$i.hdr" -o /dev/null "$GW_URL/api/products?category=fruit&limit=25" &
    PIDS+=($!)
done
for pid in "${PIDS[@]}"; do
    wait "$pid"
done
STAMPEDE_DB_QUERIES="$(read_db_queries)"
STAMPEDE_HITS=$(grep -ih '^x-praeco-cache:' "$TMP_DIR"/stampede_*.hdr | awk '{print $2}' | tr -d '\r' | sort | uniq -c | tr '\n' ';')
echo "Concurrent callers: $STAMPEDE_CONCURRENCY | Backend DB queries executed: $STAMPEDE_DB_QUERIES"
echo "Cache outcomes: $STAMPEDE_HITS"

echo
echo ">>> Summary Comparison (No Cache vs. With Cache)"
python3 - "$TMP_DIR" <<'PY'
import json, os, sys
d = sys.argv[1]
cases = [
    ("GET plain", "no_get_plain.json", "yes_get_plain.json"),
    ("GET gzip",  "no_get_gzip.json",  "yes_get_gzip.json"),
    ("POST json", "no_post.json",      "yes_post.json"),
]
print(f"{'Scenario':<12} | {'NoCache RPS':>11} | {'Cache RPS':>11} | {'Speedup':>8} | {'Avg Lat (No -> Cache)':>23} | {'p99 (No -> Cache)':>21} | {'DB Queries (No -> Cache)':>24}")
print("-" * 124)
for label, nf, yf in cases:
    no = json.load(open(os.path.join(d, nf)))
    ye = json.load(open(os.path.join(d, yf)))
    spd = (ye["rps"] / no["rps"]) if no["rps"] > 0 else 0.0
    avg = f"{no['avg_lat']} -> {ye['avg_lat']}"
    p99 = f"{no['p99_lat']} -> {ye['p99_lat']}"
    dbq = f"{no['db_queries']} -> {ye['db_queries']}"
    print(f"{label:<12} | {no['rps']:>11.1f} | {ye['rps']:>11.1f} | {spd:>7.1f}x | {avg:>23} | {p99:>21} | {dbq:>24}")
PY

echo
echo ">>> Praeco Cache Prometheus Metrics ($ADMIN_URL/metrics)"
curl -sf "$ADMIN_URL/metrics" | grep -E '^praeco_(server_)?cache_' || true
