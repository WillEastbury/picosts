#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT="${TEST_PORT:-15100}"
DATA_DIR="$(mktemp -d /tmp/picosts-password.XXXXXX)"
LOG="$(mktemp /tmp/picosts-password.XXXXXX.log)"
PID=""

cleanup() {
  if [[ -n "$PID" ]]; then
    kill "$PID" 2>/dev/null || true
    wait "$PID" 2>/dev/null || true
  fi
  rm -rf "$DATA_DIR"
  rm -f "$LOG"
}
trap cleanup EXIT

dotnet build "$ROOT/sts.csproj" -c Release --nologo >/dev/null
ASPNETCORE_URLS="http://127.0.0.1:$PORT" \
STS_ISSUER="http://127.0.0.1:$PORT" \
STS_DATA_DIR="$DATA_DIR" \
STS_ADMIN_PASSWORD="Initial9Pass" \
dotnet run --project "$ROOT/sts.csproj" -c Release --no-build >"$LOG" 2>&1 &
PID=$!

for _ in {1..80}; do
  if curl --silent --fail --max-time 1 "http://127.0.0.1:$PORT/health" >/dev/null; then
    break
  fi
  sleep 0.1
done

token="$(
  curl --silent --fail --max-time 3 \
    --data-urlencode "grant_type=password" \
    --data-urlencode "client_id=spa" \
    --data-urlencode "username=admin" \
    --data-urlencode "password=Initial9Pass" \
    "http://127.0.0.1:$PORT/token" |
  python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])'
)"

status="$(
  curl --silent --max-time 3 --output /dev/null --write-out '%{http_code}' \
    --request POST \
    --header "Authorization: Bearer $token" \
    --header "Content-Type: application/json" \
    --data '{"currentPassword":"Initial9Pass","newPassword":"Changed8Pass"}' \
    "http://127.0.0.1:$PORT/account/password"
)"
[[ "$status" == "204" ]]

old_status="$(
  curl --silent --max-time 3 --output /dev/null --write-out '%{http_code}' \
    --data-urlencode "grant_type=password" \
    --data-urlencode "client_id=spa" \
    --data-urlencode "username=admin" \
    --data-urlencode "password=Initial9Pass" \
    "http://127.0.0.1:$PORT/token"
)"
[[ "$old_status" == "400" ]]

new_status="$(
  curl --silent --max-time 3 --output /dev/null --write-out '%{http_code}' \
    --data-urlencode "grant_type=password" \
    --data-urlencode "client_id=spa" \
    --data-urlencode "username=admin" \
    --data-urlencode "password=Changed8Pass" \
    "http://127.0.0.1:$PORT/token"
)"
[[ "$new_status" == "200" ]]

echo "PicoSTS password change passed"
