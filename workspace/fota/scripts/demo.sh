#!/usr/bin/env bash
# Reproducible end-to-end demo against a running container.
#
#   docker compose up --build -d     # service on :8080, demo data seeded
#   ./scripts/demo.sh                # builds the image, drives a 10-device fleet
#
# Every fleet invocation = one fleet "wake-up". Each device advances at most a
# few steps (check-in -> resumable download -> install), exactly like real
# intermittently-connected terminals coming online on a schedule.
set -euo pipefail

BASE_URL="${FOTA_URL:-http://localhost:8080}"
IMAGE="fota-service:dev"

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo ">> building $IMAGE"
  docker build -t "$IMAGE" .
fi

api() { curl -fsS "$@"; }

run() {
  docker run --rm --network host -v fota-fleet:/fleet "$IMAGE" \
    python client/fleet.py --base-url "$BASE_URL" --workdir /fleet "$@"
}

stage_id() { # $1 = stage number
  api "$BASE_URL/api/admin/batches" \
    | python3 -c "import json,sys;print([b for b in json.load(sys.stdin) if b['stage']==$1][0]['id'])"
}
action() { # $1 = batch id, $2 = json body
  api -X POST "$BASE_URL/api/admin/batches/$1/action" -H 'content-type: application/json' -d "$2" >/dev/null
}

echo "== 0) health"; api "$BASE_URL/healthz"; echo

B1=$(stage_id 1)
echo "== 1) activate seeded canary stage (HW2026Q3, quota=2): $B1"
action "$B1" '{"action":"activate"}'

echo "== 2) wake #1: 10 terminals, radio dies after 1 block (only 2 get seats)"
run --count 10 --drop-chunks 1

echo "== 3) operator PAUSES while the two devices are mid-download"
action "$B1" '{"action":"pause"}'
echo "== 4) wake #2 while paused: not-yet-installed devices must stop"
run --count 10

echo "== 5) resume; wake #3 resumes from verified blocks and installs"
action "$B1" '{"action":"resume","force":true}'
run --count 10 --steps 3

CID=$(api "$BASE_URL/api/admin/batches" | python3 -c 'import json,sys;print(json.load(sys.stdin)[0]["campaign_id"])')
echo "== 6) create stage 2 (quota=10, halt at >=20% over >=5 attempts) and stage 3 child"
api -X POST "$BASE_URL/api/admin/batches" -H 'content-type: application/json' \
  -d "{\"campaign_id\":\"$CID\",\"hardware_batch\":\"HW2026Q3\",\"stage\":2,\"quota_mode\":\"absolute\",\"quota_value\":10,\"failure_threshold\":0.2,\"failure_min_sample\":5}" >/dev/null
B2=$(stage_id 2)
api -X POST "$BASE_URL/api/admin/batches" -H 'content-type: application/json' \
  -d "{\"campaign_id\":\"$CID\",\"hardware_batch\":\"HW2026Q3\",\"stage\":3,\"quota_mode\":\"absolute\",\"quota_value\":10,\"parent_id\":\"$B2\"}" >/dev/null
B3=$(stage_id 3)
action "$B2" '{"action":"activate"}'
action "$B3" '{"action":"activate"}'

echo "== 7) wake #4: devices 2,3 fail install and roll back to 1.9.0. After 5"
echo "      terminal attempts (2 fail / 3 ok = 40%) the service auto-halts stage 2"
echo "      and cascades to stage 3, so devices 7-9 are not even offered."
run --count 10 --fail-ids 2,3 --steps 3

echo "== 8) final batch states / stats"
api "$BASE_URL/api/admin/batches" | python3 -m json.tool
api "$BASE_URL/api/admin/overview" | python3 -m json.tool
