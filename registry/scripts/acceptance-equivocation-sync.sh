#!/usr/bin/env bash
# Two real peers, a real fork, over a real socket.
#
# This scenario exists because a unit test could not have found what it checks. `detectionsSince`
# is a pure function over ledger entries and passes whether or not anything calls it; the defect
# was that `cmdSync` called nothing. A connection detected an equivocation, wrote it to the ledger
# on both sides, and printed `equivocations 0 (0 new)` — accurate counters, since those count what
# the PEER SENT, and a zero in front of the operator at the one moment the protocol has something
# serious to say.
#
# So every assertion here reads the process's own output and its own files. Nothing is stubbed and
# nothing is imported: two Argon2id solves, two logs, one TCP connection.
set -u
cd "$(dirname "$0")/.."

VW=(node --experimental-strip-types bin/vayuweb-registry.ts)
D=$(mktemp -d)
PORT=${VW_SYNC_PORT:-7931}
NAME=atlasobservatory.vayu
AT=1782518400
# Two different content identifiers, so the two records differ in more than their signatures.
CID_ONE=bafkreifzjut3te2nhyekklss27nh3k72ysco7y32koao5eei66wof36n5e
CID_TWO=bafkreiaxlvczbcuvhwjrwqmz2s6lrx3zjrxpjnpbcvi3ohbrhkuuwqmxbe

pass=0
fail=0
ok() {
  echo "  PASS  $1"
  pass=$((pass + 1))
}
bad() {
  echo "  FAIL  $1"
  echo "        $2"
  fail=$((fail + 1))
}

cleanup() {
  [ -n "${LISTENER:-}" ] && kill "$LISTENER" 2>/dev/null
  wait "${LISTENER:-}" 2>/dev/null
  rm -rf "$D"
}
trap cleanup EXIT

echo "=== one owner, two futures for one name (two real proof-of-work solves) ==="
"${VW[@]}" keygen --key "$D/key" >/dev/null 2>&1
for pair in "a:$CID_ONE" "b:$CID_TWO"; do
  side=${pair%%:*}
  cid=${pair#*:}
  if ! "${VW[@]}" register --log "$D/$side.log" --key "$D/key" --name "$NAME" \
    --cid "$cid" --at "$AT" >/dev/null 2>&1; then
    echo "register into $side.log failed; cannot run this scenario"
    exit 1
  fi
done
ok "both logs hold a signed REGISTER for $NAME at seq 0, by one key, with different content"

echo
echo "=== sync them, and read what the operator is told ==="
"${VW[@]}" sync --log "$D/a.log" --listen "$PORT" > "$D/listener.out" 2>&1 &
LISTENER=$!
for _ in $(seq 1 30); do
  grep -q 'listening on' "$D/listener.out" 2>/dev/null && break
  sleep 0.5
done
timeout 40 "${VW[@]}" sync --log "$D/b.log" --connect "127.0.0.1:$PORT" > "$D/connector.out" 2>&1
kill "$LISTENER" 2>/dev/null
wait "$LISTENER" 2>/dev/null
LISTENER=

# The record itself must be refused. A peer that ACCEPTED the second future would have replaced a
# name's content on the strength of the owner contradicting themselves, which is the whole harm.
if grep -q 'rejected 1' "$D/connector.out"; then
  ok "the conflicting record is refused rather than applied"
else
  bad "the conflicting record was not refused" "$(grep 'peer ' "$D/connector.out" | head -1)"
fi

# **The assertion this scenario exists for.** Before the fix both of these failed: the ledgers grew
# and both summaries said `equivocations 0 (0 new)` with nothing else printed.
for side in connector listener; do
  if grep -q 'equivocation recorded' "$D/$side.out"; then
    ok "the $side TELLS the operator it detected an equivocation"
  else
    bad "the $side detected a fork silently" "$(tail -2 "$D/$side.out" | tr '\n' ' ')"
  fi
done

if grep -q "equivocation recorded.*$NAME.*seq 0" "$D/connector.out"; then
  ok "and names the name and the seq, so the operator can act without a hex editor"
else
  bad "the line does not identify the fact" "$(grep -m1 'equivocation recorded' "$D/connector.out")"
fi

if grep -q 'nothing is penalised by it' "$D/connector.out"; then
  ok "and says what it does NOT mean, which REPLICATION.md 6.4 is specific about"
else
  bad "the report implies a penalty the protocol does not impose" "no 6.4 line"
fi

echo
echo "=== the ledger on disk agrees with what was printed ==="
for side in a b; do
  held=$("${VW[@]}" equivocations --log "$D/$side.log" 2>&1)
  case "$held" in
    *"$NAME"*detected*) ok "$side.log's ledger holds the report, marked as detected here" ;;
    *) bad "$side.log's ledger" "$(printf '%s' "$held" | head -2 | tr '\n' ' ')" ;;
  esac
done

# A second sync must not re-report a fact already settled: a line an operator sees every time they
# sync is a line they stop reading.
"${VW[@]}" sync --log "$D/a.log" --listen "$PORT" > "$D/listener2.out" 2>&1 &
LISTENER=$!
for _ in $(seq 1 30); do
  grep -q 'listening on' "$D/listener2.out" 2>/dev/null && break
  sleep 0.5
done
timeout 40 "${VW[@]}" sync --log "$D/b.log" --connect "127.0.0.1:$PORT" > "$D/connector2.out" 2>&1
kill "$LISTENER" 2>/dev/null
wait "$LISTENER" 2>/dev/null
LISTENER=
if grep -q 'equivocation recorded' "$D/connector2.out"; then
  bad "a settled fact is re-reported on every sync" "$(grep -m1 'equivocation recorded' "$D/connector2.out")"
else
  ok "a fact already settled is not reported again on the next sync"
fi

echo
echo "=== $pass passed, $fail failed ==="
[ "$fail" -eq 0 ]
