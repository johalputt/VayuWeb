#!/usr/bin/env bash
#
# Acceptance: the control API against a running resolver, over real sockets.
#
# Every assertion here is about what the process did on a wire — the control API over its Unix
# socket, the browsing proxy over loopback TCP. Nothing is stubbed and nothing is a unit test.
#
# **This script exists because it found something the unit tests could not.** `pinGated` was tested
# and correct, `PinSet` was tested and correct, `POST /v1/pin` was tested and correct — and unpin
# followed by re-pin left the site down, because the failure the re-pin should undo was cached
# against the content source. Each piece was green about itself; the sequence was not.
#
# The lesson it encodes: a control endpoint that changes what a resolver serves has to be checked
# by asking the resolver, in the order an operator would ask.
#
#     bash registry/scripts/acceptance-control-lifecycle.sh
#
# Exits non-zero on the first failing assertion group. Needs curl and nc. The registration is a
# real Argon2id solve, so it takes a minute.
set -u
cd "$(dirname "$0")/.."
D=$(mktemp -d)
VW=(node --experimental-strip-types bin/vayuweb-registry.ts)
NAME=atlasobservatory.vayu
AT=1782518400
pass=0; fail=0
ok()  { echo "  PASS  $1"; pass=$((pass+1)); }
bad() { echo "  FAIL  $1"; echo "        $2"; fail=$((fail+1)); }

mkdir -p "$D/site"
printf 'the atlas observatory' > "$D/site/index.html"

"${VW[@]}" keygen --key "$D/owner.key" >/dev/null 2>&1
echo "registering (real Argon2id solve)..."
"${VW[@]}" register --log "$D/log" --key "$D/owner.key" --name "$NAME" \
  --cid "$(node --experimental-strip-types -e '
import("./src/unixfs.ts").then(async (u) => {
  const c = await import("./src/content.ts");
  const built = u.importSite([{ path: "index.html", content: new TextEncoder().encode("the atlas observatory") }]);
  process.stdout.write(built.root);
});')" --at "$AT" >/dev/null 2>&1 || { echo "register failed"; exit 1; }

SOCK="$D/control.sock"
"${VW[@]}" serve --log "$D/log" --site "$D/site" --port "${VW_PORT:-7799}" --socket "$SOCK" > "$D/serve.out" 2>&1 &
SERVE_PID=$!
for _ in $(seq 1 40); do [ -S "$SOCK" ] && break; sleep 0.5; done
sleep 1

TOKEN=$(grep -A1 'control token' "$D/serve.out" | tail -1 | tr -d ' ')
ROOT=$(grep 'root CID' "$D/serve.out" | awk '{print $NF}')
echo "token=${TOKEN:0:12}...  root=${ROOT:0:16}..."

ctl() { # method path [body]
  local m=$1 p=$2 b=${3:-}
  if [ -n "$b" ]; then
    curl -sS --unix-socket "$SOCK" -X "$m" "http://localhost$p" \
      -H "x-vayuweb-control: 1" -H "authorization: Bearer $TOKEN" \
      -H 'content-type: application/json' --data-raw "$b" -w '\n%{http_code}'
  else
    curl -sS --unix-socket "$SOCK" -X "$m" "http://localhost$p" \
      -H "x-vayuweb-control: 1" -H "authorization: Bearer $TOKEN" -w '\n%{http_code}'
  fi
}
proxy() { curl -sS -o /dev/null -w '%{http_code}' -H "Host: $NAME" "http://127.0.0.1:${VW_PORT:-7799}/index.html"; }

echo; echo "=== the site is pinned because publishing it is pinning it ==="
R=$(ctl GET /v1/pins); case "$R" in *"$ROOT"*200) ok "GET /v1/pins reports the published root";; *) bad "GET /v1/pins" "$R";; esac

echo "=== the proxy serves it ==="
C=$(proxy); [ "$C" = 200 ] && ok "proxy 200 while pinned" || bad "proxy while pinned" "got $C"

echo; echo "=== DELETE /v1/pin/{cid} has teeth ==="
R=$(ctl DELETE "/v1/pin/$ROOT"); case "$R" in *'"unpinned":true'*200) ok "unpin reports true";; *) bad "unpin" "$R";; esac
C=$(proxy); [ "$C" != 200 ] && ok "proxy STOPS serving after unpin (got $C)" || bad "unpin has no teeth" "proxy still 200"
R=$(ctl GET /v1/pins); case "$R" in *'"pins":[]'*200) ok "GET /v1/pins is empty after unpin";; *) bad "pins after unpin" "$R";; esac

echo; echo "=== DELETE is idempotent; a bad CID is 400 not 404 ==="
R=$(ctl DELETE "/v1/pin/$ROOT"); case "$R" in *'"unpinned":false'*200) ok "second unpin is idempotent";; *) bad "idempotent unpin" "$R";; esac
R=$(ctl DELETE "/v1/pin/not-a-cid"); case "$R" in *bad_cid*400) ok "a non-CID path is 400 bad_cid";; *) bad "bad cid" "$R";; esac

echo; echo "=== POST /v1/pin refuses what the node does not hold, accepts what it does ==="
R=$(ctl POST /v1/pin '{"cid":"bafkreifzjut3te2nhyekklss27nh3k72ysco7y32koao5eei66wof36n5e"}')
case "$R" in *not_held*409) ok "a stranger CID is 409 not_held";; *) bad "not_held" "$R";; esac
R=$(ctl POST /v1/pin "{\"cid\":\"$ROOT\"}"); case "$R" in *'"outcome":"pinned"'*200) ok "re-pinning the held root succeeds";; *) bad "re-pin" "$R";; esac
C=$(proxy); [ "$C" = 200 ] && ok "proxy serves again after re-pin" || bad "re-pin has no effect" "got $C"

echo; echo "=== POST /v1/resolve, the body-carrying endpoint ==="
R=$(ctl POST /v1/resolve "{\"name\":\"$NAME\"}"); case "$R" in *"\"name\":\"$NAME\""*200) ok "POST /v1/resolve answers from a body";; *) bad "resolve body" "$R";; esac
R=$(ctl POST /v1/resolve '{"name":"../../etc/passwd"}'); case "$R" in *bad_name*400) ok "a traversal name is 400 bad_name";; *) bad "resolve traversal" "$R";; esac

echo; echo "=== the bounded body reader, on the wire ==="
R=$(printf 'POST /v1/resolve HTTP/1.1\r\nx-vayuweb-control: 1\r\nauthorization: Bearer %s\r\ncontent-length: 99999\r\n\r\n' "$TOKEN" | timeout 5 nc -U "$SOCK" | head -1)
case "$R" in *413*) ok "an oversized declared body is 413 from the head alone";; *) bad "413" "$R";; esac
R=$(printf 'POST /v1/resolve HTTP/1.1\r\nx-vayuweb-control: 1\r\ntransfer-encoding: chunked\r\n\r\n0\r\n\r\n' | timeout 5 nc -U "$SOCK" | head -1)
case "$R" in *400*) ok "chunked framing is 400";; *) bad "chunked" "$R";; esac
R=$(printf 'POST / HTTP/1.1\r\nHost: %s\r\ncontent-length: 5\r\n\r\nhello' "$NAME" | timeout 5 nc 127.0.0.1 "${VW_PORT:-7799}" | head -1)
case "$R" in *400*) ok "a body on the proxy is 400 UNEXPECTED_BODY";; *) bad "proxy body" "$R";; esac

echo; echo "=== PATCH /v1/config ==="
R=$(ctl PATCH /v1/config '{"cacheSizes":{"negativeEntries":16}}'); case "$R" in *'"negativeEntries":16'*200) ok "a cache size is set and read back";; *) bad "patch config" "$R";; esac
R=$(ctl PATCH /v1/config '{"mode":"tor"}'); case "$R" in *unsupported_field*400) ok "mode is REFUSED by name, not ignored";; *) bad "patch mode" "$R";; esac
R=$(ctl GET /v1/config); case "$R" in *redacted*) ok "GET /v1/config redacts the token";; *) bad "config redaction" "$R";; esac

echo; echo "=== POST /v1/token/rotate — the old token must die ==="
R=$(ctl POST /v1/token/rotate '{}'); NEW=$(printf '%s' "$R" | sed -n 's/.*"token":"\([A-Za-z0-9_-]*\)".*/\1/p')
[ -n "$NEW" ] && [ "$NEW" != "$TOKEN" ] && ok "rotate issues a different token" || bad "rotate" "$R"
R=$(ctl GET /v1/status); case "$R" in *401) ok "the OLD token is refused on the next request";; *) bad "old token still works" "$R";; esac
TOKEN=$NEW
R=$(ctl GET /v1/status); case "$R" in *200) ok "the NEW token works";; *) bad "new token" "$R";; esac
case "$R" in *0.2.1*) ok "the disclosed version matches the package";; *) bad "version" "$R";; esac

kill $SERVE_PID 2>/dev/null; wait $SERVE_PID 2>/dev/null
rm -rf "$D"
echo; echo "=== $pass passed, $fail failed ==="
exit $([ $fail -eq 0 ] && echo 0 || echo 1)
