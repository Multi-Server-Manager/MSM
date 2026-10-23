#!/usr/bin/env bash
#
# End-to-end checks for the pairing channel and the command surface.
#
# Run this inside a container that has both binaries; never on a host directly.
# The values below are the ones the containers in the build notes use.
#
#   NODE_BIN=/opt/msm/bin/msm-node CLIENT_BIN=/opt/msm/bin/msm ./e2e.sh
#
# Set E2E_PACKAGE to a real package name to also run one real install.
#
# Every scenario starts its own node on random ports with a throwaway state
# directory, so the script is safe to re-run and cannot disturb a real node.

set -uo pipefail

NODE_BIN="${NODE_BIN:-/opt/msm/bin/msm-node}"
CLIENT_BIN="${CLIENT_BIN:-/opt/msm/bin/msm}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROBE="${PROBE:-${SCRIPT_DIR}/probe.py}"
OP_PROBE="${OP_PROBE:-${SCRIPT_DIR}/op_probe.py}"
WORK="${WORK:-/tmp/msm-e2e}"
DIAL_HOST="${DIAL_HOST:-127.0.0.1}"

PASS=0
FAIL=0

ok() { PASS=$((PASS + 1)); printf 'ok   %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$1"; }

check() { # name actual expected
    if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (want $3, got $2)"; fi
}

has() { # name file pattern
    if grep -q -- "$3" "$2" 2>/dev/null; then ok "$1"; else bad "$1"; fi
}

hasnt() { # name file pattern
    if grep -q -- "$3" "$2" 2>/dev/null; then bad "$1"; else ok "$1"; fi
}

rm -rf "$WORK"
mkdir -p "$WORK"

# ---------------------------------------------------------------- helpers ----

node_start() { # dir [extra args...]
    local dir="$1"
    shift
    mkdir -p "$dir"
    "$NODE_BIN" --state-dir "$dir/state" \
        --op-listen "0.0.0.0:0" \
        --pair-listen "0.0.0.0:0" \
        --advertise-host "$DIAL_HOST" \
        "$@" >"$dir/node.log" 2>&1 &
    echo $! >"$dir/node.pid"
    local _
    for _ in $(seq 1 100); do
        grep -q '^PAIR code=' "$dir/node.log" 2>/dev/null && return 0
        sleep 0.1
    done
    return 1
}

node_stop() { # dir
    local dir="$1" pid
    [ -f "$dir/node.pid" ] || return 0
    pid="$(cat "$dir/node.pid")"
    kill "$pid" 2>/dev/null
    wait "$pid" 2>/dev/null
    return 0
}

attr() { # log key
    awk -v prefix="$2=" '
        /^PAIR / { for (i = 1; i <= NF; i++) if (index($i, prefix) == 1) value = substr($i, length(prefix) + 1) }
        END { print value }
    ' "$1"
}

flip() { # code -> a different code
    local flipped
    flipped="$(printf '%s' "$1" | sed 's/.$/Z/')"
    [ "$flipped" = "$1" ] && flipped="00000000"
    printf '%s' "$flipped"
}

pair() { # state-dir addr code label
    "$CLIENT_BIN" --state-dir "$1" pair --addr "$2" --code "$3" --label "$4" 2>&1
}

port_open() { # host port
    (exec 3<>"/dev/tcp/$1/$2") 2>/dev/null && { exec 3<&-; return 0; }
    return 1
}

# -------------------------------------------------------------- scenarios ----

t1_pair_success() {
    local dir="$WORK/t1"
    node_start "$dir" || { bad "t1 node started"; return; }

    local code addr out rc
    code="$(attr "$dir/node.log" code)"
    addr="$(attr "$dir/node.log" addr)"
    if [ -z "$code" ] || [ -z "$addr" ]; then
        bad "t1 node printed code and address"
        node_stop "$dir"
        return
    fi
    check "t1 code length" "${#code}" "8"

    out="$(pair "$dir/client" "$addr" "$code" "node-one")"
    rc=$?
    check "t1 client exit status" "$rc" "0"
    case "$out" in
    *PAIRED*) ok "t1 client reported PAIRED" ;;
    *) bad "t1 client output: $out" ;;
    esac

    [ -f "$dir/client/nodes.json" ] && ok "t1 pin file written" || bad "t1 pin file written"
    has "t1 label stored" "$dir/client/nodes.json" '"label": "node-one"'
    has "t1 pin stored" "$dir/client/nodes.json" '"spki"'

    sleep 0.3
    has "t1 node recorded the pairing" "$dir/node.log" "^PAIRED "
    has "t1 node closed the pairing listener" "$dir/node.log" "PAIRING closed"

    if port_open "${addr%:*}" "${addr##*:}"; then
        bad "t1 pairing port is closed"
    else
        ok "t1 pairing port is closed"
    fi

    node_stop "$dir"
}

t2_wrong_code() {
    local dir="$WORK/t2"
    node_start "$dir" || { bad "t2 node started"; return; }

    local code addr out rc
    code="$(attr "$dir/node.log" code)"
    addr="$(attr "$dir/node.log" addr)"

    out="$(pair "$dir/client" "$addr" "$(flip "$code")" "intruder")"
    rc=$?
    [ "$rc" -ne 0 ] && ok "t2 wrong code rejected" || bad "t2 wrong code rejected"
    case "$out" in
    *bad_proof*) ok "t2 error is bad_proof" ;;
    *) bad "t2 error is bad_proof: $out" ;;
    esac

    hasnt "t2 node did not pair" "$dir/node.log" "^PAIRED "
    [ -f "$dir/client/nodes.json" ] && bad "t2 no pin written" || ok "t2 no pin written"

    # The code is still valid after a single failure.
    out="$(pair "$dir/client-retry" "$addr" "$code" "node-two")"
    rc=$?
    check "t2 correct code still works" "$rc" "0"

    node_stop "$dir"
}

t3_attempt_budget() {
    local dir="$WORK/t3"
    node_start "$dir" --pairing-attempts 3 || { bad "t3 node started"; return; }

    local code addr first i out
    code="$(attr "$dir/node.log" code)"
    addr="$(attr "$dir/node.log" addr)"
    first="$code"

    : >"$dir/attempts.txt"
    for i in 1 2 3; do
        out="$(pair "$dir/client$i" "$addr" "$(flip "$code")" "intruder")"
        printf '%s\n' "$out" >>"$dir/attempts.txt"
    done

    has "t3 first failure is bad_proof" "$dir/attempts.txt" "bad_proof"
    if sed -n '3p' "$dir/attempts.txt" | grep -q "abuse"; then
        ok "t3 third failure is abuse"
    else
        bad "t3 third failure is abuse"
    fi
    has "t3 node rotated the code" "$dir/node.log" "rotated=abuse"

    local second
    second="$(attr "$dir/node.log" code)"
    [ "$second" != "$first" ] && ok "t3 new code differs" || bad "t3 new code differs"

    node_stop "$dir"
}

t4_expiry() {
    local dir="$WORK/t4"
    node_start "$dir" --pairing-ttl 1s || { bad "t4 node started"; return; }

    local code addr out rc
    code="$(attr "$dir/node.log" code)"
    addr="$(attr "$dir/node.log" addr)"
    sleep 2

    out="$(pair "$dir/client" "$addr" "$code" "late")"
    rc=$?
    [ "$rc" -ne 0 ] && ok "t4 expired code rejected" || bad "t4 expired code rejected"
    case "$out" in
    *expired*) ok "t4 error is expired" ;;
    *) bad "t4 error is expired: $out" ;;
    esac
    has "t4 node rotated the expired code" "$dir/node.log" "rotated=expired"

    node_stop "$dir"
}

t5_code_burned() {
    local dir="$WORK/t5"
    node_start "$dir" || { bad "t5 node started"; return; }

    local code addr out rc
    code="$(attr "$dir/node.log" code)"
    addr="$(attr "$dir/node.log" addr)"

    out="$(pair "$dir/client" "$addr" "$code" "node-five")"
    rc=$?
    check "t5 first pairing succeeds" "$rc" "0"
    sleep 0.3

    out="$(pair "$dir/client-b" "$addr" "$code" "node-five-again")"
    rc=$?
    [ "$rc" -ne 0 ] && ok "t5 burned code refused" || bad "t5 burned code refused"

    local count
    count="$(grep -c '^PAIRED ' "$dir/node.log")"
    check "t5 exactly one pairing recorded" "$count" "1"

    node_stop "$dir"
}

t6_operational_pin() {
    local dir="$WORK/t6"
    node_start "$dir" || { bad "t6 node started"; return; }

    local code addr out rc
    code="$(attr "$dir/node.log" code)"
    addr="$(attr "$dir/node.log" addr)"
    pair "$dir/client" "$addr" "$code" "node-six" >/dev/null
    rc=$?
    if [ "$rc" -ne 0 ]; then
        bad "t6 setup pairing"
        node_stop "$dir"
        return
    fi

    out="$("$CLIENT_BIN" --state-dir "$dir/client" info node-six 2>&1)"
    rc=$?
    check "t6 info exit status" "$rc" "0"
    case "$out" in
    *pinned_clients=1*) ok "t6 node reports one pinned console" ;;
    *) bad "t6 node reports one pinned console: $out" ;;
    esac
    case "$out" in
    *hostname=*) ok "t6 node reports its hostname" ;;
    *) bad "t6 node reports its hostname" ;;
    esac

    # Replace the pin with a different valid Ed25519 SPKI: the channel must fail.
    cp "$dir/client/nodes.json" "$dir/nodes.backup.json"
    local bogus
    bogus="$(head -c 44 /dev/zero | base64 -w0)"
    sed -i "s|\"spki\": \"[^\"]*\"|\"spki\": \"$bogus\"|" "$dir/client/nodes.json"

    out="$("$CLIENT_BIN" --state-dir "$dir/client" info node-six 2>&1)"
    rc=$?
    [ "$rc" -ne 0 ] && ok "t6 wrong pin refused" || bad "t6 wrong pin refused"
    case "$out" in
    *hostname=*) bad "t6 wrong pin leaked node info" ;;
    *) ok "t6 wrong pin leaked no node info" ;;
    esac

    node_stop "$dir"
}

t7_unpinned_console() {
    local dir="$WORK/t7"
    node_start "$dir" || { bad "t7 node started"; return; }

    local code addr rc
    code="$(attr "$dir/node.log" code)"
    addr="$(attr "$dir/node.log" addr)"
    pair "$dir/owner" "$addr" "$code" "node-seven" >/dev/null
    rc=$?
    if [ "$rc" -ne 0 ]; then
        bad "t7 setup pairing"
        node_stop "$dir"
        return
    fi

    # A fresh identity that copied the pin file: authentication must still fail.
    mkdir -p "$dir/stranger"
    cp "$dir/owner/nodes.json" "$dir/stranger/nodes.json"

    local out
    out="$("$CLIENT_BIN" --state-dir "$dir/stranger" info node-seven 2>&1)"
    rc=$?
    [ "$rc" -ne 0 ] && ok "t7 unpaired console refused" || bad "t7 unpaired console refused"
    case "$out" in
    *unauthorized*) ok "t7 node error is unauthorized" ;;
    *) bad "t7 node error is unauthorized: $out" ;;
    esac

    node_stop "$dir"
}

t8_frame_probes() {
    local dir="$WORK/t8"
    node_start "$dir" || { bad "t8 node started"; return; }

    local addr host port code out rc
    addr="$(attr "$dir/node.log" addr)"
    code="$(attr "$dir/node.log" code)"
    host="${addr%:*}"
    port="${addr##*:}"

    check "t8 unknown type" "$(python3 "$PROBE" unknown "$host" "$port")" "error unknown_type"
    check "t8 oversized frame" "$(python3 "$PROBE" oversize "$host" "$port")" "error bad_frame"
    check "t8 zero-length frame" "$(python3 "$PROBE" empty "$host" "$port")" "error bad_frame"

    # Bad frames must not consume the attempt budget or kill the listener.
    out="$(pair "$dir/client" "$addr" "$code" "after-probes")"
    rc=$?
    check "t8 pairing still works after bad frames" "$rc" "0"

    node_stop "$dir"
}

t9_commands() {
    local dir="$WORK/t9"
    node_start "$dir" || { bad "t9 node started"; return; }

    local code addr out rc
    code="$(attr "$dir/node.log" code)"
    addr="$(attr "$dir/node.log" addr)"
    pair "$dir/client" "$addr" "$code" "cmd-node" >/dev/null
    rc=$?
    if [ "$rc" -ne 0 ]; then
        bad "t9 setup pairing"
        node_stop "$dir"
        return
    fi

    out="$("$CLIENT_BIN" --state-dir "$dir/client" metrics --node cmd-node --json 2>&1)"
    rc=$?
    check "t9 metrics exit status" "$rc" "0"
    case "$out" in
    *'"ok":true'*cpu_count*) ok "t9 metrics payload" ;;
    *) bad "t9 metrics payload: $out" ;;
    esac

    out="$("$CLIENT_BIN" --state-dir "$dir/client" logs 3 --node cmd-node 2>&1)"
    rc=$?
    check "t9 logs exit status" "$rc" "0"
    case "$out" in
    *lines=*) ok "t9 bounded log tail" ;;
    *) bad "t9 bounded log tail: $out" ;;
    esac

    out="$("$CLIENT_BIN" --state-dir "$dir/client" logs 501 --node cmd-node 2>&1)"
    rc=$?
    [ "$rc" -ne 0 ] && ok "t9 oversized logs.tail refused" || bad "t9 oversized logs.tail refused"
    case "$out" in
    *bad_argument*) ok "t9 oversized logs.tail is bad_argument" ;;
    *) bad "t9 oversized logs.tail is bad_argument: $out" ;;
    esac

    out="$("$CLIENT_BIN" --state-dir "$dir/client" install 'a;rm -rf /' --node cmd-node 2>&1)"
    rc=$?
    [ "$rc" -ne 0 ] && ok "t9 shell metacharacters refused" || bad "t9 shell metacharacters refused"
    case "$out" in
    *bad_argument*) ok "t9 package refusal is bad_argument" ;;
    *) bad "t9 package refusal is bad_argument: $out" ;;
    esac

    out="$("$CLIENT_BIN" --state-dir "$dir/client" install '..' --node cmd-node 2>&1)"
    rc=$?
    [ "$rc" -ne 0 ] && ok "t9 leading-dot package refused" || bad "t9 leading-dot package refused"

    out="$("$CLIENT_BIN" --state-dir "$dir/client" reboot --node cmd-node 2>&1)"
    rc=$?
    [ "$rc" -ne 0 ] && ok "t9 reboot without confirm refused" || bad "t9 reboot without confirm refused"
    case "$out" in
    *confirmation_required*) ok "t9 reboot refusal is confirmation_required" ;;
    *) bad "t9 reboot refusal is confirmation_required: $out" ;;
    esac

    if [ -n "${E2E_PACKAGE:-}" ]; then
        out="$("$CLIENT_BIN" --state-dir "$dir/client" install "$E2E_PACKAGE" --node cmd-node 2>&1)"
        rc=$?
        check "t9 real install exit status" "$rc" "0"
        case "$out" in
        *manager=*) ok "t9 real install reported a manager" ;;
        *) bad "t9 real install reported a manager: $out" ;;
        esac
    fi

    node_stop "$dir"
}

t10_fanout() {
    local dir="$WORK/t10"
    node_start "$dir/a" || { bad "t10 first node started"; return; }
    node_start "$dir/b" || { bad "t10 second node started"; node_stop "$dir/a"; return; }

    local code addr out rc
    code="$(attr "$dir/a/node.log" code)"
    addr="$(attr "$dir/a/node.log" addr)"
    pair "$dir/client" "$addr" "$code" "alpha" >/dev/null
    code="$(attr "$dir/b/node.log" code)"
    addr="$(attr "$dir/b/node.log" addr)"
    pair "$dir/client" "$addr" "$code" "beta" >/dev/null

    out="$("$CLIENT_BIN" --state-dir "$dir/client" metrics --all 2>&1)"
    rc=$?
    check "t10 fan-out exit status" "$rc" "0"
    case "$out" in
    *"2 nodes: 2 ok, 0 failed"*) ok "t10 fan-out summary" ;;
    *) bad "t10 fan-out summary: $out" ;;
    esac
    case "$out" in
    *alpha*) ok "t10 first node reported" ;;
    *) bad "t10 first node reported" ;;
    esac
    case "$out" in
    *beta*) ok "t10 second node reported" ;;
    *) bad "t10 second node reported" ;;
    esac

    out="$("$CLIENT_BIN" --state-dir "$dir/client" logs 900 --all 2>&1)"
    rc=$?
    [ "$rc" -ne 0 ] && ok "t10 fan-out exit status reports a refusal" || bad "t10 fan-out exit status reports a refusal"
    case "$out" in
    *"2 nodes: 0 ok, 2 failed"*) ok "t10 refusal summary" ;;
    *) bad "t10 refusal summary: $out" ;;
    esac

    node_stop "$dir/a"
    node_stop "$dir/b"
}

t11_unknown_type() {
    local dir="$WORK/t11"
    node_start "$dir" || { bad "t11 node started"; return; }

    if ! command -v python3 >/dev/null || ! command -v openssl >/dev/null; then
        printf 'skip t11: python3 and openssl are needed\n'
        node_stop "$dir"
        return
    fi

    local code addr out rc port
    code="$(attr "$dir/node.log" code)"
    addr="$(attr "$dir/node.log" addr)"
    pair "$dir/client" "$addr" "$code" "probe-node" >/dev/null
    rc=$?
    if [ "$rc" -ne 0 ]; then
        bad "t11 setup pairing"
        node_stop "$dir"
        return
    fi

    port="$(sed -n 's/.*"op_port": \([0-9][0-9]*\).*/\1/p' "$dir/client/nodes.json")"
    out="$(python3 "$OP_PROBE" --addr "${DIAL_HOST}:${port}" \
        --identity "$dir/client/identity.json" \
        --json '{"t":"pkg.nuke","v":1,"id":"probe-1"}' 2>&1)"
    case "$out" in
    *unknown_type*) ok "t11 unknown command refused" ;;
    *) bad "t11 unknown command refused: $out" ;;
    esac

    # A fresh identity is what an unpaired console looks like on the wire.
    out="$(python3 "$OP_PROBE" --addr "${DIAL_HOST}:${port}" --fresh \
        --json '{"t":"metrics.sample","v":1,"id":"probe-2"}' 2>&1)"
    case "$out" in
    *unauthorized*) ok "t11 unpaired identity refused" ;;
    *) bad "t11 unpaired identity refused: $out" ;;
    esac

    node_stop "$dir"
}

t13_tailnet_discovery() {
    local dir="$WORK/t13"
    # The pairing port and the probe port are the same contract value; the port
    # is random here so the suite can run on a busy host.
    local pair_port=$((20000 + RANDOM % 20000))
    node_start "$dir" --pair-listen "0.0.0.0:${pair_port}" \
        || { bad "t13 node started"; return; }

    if ! port_open "$DIAL_HOST" "$pair_port"; then
        bad "t13 pairing port is listening"
        node_stop "$dir"
        return
    fi

    # A stub tailscale: one online peer, one offline. The online peer is the
    # node itself on loopback, standing in for its 100.x address.
    mkdir -p "$dir/bin"
    cat >"$dir/bin/tailscale" <<EOF
#!/bin/sh
[ "\$1" = status ] || exit 1
cat <<'JSON'
{"Peer":{
  "k1":{"HostName":"tailbox","Online":true,"TailscaleIPs":["${DIAL_HOST}"]},
  "k2":{"HostName":"offline-box","Online":false,"TailscaleIPs":["127.0.0.2"]}}}
JSON
EOF
    chmod +x "$dir/bin/tailscale"

    local id out lines
    id="$(sed -n 's/^MSM-NODE id=\([^ ]*\).*/\1/p' "$dir/node.log")"
    out="$(MSM_TAILSCALE="$dir/bin/tailscale" MSM_TAILNET_PORT="$pair_port" \
        "$CLIENT_BIN" --state-dir "$dir/client" discover --tailnet-only 2>&1)"
    case "$out" in
    *tailbox*) ok "t13 tailnet lists an online peer" ;;
    *) bad "t13 tailnet lists an online peer: $out" ;;
    esac
    case "$out" in
    *"$id"*) ok "t13 the probe returned the node id" ;;
    *) bad "t13 the probe returned the node id: $out" ;;
    esac
    lines="$(printf '%s\n' "$out" | grep -c 'tailbox')"
    check "t13 offline peers are skipped" "$lines" "1"

    # Pairing over the discovered endpoint, then the stale-port regression:
    # the pairing listener closes and the node must advertise the op port.
    local addr code
    addr="$(printf '%s\n' "$out" | awk '/tailbox/ {print $2}')"
    code="$(attr "$dir/node.log" code)"
    out="$(pair "$dir/client" "$addr" "$code" "tailbox")"
    case "$out" in
    *PAIRED*) ok "t13 pairing over the tailnet endpoint" ;;
    *) bad "t13 pairing over the tailnet endpoint: $out" ;;
    esac
    sleep 0.3
    if port_open "$DIAL_HOST" "$pair_port"; then
        bad "t13 pairing port closed after pairing"
    else
        ok "t13 pairing port closed after pairing"
    fi
    local op_port
    op_port="$(sed -n 's/^LISTEN addr=.*:\([0-9][0-9]*\)$/\1/p' "$dir/node.log")"
    has "t13 node re-advertises the operational port" "$dir/node.log" "MDNS service=.* port=${op_port}$"

    node_stop "$dir"
}

t12_self_restart() {
    local dir="$WORK/t12"
    # A fixed port: the arg is reused on re-exec, so an ephemeral port would move.
    local port=$((20000 + RANDOM % 20000))
    node_start "$dir" --op-listen "0.0.0.0:${port}" \
        || { bad "t12 node started"; return; }

    local code addr out rc
    code="$(attr "$dir/node.log" code)"
    addr="$(attr "$dir/node.log" addr)"
    pair "$dir/client" "$addr" "$code" "restart-node" >/dev/null
    rc=$?
    if [ "$rc" -ne 0 ]; then
        bad "t12 setup pairing"
        node_stop "$dir"
        return
    fi

    out="$("$CLIENT_BIN" --state-dir "$dir/client" restart --node restart-node 2>&1)"
    rc=$?
    check "t12 restart exit status" "$rc" "0"
    case "$out" in
    *method=exec*) ok "t12 restart used exec" ;;
    *) bad "t12 restart used exec: $out" ;;
    esac

    sleep 1
    out="$("$CLIENT_BIN" --state-dir "$dir/client" metrics --node restart-node 2>&1)"
    rc=$?
    check "t12 node answers after restarting" "$rc" "0"
    has "t12 node logged the re-exec" "$dir/node.log" "RESTART exec="
    local banners
    banners="$(grep -c '^MSM-NODE id=' "$dir/node.log")"
    check "t12 node started twice" "$banners" "2"

    node_stop "$dir"
}

# -------------------------------------------------------------------- main ----

t1_pair_success
t2_wrong_code
t3_attempt_budget
t4_expiry
t5_code_burned
t6_operational_pin
t7_unpinned_console
t8_frame_probes
t9_commands
t10_fanout
t11_unknown_type
t12_self_restart
t13_tailnet_discovery

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
