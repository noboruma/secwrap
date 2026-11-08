#!/bin/bash
# End-to-end tests of secwrap, run as root inside the vmtest VM (run.sh).
# Usage: tests.sh SECWRAP_BINARY. Exits non-zero if any check fails.
set -u
SW=${1:?path to secwrap}
export HOME=/run/secwrap-home # /root is not readable through the share
mkdir -p "$HOME"
D=$(mktemp -d -p /run) U=swtest-$$ PORT=18080
pass=0 fail=0 SWPID= LPID=
ok() { echo "PASS  $*"; pass=$((pass + 1)); }
bad() { echo "FAIL  $*"; fail=$((fail + 1)); }
cg() { sed -n 's/^0:://p' /proc/$1/cgroup 2>/dev/null; }
conn_state() { sleep 2.5; tail -n1 $D/conn.log; }
# A shell loop that logs OK or BLOCKED for a loopback connect to file $1.
loop() {
	echo "while :; do if timeout 1 bash -c 'exec 3<>/dev/tcp/127.0.0.1/$PORT' 2>/dev/null; then echo OK; else echo BLOCKED; fi >> $1; sleep 0.5; done"
}
last() { sleep 2.5; tail -n1 $1; }
mainpid() { systemctl show -p MainPID --value $1; }
# stop_sw sends Ctrl-C to the running secwrap and waits for it.
stop_sw() {
	kill -INT $SWPID
	wait $SWPID 2>/dev/null
	SWPID=
}
cleanup() {
	kill $SWPID $LPID 2>/dev/null
	systemctl stop "$U*" 2>/dev/null
	systemctl reset-failed "$U*" 2>/dev/null
}
trap cleanup EXIT

python3 -m http.server $PORT --bind 127.0.0.1 >/dev/null 2>&1 &
LPID=$!
sleep 1

echo "== attach --net=deny to a process in a systemd unit with limits"
systemd-run -q --unit=$U -p MemoryMax=200M -p TasksMax=64 /bin/bash -c "
  sleep 600 &
  while :; do
    if timeout 1 bash -c 'exec 3<>/dev/tcp/127.0.0.1/$PORT' 2>/dev/null; then echo OK; else echo BLOCKED; fi >> $D/conn.log
    sleep 0.5
  done"
sleep 1.5
MAIN=$(systemctl show -p MainPID --value $U)
KID=$(pgrep -P $MAIN -x sleep | head -1)
UNITCG=$(cg $MAIN)
[ "$(conn_state)" = OK ] && ok "connects work before attach" || bad "connects before attach: $(tail -n1 $D/conn.log)"

$SW attach --net=deny --no-web --log off $MAIN >$D/attach.out 2>&1 &
SWPID=$!
sleep 3
WANT="$UNITCG/secwrap-deny-$SWPID"
[ "$(cg $MAIN)" = "$WANT" ] && ok "process moved to a child of its unit's cgroup" || bad "process cgroup is $(cg $MAIN), want $WANT"
[ "$(cg $KID)" = "$WANT" ] && ok "already-running child moved too" || bad "child cgroup is $(cg $KID), want $WANT"
[ "$(conn_state)" = BLOCKED ] && ok "connects blocked, from new children too" || bad "connects after attach: $(tail -n1 $D/conn.log)"
tasks=$(cat /sys/fs/cgroup$UNITCG/pids.current)
[ "$tasks" -gt 0 ] && ok "unit still accounts for them (pids.current=$tasks)" || bad "unit pids.current=$tasks"
systemctl is-active -q $U && ok "systemd still sees the unit as active" || bad "unit not active"
[ -z "$(ls -d /sys/fs/cgroup/secwrap-deny-* 2>/dev/null)" ] && ok "no deny cgroup at the root" || bad "deny cgroup at the root"

kill -INT $SWPID
wait $SWPID 2>/dev/null
SWPID=
[ "$(cg $MAIN)" = "$UNITCG" ] && ok "process back in its unit's cgroup after Ctrl-C" || bad "process cgroup after stop: $(cg $MAIN)"
[ "$(cg $KID)" = "$UNITCG" ] && ok "child back too" || bad "child cgroup after stop: $(cg $KID)"
[ ! -e "/sys/fs/cgroup$WANT" ] && ok "deny cgroup removed" || bad "$WANT still exists"
[ "$(conn_state)" = OK ] && ok "connects work again" || bad "connects after stop: $(tail -n1 $D/conn.log)"
systemctl stop $U

echo "== attach by thread id; the session ends when the process exits"
systemd-run -q --unit=$U-thr python3 -c 'import threading,time; threading.Thread(target=time.sleep,args=(600,)).start(); time.sleep(600)'
sleep 1.5
P=$(systemctl show -p MainPID --value $U-thr)
TID=$(ls /proc/$P/task | grep -vx $P | head -1)
timeout 20 $SW attach --net=log --no-web --log off $TID >$D/thread.out 2>&1 &
SWPID=$!
sleep 3
kill -9 $P
t0=$SECONDS
wait $SWPID
rc=$?
SWPID=
grep -q "attaching to \[$TID\]" $D/thread.out && [ $rc -eq 0 ] && [ $((SECONDS - t0)) -lt 5 ] &&
	ok "secwrap ended $((SECONDS - t0))s after the process died" ||
	bad "attach by thread id: rc=$rc after $((SECONDS - t0))s: $(tail -n3 $D/thread.out)"

echo "== one attach, processes in two cgroups"
systemd-run -q --unit=$U-multi /bin/bash -c "systemd-run -q --scope --unit=$U-sub sleep 600 & sleep 0.5; exec sleep 600"
sleep 2
MAIN=$(mainpid $U-multi)
SUB=$(pgrep -P $MAIN | head -1)
MAINCG=$(cg $MAIN) SUBCG=$(cg $SUB)
[ "$SUBCG" != "$MAINCG" ] && [ -n "$SUB" ] || bad "setup: child $SUB is in $SUBCG, parent in $MAINCG"
$SW attach --net=deny --no-web --log off $MAIN >$D/multi.out 2>&1 &
SWPID=$!
sleep 3
[ "$(cg $MAIN)" = "$MAINCG/secwrap-deny-$SWPID" ] && [ "$(cg $SUB)" = "$SUBCG/secwrap-deny-$SWPID" ] &&
	ok "each process moved under its own cgroup" || bad "cgroups: parent $(cg $MAIN), child $(cg $SUB)"
stop_sw
[ "$(cg $MAIN)" = "$MAINCG" ] && [ "$(cg $SUB)" = "$SUBCG" ] && ok "both back after Ctrl-C" ||
	bad "after stop: parent $(cg $MAIN), child $(cg $SUB)"
[ ! -e "/sys/fs/cgroup$MAINCG/secwrap-deny-$SWPID" ] && [ -z "$(ls -d /sys/fs/cgroup$SUBCG/secwrap-deny-* 2>/dev/null)" ] &&
	ok "both deny cgroups removed" || bad "deny cgroups left under $MAINCG or $SUBCG"
systemctl stop $U-multi $U-sub 2>/dev/null

echo "== attach --name"
cp /bin/sleep $D/swnamed
systemd-run -q --unit=$U-name $D/swnamed 600
sleep 1.5
P=$(mainpid $U-name) PCG=$(cg $P)
$SW attach --net=deny --no-web --log off --name swnamed >$D/name.out 2>&1 &
SWPID=$!
sleep 3
[ "$(cg $P)" = "$PCG/secwrap-deny-$SWPID" ] && ok "found by name and moved" || bad "by name: cgroup $(cg $P): $(tail -n3 $D/name.out)"
stop_sw
[ "$(cg $P)" = "$PCG" ] && ok "back after Ctrl-C" || bad "after stop: $(cg $P)"
systemctl stop $U-name

echo "== fallback to the root when the process's cgroup takes no child"
systemd-run -q --unit=$U-fb /bin/bash -c "$(loop $D/fb.log)"
sleep 1.5
P=$(mainpid $U-fb) PCG=$(cg $P)
echo 0 >/sys/fs/cgroup$PCG/cgroup.max.descendants
$SW attach --net=deny --no-web --log off $P >$D/fallback.out 2>&1 &
SWPID=$!
sleep 3
[ "$(cg $P)" = "/secwrap-deny-$SWPID" ] && ok "moved to the deny cgroup at the root" || bad "fallback: cgroup $(cg $P): $(tail -n3 $D/fallback.out)"
[ "$(last $D/fb.log)" = BLOCKED ] && ok "connects blocked there" || bad "fallback connects: $(tail -n1 $D/fb.log)"
stop_sw
[ "$(cg $P)" = "$PCG" ] && ok "back in its own cgroup after Ctrl-C" || bad "after stop: $(cg $P)"
[ ! -e "/sys/fs/cgroup/secwrap-deny-$SWPID" ] && ok "root deny cgroup removed" || bad "root deny cgroup left"
systemctl stop $U-fb

echo "== the leader thread exits first; the process is followed until its last thread"
systemd-run -q --unit=$U-leader python3 -c '
import ctypes, threading, time
threading.Thread(target=time.sleep, args=(10,)).start()
time.sleep(3)
ctypes.CDLL(None).pthread_exit(None)'
sleep 0.5
P=$(mainpid $U-leader)
t0=$SECONDS
timeout 30 $SW attach --net=log --no-web --log off $P >$D/leader.out 2>&1 &
SWPID=$!
sleep 6
state=$(sed -n 's/^State:\s*//p' /proc/$P/status)
case "$state" in Z*) ;; *) bad "setup: leader state is '$state', not a zombie" ;; esac
kill -0 $SWPID 2>/dev/null && ok "still attached after the leader exited" || bad "secwrap ended when the leader exited"
wait $SWPID
rc=$?
SWPID=
[ $rc -eq 0 ] && [ $((SECONDS - t0)) -ge 9 ] && ok "ended with the last thread ($((SECONDS - t0))s)" ||
	bad "leader test: rc=$rc after $((SECONDS - t0))s: $(tail -n3 $D/leader.out)"

echo "== the unit is stopped while attached"
systemd-run -q --unit=$U-stop /bin/bash -c "sleep 600 & $(loop $D/stop.log)"
sleep 1.5
P=$(mainpid $U-stop) PCG=$(cg $P)
timeout 30 $SW attach --net=deny --no-web --log off $P >$D/unitstop.out 2>&1 &
SWPID=$!
sleep 3
systemctl stop $U-stop
wait $SWPID
rc=$?
SWPID=
[ $rc -eq 0 ] && ok "secwrap ended with the unit" || bad "unit stop: secwrap rc=$rc: $(tail -n3 $D/unitstop.out)"
sleep 1
[ ! -e "/sys/fs/cgroup$PCG" ] && ok "the unit's cgroup is gone, deny cgroup included" || bad "left: $(find /sys/fs/cgroup$PCG -type d)"

echo "== launched command with --net=deny"
OWN=$(cg $$)
$SW monitor --net=deny --no-web --log off -- bash -c \
	"sed -n 's/^0:://p' /proc/self/cgroup; exec 3<>/dev/tcp/127.0.0.1/$PORT && echo OK || echo BLOCKED" >$D/cmd.out 2>&1
CMDCG=$(grep -m1 secwrap-deny $D/cmd.out)
case "$CMDCG" in
"$OWN"/secwrap-deny-*) ok "command ran in a child of secwrap's own cgroup" ;;
*) bad "command cgroup: '$CMDCG' (secwrap's: $OWN)" ;;
esac
grep -qx BLOCKED $D/cmd.out && ok "command's connect blocked" || bad "command output: $(tail -n3 $D/cmd.out)"

echo "== launched command with ask: its freeze cgroup"
# No exec and no network: nothing is asked, but the command still runs in
# the cgroup that would be frozen during a question.
timeout 30 $SW monitor --exec=ask --no-web --log off -- /bin/bash -c 'read l < /proc/self/cgroup; echo "CG=${l#0::}"' >$D/ask.out 2>&1
CMDCG=$(sed -n 's/^CG=//p' $D/ask.out)
case "$CMDCG" in
"$OWN"/secwrap-ask-*) ok "command ran in a child of secwrap's own cgroup" ;;
*) bad "ask command cgroup: '$CMDCG' (secwrap's: $OWN): $(tail -n3 $D/ask.out)" ;;
esac

echo "== other modes run and clean up"
for m in "--filesystem=log --exec=log" "--filesystem=deny --exec=deny --net=deny" \
	"--net=log --filesystem=log --exec=log --sbom $D/sbom"; do
	timeout 30 $SW monitor $m --no-web --log off -- /bin/sh -c 'ls / >/dev/null; cat /etc/hostname >/dev/null; true' >$D/mode.out 2>&1
	rc=$?
	if [ $rc -eq 0 ] && ! grep -qi 'panic\|goroutine' $D/mode.out; then
		ok "monitor $m"
	else
		bad "monitor $m: rc=$rc: $(tail -n3 $D/mode.out)"
	fi
done
left=$(find /sys/fs/cgroup -type d \( -name 'secwrap-deny-*' -o -name 'secwrap-ask-*' \) 2>/dev/null)
[ -z "$left" ] && ok "no secwrap cgroups left" || bad "leftover cgroups: $left"

if [ $fail -gt 0 ]; then
	for f in $D/*.out; do echo "--- $f"; tail -n 20 $f; done
fi
echo
echo "$pass passed, $fail failed"
[ $fail -eq 0 ]
