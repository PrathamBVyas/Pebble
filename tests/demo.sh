#!/usr/bin/env bash
# The six beats. Nothing else.
set -euo pipefail

PYTHON="${PYTHON:-python3}"
ROOT=$(mktemp -d)
trap 'fusermount3 -u "$ROOT/mnt" 2>/dev/null || true; rm -rf "$ROOT"' EXIT

PW="$ROOT/alice.pw"
BOB_PW="$ROOT/bob.pw"
printf 'alice-demo' > "$PW"
printf 'bob-demo' > "$BOB_PW"
CIPHER="$ROOT/cipher"
STATE="$ROOT/state"
WITNESS="$ROOT/witness"
STATE2="$ROOT/state2"
WIT2="$ROOT/witness2"
mkdir -p "$STATE2" "$WIT2"
: > "$WIT2/log"

export PEBBLE_CIPHER="$CIPHER"
export PEBBLE_STATE="$STATE"
export PEBBLE_WITNESS="$WITNESS"
export PEBBLE_PASSWORD_FILE="$PW"

pebble() { "$PYTHON" -m pebble "$@"; }

# 1. Unlock, write, show ciphertext.
pebble init
printf 'beat-one-plaintext' > "$ROOT/note.txt"
pebble put "$ROOT/note.txt" note.txt
pebble commit
if grep -a -R -q -- 'beat-one-plaintext' "$CIPHER/objects"; then
  echo "plaintext was stored" >&2
  exit 1
fi
OBJ=$(find "$CIPHER/objects" -type f | head -n 1)
echo "ciphertext $(od -An -tx1 -N 8 "$OBJ" | tr -s ' ')"

# 2. Second device fast-forwards.
H1=$(tr -d '\n' < "$CIPHER/HEAD")
cp -a "$CIPHER" "$ROOT/snap"
printf 'second' > "$ROOT/two.txt"
pebble put "$ROOT/two.txt" two.txt
pebble commit
H2=$(tr -d '\n' < "$CIPHER/HEAD")
cp -a "$CIPHER" "$ROOT/cipher-h2"
PEBBLE_CIPHER="$ROOT/snap" PEBBLE_STATE="$STATE2" PEBBLE_WITNESS="$WIT2" \
  pebble status | grep -qx "update $H1"
PEBBLE_STATE="$STATE2" PEBBLE_WITNESS="$WIT2" pebble status | grep -qx "update $H2"
echo "fast-forward $H2"

# 3. Put yesterday's directory back: open refused.
set +e
YESTERDAY=$(PEBBLE_CIPHER="$ROOT/snap" PEBBLE_STATE="$STATE2" PEBBLE_WITNESS="$WIT2" pebble status 2>&1)
CODE=$?
set -e
test "$CODE" -ne 0
printf '%s\n' "$YESTERDAY" >&2
echo "open refused"

# 4. Sibling history: read-only, receipt verifies without the password.
SIDE="$ROOT/side"
cp -a "$ROOT/cipher-h2" "$SIDE"
cp "$ROOT/snap/HEAD" "$SIDE/HEAD"
SIDE_STATE="$ROOT/side-state"
SIDE_WIT="$ROOT/side-witness"
mkdir -p "$SIDE_STATE" "$SIDE_WIT"
: > "$SIDE_WIT/log"
PEBBLE_CIPHER="$ROOT/snap" PEBBLE_STATE="$SIDE_STATE" PEBBLE_WITNESS="$SIDE_WIT" \
  pebble status >/dev/null
printf 'sibling' > "$ROOT/side.txt"
PEBBLE_CIPHER="$SIDE" PEBBLE_STATE="$SIDE_STATE" PEBBLE_WITNESS="$SIDE_WIT" \
  pebble put "$ROOT/side.txt" side.txt
PEBBLE_CIPHER="$SIDE" PEBBLE_STATE="$SIDE_STATE" PEBBLE_WITNESS="$SIDE_WIT" pebble commit >/dev/null
H3=$(tr -d '\n' < "$SIDE/HEAD")
set +e
SPLIT=$(PEBBLE_CIPHER="$SIDE" PEBBLE_STATE="$STATE2" PEBBLE_WITNESS="$WIT2" pebble status 2>&1)
CODE=$?
set -e
test "$CODE" -eq 3
RECEIPT=$(printf '%s\n' "$SPLIT" | tail -n 1)
EMPTY="$ROOT/empty"
mkdir "$EMPTY"
(
  cd "$EMPTY"
  unset PEBBLE_PASSWORD_FILE PEBBLE_CIPHER PEBBLE_STATE PEBBLE_WITNESS
  OUT=$("$PYTHON" -m pebble verify-proof "$RECEIPT")
  printf '%s\n' "$OUT" | grep -qx fork
  printf '%s\n' "$OUT" | grep -qx "$H2"
  printf '%s\n' "$OUT" | grep -qx "$H3"
)
echo "receipt"

# 5. Remove the new save from the folder, leave the witness note.
HIDDEN="$ROOT/hidden"
cp -a "$ROOT/cipher-h2" "$HIDDEN"
cp "$ROOT/snap/HEAD" "$HIDDEN/HEAD"
test "$(tr -d '\n' < "$HIDDEN/HEAD")" = "$H1"
WIT_BEFORE=$(wc -c < "$WIT2/log")
set +e
NAMED=$(PEBBLE_CIPHER="$HIDDEN" PEBBLE_STATE="$STATE2" PEBBLE_WITNESS="$WIT2" pebble status 2>&1)
CODE=$?
set -e
test "$CODE" -eq 2
printf '%s\n' "$NAMED" | grep -qx "rewind $H2 $H1"
test "$(wc -c < "$WIT2/log")" -ge "$WIT_BEFORE"
echo "hidden $H2"

# 6. Share one folder, not the vault. Revoke, write, restore the old grant list.
printf 'old-file' > "$ROOT/old.txt"
printf 'vault-secret' > "$ROOT/secret.txt"
pebble put "$ROOT/secret.txt" private/secret.txt
pebble put "$ROOT/old.txt" shared/old.txt
pebble commit >/dev/null
"$PYTHON" -m pebble keygen --password-file "$BOB_PW" --keybag "$ROOT/bob.keybag" --public "$ROOT/bob.pub"
pebble add-user --name bob --keybag "$ROOT/bob.keybag" --public "$ROOT/bob.pub"
SHARE=$(pebble share shared bob)
printf 'new-file' > "$ROOT/new.txt"
pebble revoke shared bob >/dev/null
pebble put "$ROOT/new.txt" shared/new.txt
pebble commit >/dev/null

MNT="$ROOT/mnt"
mkdir -p "$MNT"
BOB_STATE="$ROOT/bob-state"
BOB_WIT="$ROOT/bob-witness"
mkdir -p "$BOB_STATE" "$BOB_WIT"
: > "$BOB_WIT/log"
PEBBLE_STATE="$BOB_STATE" PEBBLE_WITNESS="$BOB_WIT" PEBBLE_PASSWORD_FILE="$BOB_PW" \
  pebble mount "$MNT" --keybag "$CIPHER/keybags/bob" >/tmp/pebble-demo-mount.log 2>&1 &
MOUNT_PID=$!
for _ in $(seq 1 50); do
  if [ -f "$MNT/shared/old.txt" ]; then
    break
  fi
  if ! kill -0 "$MOUNT_PID" 2>/dev/null; then
    cat /tmp/pebble-demo-mount.log >&2
    exit 1
  fi
  sleep 0.1
done
test "$(cat "$MNT/shared/old.txt")" = "old-file"
if [ -e "$MNT/shared/new.txt" ] || [ -e "$MNT/private" ]; then
  echo "bob saw a folder he was not granted" >&2
  exit 1
fi
echo "old file opens"
echo "new file rejected"
echo "unshared folder never did"
fusermount3 -u "$MNT"
wait "$MOUNT_PID"

PLANT=$(dirname "$0")/plant_old_grant.py
PEBBLE_PASSWORD_FILE="$PW" "$PYTHON" "$PLANT" "$SHARE" >/dev/null
set +e
RESTORED=$(pebble status 2>&1)
CODE=$?
set -e
test "$CODE" -eq 4
printf '%s\n' "$RESTORED" | grep -qx "grant history is not valid"
echo "restored grant list refused"
