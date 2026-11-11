#!/usr/bin/env bash
# Copy the cipher directory by hand. The witness log stays behind.
set -euo pipefail

PYTHON="${PYTHON:-python3}"
ROOT=$(mktemp -d)
trap 'rm -rf "$ROOT"' EXIT

PW="$ROOT/password"
printf 'handcopy-secret' > "$PW"
CIPHER="$ROOT/cipher"
STATE="$ROOT/state"
WITNESS="$ROOT/witness"

export PEBBLE_CIPHER="$CIPHER"
export PEBBLE_STATE="$STATE"
export PEBBLE_WITNESS="$WITNESS"
export PEBBLE_PASSWORD_FILE="$PW"

pebble() {
  "$PYTHON" -m pebble "$@"
}

pebble init
printf 'hello-one' > "$ROOT/one.txt"
pebble put "$ROOT/one.txt" one.txt
pebble commit
pebble ls | grep -qx 'one.txt'

if grep -a -R -q -- 'hello-one' "$CIPHER/objects"; then
  echo "plaintext leaked into the cipher directory" >&2
  exit 1
fi

H1=$(tr -d '\n' < "$CIPHER/HEAD")
cp -a "$CIPHER" "$ROOT/snap"

names=$(PEBBLE_CIPHER="$ROOT/snap" pebble ls)
printf '%s\n' "$names" | grep -qx 'one.txt'
if printf '%s\n' "$names" | grep -qx 'two.txt'; then
  echo "copy already has the second file" >&2
  exit 1
fi

printf 'hello-two' > "$ROOT/two.txt"
pebble put "$ROOT/two.txt" two.txt
pebble commit
H2=$(tr -d '\n' < "$CIPHER/HEAD")
test "$H1" != "$H2"
pebble ls | grep -qx 'two.txt'

# A second device has seen only the copied folder. The full folder is an update.
STATE2="$ROOT/state2"
WIT2="$ROOT/witness2"
mkdir -p "$STATE2" "$WIT2"
: > "$WIT2/log"
PEBBLE_CIPHER="$ROOT/snap" PEBBLE_STATE="$STATE2" PEBBLE_WITNESS="$WIT2" \
  pebble status | grep -qx "update $H1"
PEBBLE_STATE="$STATE2" PEBBLE_WITNESS="$WIT2" pebble status | grep -qx "update $H2"

# Point HEAD backward. The witness still names the newer save.
cp -a "$CIPHER" "$ROOT/cipher-h2"
cp "$ROOT/snap/HEAD" "$CIPHER/HEAD"
test "$(tr -d '\n' < "$CIPHER/HEAD")" = "$H1"
set +e
REWIND=$(PEBBLE_STATE="$STATE2" PEBBLE_WITNESS="$WIT2" pebble status 2>&1)
CODE=$?
set -e
printf '%s\n' "$REWIND" >&2
test "$CODE" -eq 2
printf '%s\n' "$REWIND" | grep -qx "rewind $H2 $H1"

# Restore the newer folder, then plant a sibling the H2 device has not accepted.
rm -rf "$CIPHER"
cp -a "$ROOT/cipher-h2" "$CIPHER"
SIDE_STATE="$ROOT/side-state"
SIDE_WIT="$ROOT/side-witness"
mkdir -p "$SIDE_STATE" "$SIDE_WIT"
: > "$SIDE_WIT/log"
PEBBLE_CIPHER="$ROOT/snap" PEBBLE_STATE="$SIDE_STATE" PEBBLE_WITNESS="$SIDE_WIT" \
  pebble status | grep -qx "update $H1"
cp "$ROOT/snap/HEAD" "$CIPHER/HEAD"
printf 'hello-side' > "$ROOT/side.txt"
PEBBLE_STATE="$SIDE_STATE" PEBBLE_WITNESS="$SIDE_WIT" pebble put "$ROOT/side.txt" side.txt
PEBBLE_STATE="$SIDE_STATE" PEBBLE_WITNESS="$SIDE_WIT" pebble commit
H3=$(tr -d '\n' < "$CIPHER/HEAD")
test "$H3" != "$H1"
test "$H3" != "$H2"

set +e
SPLIT=$(pebble status 2>&1)
CODE=$?
set -e
printf '%s\n' "$SPLIT" >&2
test "$CODE" -eq 3
printf '%s\n' "$SPLIT" | head -n 1 | grep -qx "split $H2 $H3"
RECEIPT=$(printf '%s\n' "$SPLIT" | tail -n 1)
test -f "$RECEIPT"

EMPTY="$ROOT/empty"
mkdir "$EMPTY"
(
  cd "$EMPTY"
  unset PEBBLE_PASSWORD_FILE PEBBLE_CIPHER PEBBLE_STATE PEBBLE_WITNESS
  OUT=$("$PYTHON" -m pebble verify-proof "$RECEIPT")
  printf '%s\n' "$OUT" | grep -qx 'fork'
  printf '%s\n' "$OUT" | grep -qx "$H2"
  printf '%s\n' "$OUT" | grep -qx "$H3"
)

echo "handcopy ok"
