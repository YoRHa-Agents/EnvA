#!/usr/bin/env bash
# test-macos.sh — End-to-end verification of Enva on macOS aarch64.
# Idempotent: uses a temp directory, cleans up on exit.
# Usage: ./test-macos.sh [/path/to/enva-binary]

set -uo pipefail

ENVA="${1:-./release/enva-macos-aarch64}"
PW="test_pass_42"
PASS_COUNT=0
FAIL_COUNT=0
RESULTS=()

cleanup() {
    [ -d "${TEST_DIR:-}" ] && rm -rf "$TEST_DIR"
    [ -d "$HOME/.enva.test-backup" ] && {
        rm -rf "$HOME/.enva" 2>/dev/null
        mv "$HOME/.enva.test-backup" "$HOME/.enva"
    }
}
trap cleanup EXIT

assert() {
    local name="$1" condition="$2"
    if eval "$condition"; then
        PASS_COUNT=$((PASS_COUNT + 1))
        RESULTS+=("PASS|$name")
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        RESULTS+=("FAIL|$name")
    fi
}

TEST_DIR=$(mktemp -d)
VP="$TEST_DIR/test.vault.json"

if [ ! -x "$ENVA" ]; then
    echo "ERROR: binary not found or not executable: $ENVA"
    exit 2
fi

echo "Enva macOS Test Suite"
echo "Binary: $ENVA"
echo "Temp:   $TEST_DIR"
echo "macOS:  $(sw_vers -productVersion) ($(uname -m))"
echo "========================================"

# ------------------------------------------------------------------
# 1. Binary basics
# ------------------------------------------------------------------
echo ""
echo "[Section 1] Binary basics"

VER=$($ENVA --version 2>&1)
assert "version output" '[ -n "$VER" ] && echo "$VER" | grep -q "enva"'

HELP=$($ENVA --help 2>&1)
assert "help shows vault subcommand" 'echo "$HELP" | grep -q "vault"'
assert "help shows serve subcommand" 'echo "$HELP" | grep -q "serve"'

SELF=$($ENVA vault self-test 2>&1)
assert "self-test passes" 'echo "$SELF" | grep -q "All checks passed"'

assert "help shows --env flag" 'echo "$HELP" | grep -q "\-\-env"'

# ------------------------------------------------------------------
# 2. Vault CRUD
# ------------------------------------------------------------------
echo ""
echo "[Section 2] Vault CRUD"

echo "$PW" | $ENVA vault init --vault "$VP" --password-stdin >/dev/null 2>&1
assert "vault init creates file" '[ -f "$VP" ]'

STRUCT=$(python3 -c "import json; d=json.load(open('$VP')); print('_meta' in d and 'secrets' in d and 'apps' in d)")
assert "vault JSON structure" '[ "$STRUCT" = "True" ]'

echo "$PW" | $ENVA vault set ascii-s -k ASCII_KEY -V "hello_world" --vault "$VP" --password-stdin >/dev/null 2>&1
GOT=$(echo "$PW" | $ENVA vault get ascii-s --vault "$VP" --password-stdin 2>/dev/null)
assert "set/get ASCII roundtrip" '[ "$GOT" = "hello_world" ]'

echo "$PW" | $ENVA vault set cn-s -k CN_KEY -V "数据库密码" --vault "$VP" --password-stdin >/dev/null 2>&1
GOT=$(echo "$PW" | $ENVA vault get cn-s --vault "$VP" --password-stdin 2>/dev/null)
assert "set/get Chinese roundtrip" '[ "$GOT" = "数据库密码" ]'

echo "$PW" | $ENVA vault set spec-s -k SPEC_KEY -V '!@#$%^&*()' --vault "$VP" --password-stdin >/dev/null 2>&1
GOT=$(echo "$PW" | $ENVA vault get spec-s --vault "$VP" --password-stdin 2>/dev/null)
assert "set/get special chars roundtrip" '[ "$GOT" = "!@#\$%^&*()" ]'

LIST=$(echo "$PW" | $ENVA vault list --vault "$VP" --password-stdin 2>/dev/null)
assert "vault list shows entries" 'echo "$LIST" | grep -q "ascii-s"'

echo "$PW" | $ENVA vault assign ascii-s --app testapp --vault "$VP" --password-stdin >/dev/null 2>&1
FLIST=$(echo "$PW" | $ENVA vault list --app testapp --vault "$VP" --password-stdin 2>/dev/null)
assert "assign + list --app" 'echo "$FLIST" | grep -q "ascii-s"'

echo "$PW" | $ENVA vault unassign ascii-s --app testapp --vault "$VP" --password-stdin >/dev/null 2>&1
ULIST=$(echo "$PW" | $ENVA vault list --app testapp --vault "$VP" --password-stdin 2>/dev/null)
assert "unassign removes from app" 'echo "$ULIST" | grep -q "No secrets found"'

echo "$PW" | $ENVA vault assign ascii-s --app expapp --vault "$VP" --password-stdin >/dev/null 2>&1
EENV=$(echo "$PW" | $ENVA vault export --app expapp --vault "$VP" --password-stdin 2>/dev/null)
assert "export env format" 'echo "$EENV" | grep -q "export ASCII_KEY="'

EJSON=$(echo "$PW" | $ENVA vault export --app expapp --format json --vault "$VP" --password-stdin 2>/dev/null)
assert "export json format" 'echo "$EJSON" | python3 -c "import json,sys; json.load(sys.stdin)" 2>/dev/null'

printf 'IMP_KEY=imp_val\nIMP_OTHER=other\n' > "$TEST_DIR/.env"
echo "$PW" | $ENVA vault import-env --from "$TEST_DIR/.env" --app impapp --vault "$VP" --password-stdin >/dev/null 2>&1
ILIST=$(echo "$PW" | $ENVA vault list --app impapp --vault "$VP" --password-stdin 2>/dev/null)
assert "import-env creates secrets" 'echo "$ILIST" | grep -q "IMP_KEY"'

echo "$PW" | $ENVA vault delete spec-s --yes --vault "$VP" --password-stdin >/dev/null 2>&1
DEL_OUT=$(echo "$PW" | $ENVA vault get spec-s --vault "$VP" --password-stdin 2>&1 || true)
assert "delete removes secret" 'echo "$DEL_OUT" | grep -q "alias not found"'

# ------------------------------------------------------------------
# 3. App injection & exec
# ------------------------------------------------------------------
echo ""
echo "[Section 3] App injection & exec"

echo "$PW" | $ENVA vault set s1 -k S1_KEY -V "val1" --vault "$VP" --password-stdin >/dev/null 2>&1
echo "$PW" | $ENVA vault set s2 -k S2_KEY -V "val2" --vault "$VP" --password-stdin >/dev/null 2>&1
echo "$PW" | $ENVA vault set s3 -k S3_KEY -V "val3" --vault "$VP" --password-stdin >/dev/null 2>&1
echo "$PW" | $ENVA vault assign s1 --app runapp --vault "$VP" --password-stdin >/dev/null 2>&1
echo "$PW" | $ENVA vault assign s2 --app runapp --vault "$VP" --password-stdin >/dev/null 2>&1
echo "$PW" | $ENVA vault assign s3 --app runapp --vault "$VP" --password-stdin >/dev/null 2>&1

DRY=$(echo "$PW" | $ENVA --vault "$VP" --password-stdin runapp 2>/dev/null)
assert "dry-run shows redacted" 'echo "$DRY" | grep -q "<redacted>"'

EXEC_OUT=$(echo "$PW" | $ENVA --vault "$VP" --password-stdin runapp -- printenv S1_KEY 2>/dev/null)
assert "exec injects env var" '[ "$EXEC_OUT" = "val1" ]'

MULTI=$(echo "$PW" | $ENVA --vault "$VP" --password-stdin runapp -- sh -c "echo \$S1_KEY \$S2_KEY \$S3_KEY" 2>/dev/null)
assert "multi-var injection" '[ "$MULTI" = "val1 val2 val3" ]'

QUIET_OUT=$(echo "$PW" | $ENVA --quiet --vault "$VP" --password-stdin vault set qx -k QX -V qv 2>&1)
assert "quiet flag suppresses" '[ -z "$QUIET_OUT" ]'

# ------------------------------------------------------------------
# 3b. Password validation
# ------------------------------------------------------------------
echo ""
echo "[Section 3b] Password validation"

EMPTY_PW_VP="$TEST_DIR/empty-pw.vault.json"
EMPTY_PW_OUT=$(echo "" | $ENVA vault init --vault "$EMPTY_PW_VP" --password-stdin 2>&1 || true)
assert "empty password rejected on init" 'echo "$EMPTY_PW_OUT" | grep -qi "password"'
assert "empty password vault not created" '[ ! -f "$EMPTY_PW_VP" ]'

# ------------------------------------------------------------------
# 3c. App name validation
# ------------------------------------------------------------------
echo ""
echo "[Section 3c] App name validation"

UPPER_OUT=$(echo "$PW" | $ENVA vault assign s1 --app "UPPERCASE" --vault "$VP" --password-stdin 2>&1 || true)
assert "uppercase app name rejected" 'echo "$UPPER_OUT" | grep -qi "invalid app name\|error"'

SPACE_OUT=$(echo "$PW" | $ENVA vault assign s1 --app "has space" --vault "$VP" --password-stdin 2>&1 || true)
assert "app name with space rejected" 'echo "$SPACE_OUT" | grep -qi "error"'

echo "$PW" | $ENVA vault assign s1 --app "valid-app-123" --vault "$VP" --password-stdin >/dev/null 2>&1
VALID_LIST=$(echo "$PW" | $ENVA vault list --app "valid-app-123" --vault "$VP" --password-stdin 2>/dev/null)
assert "valid app name accepted" 'echo "$VALID_LIST" | grep -q "s1"'

# ------------------------------------------------------------------
# 3d. Exit codes
# ------------------------------------------------------------------
echo ""
echo "[Section 3d] Exit codes"

echo "wrongpw" | $ENVA vault list --vault "$VP" --password-stdin >/dev/null 2>&1
EC_AUTH=$?
assert "auth failure exit code 2" '[ "$EC_AUTH" -eq 2 ]'

echo "$PW" | $ENVA vault get nonexistent-alias --vault "$VP" --password-stdin >/dev/null 2>&1
EC_NOTFOUND=$?
assert "not-found exit code 3" '[ "$EC_NOTFOUND" -eq 3 ]'

echo "$PW" | $ENVA vault list --vault "/no/such/file.json" --password-stdin >/dev/null 2>&1
EC_IO=$?
assert "io error exit code 1" '[ "$EC_IO" -eq 1 ]'

# ------------------------------------------------------------------
# 4. Config loading
# ------------------------------------------------------------------
echo ""
echo "[Section 4] Config loading"

VP2="$TEST_DIR/cfg.vault.json"
echo "$PW" | $ENVA vault init --vault "$VP2" --password-stdin >/dev/null 2>&1
echo "$PW" | $ENVA vault set cfgs -k CFG_K -V "cfgv" --vault "$VP2" --password-stdin >/dev/null 2>&1

ENV_VP=$(echo "$PW" | ENVA_VAULT_PATH="$VP2" $ENVA vault list --password-stdin 2>/dev/null)
assert "ENVA_VAULT_PATH override" 'echo "$ENV_VP" | grep -q "cfgs"'

PROJ="$TEST_DIR/proj/sub/deep"
mkdir -p "$PROJ"
cat > "$TEST_DIR/proj/.enva.yaml" << YAML
vault_path: $VP2
YAML
PROJ_OUT=$(cd "$PROJ" && echo "$PW" | $ENVA vault list --password-stdin 2>/dev/null)
assert "project .enva.yaml discovery" 'echo "$PROJ_OUT" | grep -q "cfgs"'

if [ -d "$HOME/.enva" ]; then
    cp -R "$HOME/.enva" "$HOME/.enva.test-backup"
fi
mkdir -p "$HOME/.enva"
cat > "$HOME/.enva/config.yaml" << YAML
vault_path: $VP2
YAML
HOME_OUT=$(echo "$PW" | $ENVA vault list --password-stdin 2>/dev/null)
assert "~/.enva/config.yaml loaded" 'echo "$HOME_OUT" | grep -q "cfgs"'
rm -rf "$HOME/.enva"
if [ -d "$HOME/.enva.test-backup" ]; then
    mv "$HOME/.enva.test-backup" "$HOME/.enva"
fi

# ------------------------------------------------------------------
# 5. Web UI
# ------------------------------------------------------------------
echo ""
echo "[Section 5] Web UI"

WEB_PORT=19080
$ENVA serve --port $WEB_PORT --vault "$VP" >/dev/null 2>&1 &
WEB_PID=$!
sleep 2

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:$WEB_PORT/" 2>/dev/null || echo "000")
assert "web UI returns HTTP 200" '[ "$HTTP_CODE" = "200" ]'

curl -s "http://127.0.0.1:$WEB_PORT/" > "$TEST_DIR/web.html" 2>/dev/null
assert "web UI returns HTML" 'head -1 "$TEST_DIR/web.html" | grep -qi "doctype\|html"'
assert "web UI has i18n translations" 'grep -q "setLanguage\|data-i18n" "$TEST_DIR/web.html"'
assert "web UI has theme toggle" 'grep -q "setTheme\|theme" "$TEST_DIR/web.html"'

curl -s -X POST -H "Content-Type: application/json" -d '{"password":""}' "http://127.0.0.1:$WEB_PORT/api/auth/login" > "$TEST_DIR/login_resp.json" 2>/dev/null
assert "web login rejects empty password" 'grep -qi "empty\|error\|must not" "$TEST_DIR/login_resp.json"'

kill $WEB_PID 2>/dev/null; wait $WEB_PID 2>/dev/null || true

WEB_PORT2=19081
$ENVA serve --port $WEB_PORT2 --vault "$VP" >/dev/null 2>"$TEST_DIR/srv.log" &
SRV_PID=$!
sleep 2
curl -s "http://127.0.0.1:$WEB_PORT2/" >/dev/null 2>&1
kill -TERM $SRV_PID 2>/dev/null
sleep 1
kill -0 $SRV_PID 2>/dev/null && SRV_ALIVE=true || SRV_ALIVE=false
assert "graceful shutdown on SIGTERM" '[ "$SRV_ALIVE" = "false" ]'
wait $SRV_PID 2>/dev/null || true

WEB_PORT3=19082
$ENVA serve --port $WEB_PORT3 --vault "$VP" >/dev/null 2>&1 &
SRV2_PID=$!
sleep 2
curl -s "http://127.0.0.1:$WEB_PORT3/" >/dev/null 2>&1
kill -INT $SRV2_PID 2>/dev/null
sleep 1
kill -0 $SRV2_PID 2>/dev/null && SRV2_ALIVE=true || SRV2_ALIVE=false
assert "graceful shutdown on SIGINT" '[ "$SRV2_ALIVE" = "false" ]'
wait $SRV2_PID 2>/dev/null || true

# ------------------------------------------------------------------
# 6. Verbose tracing
# ------------------------------------------------------------------
echo ""
echo "[Section 6] Verbose tracing"

VERB_OUT=$(echo "$PW" | $ENVA --verbose --vault "$VP" --password-stdin vault list 2>&1)
assert "verbose shows debug tracing" 'echo "$VERB_OUT" | grep -q "dispatching command"'
assert "verbose shows vault_path" 'echo "$VERB_OUT" | grep -q "vault_path"'
assert "verbose shows password source" 'echo "$VERB_OUT" | grep -q "reading password"'

# ------------------------------------------------------------------
# 7. Error paths
# ------------------------------------------------------------------
echo ""
echo "[Section 7] Error paths"

ERR_PW=$(echo "wrongpw" | $ENVA vault list --vault "$VP" --password-stdin 2>&1 || true)
assert "wrong password error" 'echo "$ERR_PW" | grep -qi "error"'

ERR_MISS=$(echo "$PW" | $ENVA vault list --vault "/no/such/file.json" --password-stdin 2>&1 || true)
assert "missing vault error" 'echo "$ERR_MISS" | grep -qi "error"'

ERR_ALIAS=$(echo "$PW" | $ENVA vault get no-such-alias --vault "$VP" --password-stdin 2>&1 || true)
assert "missing alias error" 'echo "$ERR_ALIAS" | grep -q "alias not found"'

LONG_VAL=$(python3 -c "print('X' * 15000)")
echo "$PW" | $ENVA vault set longv -k LONG_K -V "$LONG_VAL" --vault "$VP" --password-stdin >/dev/null 2>&1
LONG_GOT=$(echo "$PW" | $ENVA vault get longv --vault "$VP" --password-stdin 2>/dev/null)
assert "long value (15KB) roundtrip" '[ "${#LONG_GOT}" -eq 15000 ]'

EMPTY_VP="$TEST_DIR/empty.vault.json"
echo "$PW" | $ENVA vault init --vault "$EMPTY_VP" --password-stdin >/dev/null 2>&1
EMPTY_LIST=$(echo "$PW" | $ENVA vault list --vault "$EMPTY_VP" --password-stdin 2>/dev/null)
assert "empty vault list" 'echo "$EMPTY_LIST" | grep -q "No secrets found"'

# ------------------------------------------------------------------
# Summary
# ------------------------------------------------------------------
echo ""
echo "========================================"
echo "        RESULTS SUMMARY"
echo "========================================"
printf "%-6s | %s\n" "STATUS" "TEST"
echo "-------+--------------------------------"
for r in "${RESULTS[@]}"; do
    STATUS="${r%%|*}"
    NAME="${r#*|}"
    if [ "$STATUS" = "PASS" ]; then
        printf "\033[32m%-6s\033[0m | %s\n" "$STATUS" "$NAME"
    else
        printf "\033[31m%-6s\033[0m | %s\n" "$STATUS" "$NAME"
    fi
done
echo "-------+--------------------------------"
TOTAL=$((PASS_COUNT + FAIL_COUNT))
echo "Total: $TOTAL | Pass: $PASS_COUNT | Fail: $FAIL_COUNT"
echo ""

if [ "$FAIL_COUNT" -gt 0 ]; then
    echo "SOME TESTS FAILED"
    exit 1
else
    echo "ALL TESTS PASSED"
    exit 0
fi
