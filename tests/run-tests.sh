#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AUDIT="${ROOT_DIR}/scripts/ai-diff-audit.sh"

# 0. Pre-flight syntax & CRLF checks on our own scripts
bash -n "${ROOT_DIR}/scripts/ai-diff-audit.sh"
python3 -m py_compile "${ROOT_DIR}/scripts/audit-diff.py"
python3 -c '
import pathlib, sys
for p in pathlib.Path(sys.argv[1]).rglob("*"):
    if p.is_file() and p.suffix in {".sh", ".py", ".md"}:
        if b"\r\n" in p.read_bytes():
            raise SystemExit(f"CRLF found in {p}")
' "${ROOT_DIR}"

TMP_REPO="$(mktemp -d)"
trap 'rm -rf "${TMP_REPO}"' EXIT

git -C "${TMP_REPO}" init -q
git -C "${TMP_REPO}" config user.name "Test"
git -C "${TMP_REPO}" config user.email "test@example.com"

mkdir -p "${TMP_REPO}/src" "${TMP_REPO}/tests"
cat > "${TMP_REPO}/src/calc.py" <<'EOF'
def add(a, b):
    return a + b
EOF
cat > "${TMP_REPO}/tests/test_calc.py" <<'EOF'
from src.calc import add

def test_add():
    assert add(2, 3) == 5
    assert add(-1, 1) == 0
EOF

git -C "${TMP_REPO}" add .
git -C "${TMP_REPO}" commit -q -m "initial"

# Test 1: Clean refactor passes (exit 0, PASS)
cat > "${TMP_REPO}/src/calc.py" <<'EOF'
def add(a: int, b: int) -> int:
    return a + b
EOF
OUT1="$(bash "${AUDIT}" --repo "${TMP_REPO}" --working --json)"
echo "${OUT1}" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["summary"]["verdict"]=="PASS", d'
echo "[PASS] Test 1: Clean refactor exits 0 (PASS)"

# Test 2: AI cheats by skipping test, deleting assertion, adding except: pass & || true
cat > "${TMP_REPO}/tests/test_calc.py" <<'EOF'
import pytest
from src.calc import add

@pytest.mark.skip(reason="flaky")
def test_add():
    assert add(2, 3) == 5
EOF
cat > "${TMP_REPO}/src/calc.py" <<'EOF'
def add(a, b):
    try:
        return a + b  # type: ignore
    except Exception:
        pass
EOF
cat > "${TMP_REPO}/src/run.sh" <<'EOF'
#!/usr/bin/env bash
pytest || true
EOF
git -C "${TMP_REPO}" add src/run.sh

set +e
OUT2="$(bash "${AUDIT}" --repo "${TMP_REPO}" --working --json)"
RC2=$?
set -e
if [ "${RC2}" -ne 1 ]; then
  echo "[FAIL] Expected exit 1 for cheat diff, got ${RC2}" >&2
  exit 1
fi
echo "${OUT2}" | python3 -c '
import json, sys
d = json.load(sys.stdin)
rules = {f["rule"] for f in d["findings"]}
for expected in ("TEST_SKIP_ADDED", "DELETED_TEST_ASSERTIONS", "ERROR_MASKING", "LINTER_SUPPRESSED"):
    assert expected in rules, f"Missing {expected} in {rules}"
assert d["summary"]["verdict"] == "FAIL"
'
echo "[PASS] Test 2: Caught TEST_SKIP_ADDED, DELETED_TEST_ASSERTIONS, ERROR_MASKING, LINTER_SUPPRESSED"

# Test 3: Secret detection redacts secret from snippet and ignores placeholder
git -C "${TMP_REPO}" checkout -q -- .
git -C "${TMP_REPO}" rm -qf src/run.sh
cat > "${TMP_REPO}/src/config.py" <<'EOF'
DUMMY_KEY = "sk-proj-EXAMPLEPLACEHOLDER123456789012"
REAL_KEY = "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz123456"
EOF
git -C "${TMP_REPO}" add src/config.py
set +e
OUT3="$(bash "${AUDIT}" --repo "${TMP_REPO}" --staged --json)"
RC3=$?
set -e
if [ "${RC3}" -ne 1 ]; then
  echo "[FAIL] Expected exit 1 for secret diff, got ${RC3}" >&2
  exit 1
fi
echo "${OUT3}" | python3 -c '
import json, sys
raw = sys.stdin.read()
assert "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz123456" not in raw, "Secret was not redacted!"
d = json.loads(raw)
secret_findings = [f for f in d["findings"] if f["rule"] == "LEAKED_SECRET"]
assert len(secret_findings) == 1, f"Expected exactly 1 secret finding (placeholder ignored), got {secret_findings}"
'
echo "[PASS] Test 3: Caught real secret, redacted output, ignored placeholder"

# Test 4: --allow-path enforces scope
git -C "${TMP_REPO}" reset -q HEAD src/config.py
rm -f "${TMP_REPO}/src/config.py"
echo "# extra" >> "${TMP_REPO}/src/calc.py"
set +e
OUT4="$(bash "${AUDIT}" --repo "${TMP_REPO}" --working --allow-path tests/ --json)"
RC4=$?
set -e
if [ "${RC4}" -ne 1 ]; then
  echo "[FAIL] Expected exit 1 for out-of-scope edit, got ${RC4}" >&2
  exit 1
fi
echo "${OUT4}" | python3 -c '
import json, sys
d = json.load(sys.stdin)
assert any(f["rule"] == "OUT_OF_SCOPE_EDIT" and f["file"] == "src/calc.py" for f in d["findings"]), d
'
echo "[PASS] Test 4: --allow-path caught OUT_OF_SCOPE_EDIT"

# Test 5: Human-readable PR receipt format check
bash "${AUDIT}" --repo "${TMP_REPO}" --working --allow-path src/ | grep -q "=== AI DIFF AUDIT RECEIPT ==="
echo "[PASS] Test 5: Human-readable PR receipt renders cleanly"

# Test structural edge cases through the CLI using Git-generated patches.
python3 - "${ROOT_DIR}/scripts/audit-diff.py" <<'PY'
import json
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

audit = sys.argv[1]

with TemporaryDirectory() as tmp:
    repo = Path(tmp)

    def git(*args):
        return subprocess.check_output(["git", "-C", tmp, *args])

    def check(*args, patch=None, code=1):
        result = subprocess.run(
            [sys.executable, audit, "--repo", tmp, "--json", *args],
            input=patch, capture_output=True,
        )
        assert result.returncode == code, result
        return json.loads(result.stdout) if code != 2 else result.stderr.decode()

    git("init", "-q")
    git("config", "user.name", "Test")
    git("config", "user.email", "test@example.com")
    (repo / "tests").mkdir()
    (repo / "src.v2").mkdir()
    (repo / "src").mkdir()
    (repo / "tests/test_all.py").write_text("assert 1 + 1 == 2\n", encoding="utf-8")
    (repo / "src.v2/名称.py").write_text("try:\n    run()\nexcept RuntimeError:\n    raise\n", encoding="utf-8")
    (repo / "src/with spaces").write_text("unchanged\n", encoding="utf-8")
    (repo / "src/task.py.backup").write_text("original\n", encoding="utf-8")
    (repo / "external binary").write_bytes(b"\0old\n")
    git("add", ".")
    assert check("--working", code=0)["summary"]["files_changed"] == 5
    git("commit", "-qm", "fixtures")

    git("rm", "tests/test_all.py")
    git("mv", "src/with spaces", "src.v2/moved file")
    (repo / "src/task.py.backup").chmod(0o755)
    git("add", "src/task.py.backup")
    (repo / "external binary").write_bytes(b"\0new\n")
    (repo / "src.v2/名称.py").write_text("try:\n    run()\nexcept RuntimeError:\n    pass\n", encoding="utf-8")
    payload = check("--working", "--allow-path", "src.v2/", "--allow-path", "src/task.py")
    summary = payload["summary"]
    assert summary["files_changed"] == 5 and summary["lines_removed"] == 2, summary
    findings = {(f["rule"], f["file"], f["line"]) for f in payload["findings"]}
    assert ("DELETED_TEST_ASSERTIONS", "tests/test_all.py", 0) in findings, findings
    assert ("ERROR_MASKING", "src.v2/名称.py", 4) in findings, findings
    assert {f[1] for f in findings if f[0] == "OUT_OF_SCOPE_EDIT"} == {
        "tests/test_all.py", "src/with spaces", "src/task.py.backup", "external binary",
    }, findings

    git("add", "--", "src.v2/名称.py", "external binary")
    git("commit", "-qm", "audit inputs")
    assert check("--base", "HEAD~1")["summary"]["files_changed"] == 5
    assert "Could not resolve base ref" in check("--base=--name-only", code=2)

    token = "ghp_" + "AaBbCcDdEeFfGgHhIiJjKkLl"
    patch = (
        "--- a/tests/example.py\n+++ b/tests/example.py\n@@ -1,2 +1,2 @@\n"
        " ---- context\n--- removed\n"
        f'+++ "{token}" # example value\r\n'
        "--- a/other.txt\n+++ b/other.txt\n@@ -1 +1 @@\n-old\n+new\n"
    ).encode("ascii")
    patch_file = repo / "fixture.diff"
    patch_file.write_bytes(patch)
    for payload in (check("--diff-file", "-", patch=patch), check("--diff-file", str(patch_file))):
        assert payload["summary"]["files"] == ["tests/example.py", "other.txt"], payload
        assert payload["summary"]["lines_added"] == payload["summary"]["lines_removed"] == 2, payload
        assert token not in json.dumps(payload), "Unredacted test token in receipt"
        assert {f["rule"] for f in payload["findings"]} == {"LEAKED_SECRET", "HIDDEN_CRLF"}, payload
    malformed = b"--- a/example.py\n+++ b/example.py\n@@ -0,0 +1,2 @@\n+one\n"
    assert "truncated" in check("--diff-file", "-", patch=malformed, code=2).lower()
PY
echo "[PASS] Test 6: Git paths, full deletion, context, patch input, and line counts"

echo "ALL TESTS PASSED"
