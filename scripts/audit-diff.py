#!/usr/bin/env python3
"""
ai-diff-audit: Zero-dependency, strictly read-only Git diff auditor for AI coding agents.

Catches the quiet ways coding agents make diffs look green:
  1. Test cheating (added skip/xfail/ignore markers or net-deleted assertions in test files)
  2. Swallowed errors & masked exit codes (`|| true`, `set +e`, empty `except: pass`, empty `catch {}`)
  3. Silenced linters / type checks (`# type: ignore`, `# noqa`, `@ts-ignore`, `eslint-disable`)
  4. Blast-radius drift (too many files/lines, sensitive infra/lockfile edits, out-of-scope paths)
  5. Leaked secrets, unresolved merge conflict markers, hidden CRLF, and debug residue

Built by Harvey | Tech Builder (@lxy71 · https://harveyi.com)
License: MIT
"""

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, asdict
from typing import List, Optional, Tuple


@dataclass
class Finding:
    severity: str  # "CRITICAL" or "WARNING"
    rule: str
    file: str
    line: int
    message: str
    snippet: str = ""


# --- Patterns (applied ONLY to added/removed diff lines) ---

TEST_FILE_RE = re.compile(
    r"(^|/)(tests?|specs?|__tests__)/|"
    r"(_test\.(py|go|rs|rb|ts|tsx|js|jsx)|"
    r"\.(test|spec)\.(ts|tsx|js|jsx|mjs|cjs)|"
    r"test_[^/]+\.py)$",
    re.IGNORECASE,
)

SKIP_TEST_PATTERNS = [
    (re.compile(r"@\s*pytest\.mark\.(skip|skipif|xfail)\b"), "Added pytest skip/xfail decorator"),
    (re.compile(r"@\s*unittest\.skip(If|Unless)?\b"), "Added unittest skip decorator"),
    (re.compile(r"\bpytest\.skip\s*\("), "Added runtime pytest.skip() call"),
    (re.compile(r"\b(it|test|describe)\.skip\s*\("), "Added JS/TS .skip() on test"),
    (re.compile(r"\b(xit|xtest|xdescribe)\s*\("), "Added disabled xit/xtest/xdescribe test"),
    (re.compile(r"\bt\.Skip(Now|f)?\s*\("), "Added Go t.Skip() call"),
    (re.compile(r"#\s*\[\s*ignore\b"), "Added Rust #[ignore] attribute on test"),
]

ASSERTION_PATTERNS = re.compile(
    r"^\s*assert\b|"
    r"\bself\.assert[A-Z]\w*\s*\(|"
    r"\bassert_(eq|ne|matches)?!\s*\(|"
    r"\bexpect\s*\(|"
    r"\bt\.(Error|Errorf|Fatal|Fatalf|Fail|FailNow)\s*\(|"
    r"\b(require|assert)\.[A-Z]\w*\s*\("
)

ERROR_MASKING_PATTERNS = [
    (re.compile(r"\|\|\s*true\b"), "Added '|| true' which masks non-zero exit codes"),
    (re.compile(r";\s*true\s*$"), "Added '; true' which masks prior command exit code"),
    (re.compile(r"\bset\s+\+e\b"), "Disabled shell errexit with 'set +e'"),
    (re.compile(r"^\s*except\b.*:\s*pass\s*(#.*)?$"), "Added inline 'except: pass' swallowing errors"),
    (re.compile(r"\bcatch\s*(\([^)]*\))?\s*\{\s*\}"), "Added empty 'catch {}' block swallowing errors"),
]

LINTER_SILENCE_PATTERNS = [
    (re.compile(r"#\s*type:\s*ignore\b"), "Added '# type: ignore' silencing type checker"),
    (re.compile(r"#\s*noqa\b"), "Added '# noqa' silencing Python linter"),
    (re.compile(r"//\s*@ts-(ignore|nocheck|expect-error)\b"), "Added TypeScript suppression directive"),
    (re.compile(r"(/\*\s*|//\s*)eslint-disable\b"), "Added eslint-disable directive"),
    (re.compile(r"#\s*\[allow\([^\]]+\)\]"), "Added Rust #[allow(...)] suppression"),
]

SECRET_PATTERNS = [
    (re.compile(r"\bsk-(proj-|ant-|live-|test-)?[A-Za-z0-9_-]{20,}\b"), "Possible API secret key (sk-...)"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"), "Possible GitHub personal/OAuth token"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"), "Possible GitHub fine-grained PAT"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "Possible AWS Access Key ID"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "Possible Slack token"),
    (re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"), "Private key header found in diff"),
    (
        re.compile(r"\b(postgres|postgresql|mysql|mongodb(\+srv)?|redis)://[^/\s:@]+:[^/\s@]{4,}@"),
        "Database URI with embedded password",
    ),
]

PLACEHOLDER_SECRET_RE = re.compile(
    r"(REDACTED|YOUR[_-]?KEY|EXAMPLE|DUMMY|FAKE|PLACEHOLDER|CHANGEME|TEST[_-]?KEY|xxxx|<[^>]+>)",
    re.IGNORECASE,
)

CONFLICT_MARKER_RE = re.compile(r"^(<{7}|={7}|>{7})(\s|$)")

DEBUG_RESIDUE_PATTERNS = [
    (re.compile(r"\bbreakpoint\s*\(\s*\)"), "Added Python breakpoint() call"),
    (re.compile(r"\bpdb\.set_trace\s*\("), "Added pdb.set_trace() call"),
    (re.compile(r"^\s*debugger\s*;?\s*$"), "Added JS/TS debugger statement"),
    (re.compile(r"\bconsole\.log\s*\("), "Added console.log() in non-test code"),
]

SENSITIVE_PATH_PATTERNS = [
    re.compile(r"^\.github/workflows/"),
    re.compile(r"(^|/)Dockerfile(\.|$)"),
    re.compile(r"(^|/)docker-compose[^/]*\.ya?ml$"),
    re.compile(r"(^|/)(package-lock\.json|pnpm-lock\.yaml|yarn\.lock|poetry\.lock|Cargo\.lock)$"),
    re.compile(r"(^|/)\.env(\.|$)"),
    re.compile(r"(^|/)(migrations|alembic)/"),
]


def redact_snippet(text: str, max_len: int = 100) -> str:
    """Redact potential secrets before displaying any snippet."""
    cleaned = text.rstrip("\r\n")
    for pattern, _ in SECRET_PATTERNS:
        cleaned = pattern.sub("[REDACTED_SECRET]", cleaned)
    if len(cleaned) > max_len:
        cleaned = cleaned[: max_len - 3] + "..."
    return cleaned


def is_test_file(path: str) -> bool:
    return bool(TEST_FILE_RE.search(path))


def is_sensitive_path(path: str) -> bool:
    return any(p.search(path) for p in SENSITIVE_PATH_PATTERNS)


def run_git_diff(repo_dir: str, mode: str, base_ref: Optional[str]) -> str:
    cmd = ["git", "-C", repo_dir, "diff", "--no-color", "--unified=1"]
    if mode == "staged":
        cmd.append("--cached")
    elif mode == "base":
        if not base_ref:
            raise ValueError("--base requires a git ref (e.g. main)")
        cmd.append(f"{base_ref}...HEAD")
    elif mode == "working":
        # Include both staged and unstaged changes relative to HEAD when HEAD exists
        head_check = subprocess.run(
            ["git", "-C", repo_dir, "rev-parse", "--verify", "HEAD"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if head_check.returncode == 0:
            cmd.append("HEAD")
    else:
        raise ValueError(f"Unsupported mode: {mode}")

    proc = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"git diff failed (exit {proc.returncode}): {err}")
    return proc.stdout.decode("utf-8", errors="replace")


def parse_and_audit_diff(
    diff_text: str,
    max_files: int,
    max_lines: int,
    allow_paths: List[str],
) -> Tuple[dict, List[Finding]]:
    findings: List[Finding] = []
    files_seen: List[str] = []
    total_added = 0
    total_removed = 0
    test_assertions_added: dict = {}
    test_assertions_removed: dict = {}

    current_file: Optional[str] = None
    new_line_no = 0
    prev_added_was_bare_except: Optional[Tuple[int, str]] = None
    crlf_reported_files = set()

    hunk_re = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")

    for raw_line in diff_text.splitlines(keepends=True):
        line_no_nl = raw_line.rstrip("\n")
        has_cr = line_no_nl.endswith("\r")
        line = line_no_nl.rstrip("\r")

        if line.startswith("diff --git "):
            prev_added_was_bare_except = None
            continue

        if line.startswith("+++ "):
            target = line[4:].strip()
            if target == "/dev/null":
                current_file = None
            else:
                if target.startswith("b/"):
                    target = target[2:]
                current_file = target
                if current_file not in files_seen:
                    files_seen.append(current_file)
            prev_added_was_bare_except = None
            continue

        if line.startswith("--- "):
            continue

        m_hunk = hunk_re.match(line)
        if m_hunk:
            new_line_no = int(m_hunk.group(1))
            prev_added_was_bare_except = None
            continue

        if current_file is None:
            continue

        # Context line
        if line.startswith(" "):
            new_line_no += 1
            prev_added_was_bare_except = None
            continue

        # Removed line
        if line.startswith("-") and not line.startswith("---"):
            total_removed += 1
            content = line[1:]
            if is_test_file(current_file) and ASSERTION_PATTERNS.search(content):
                test_assertions_removed[current_file] = test_assertions_removed.get(current_file, 0) + 1
            continue

        # Added line
        if line.startswith("+") and not line.startswith("+++"):
            total_added += 1
            content = line[1:]
            line_num = new_line_no
            new_line_no += 1

            # 1. Hidden CRLF check
            if has_cr and current_file not in crlf_reported_files:
                crlf_reported_files.add(current_file)
                findings.append(
                    Finding(
                        severity="WARNING",
                        rule="HIDDEN_CRLF",
                        file=current_file,
                        line=line_num,
                        message="Added line introduces CRLF (\\r\\n) line ending",
                        snippet=redact_snippet(content),
                    )
                )

            # 2. Unresolved merge conflict markers
            if CONFLICT_MARKER_RE.match(content):
                findings.append(
                    Finding(
                        severity="CRITICAL",
                        rule="MERGE_CONFLICT_MARKER",
                        file=current_file,
                        line=line_num,
                        message="Unresolved merge conflict marker in added code",
                        snippet=redact_snippet(content),
                    )
                )

            # 3. Secrets in added lines
            if not PLACEHOLDER_SECRET_RE.search(content):
                for pat, msg in SECRET_PATTERNS:
                    if pat.search(content):
                        findings.append(
                            Finding(
                                severity="CRITICAL",
                                rule="LEAKED_SECRET",
                                file=current_file,
                                line=line_num,
                                message=msg,
                                snippet=redact_snippet(content),
                            )
                        )
                        break

            # 4. Test-skipping cheats
            if is_test_file(current_file):
                if ASSERTION_PATTERNS.search(content):
                    test_assertions_added[current_file] = test_assertions_added.get(current_file, 0) + 1
                for pat, msg in SKIP_TEST_PATTERNS:
                    if pat.search(content):
                        findings.append(
                            Finding(
                                severity="CRITICAL",
                                rule="TEST_SKIP_ADDED",
                                file=current_file,
                                line=line_num,
                                message=msg,
                                snippet=redact_snippet(content),
                            )
                        )

            # 5. Error swallowing / exit-code masking
            for pat, msg in ERROR_MASKING_PATTERNS:
                if pat.search(content):
                    findings.append(
                        Finding(
                            severity="CRITICAL",
                            rule="ERROR_MASKING",
                            file=current_file,
                            line=line_num,
                            message=msg,
                            snippet=redact_snippet(content),
                        )
                    )

            # Two-line Python `except ...:\n    pass`
            if prev_added_was_bare_except is not None:
                if re.match(r"^\s*pass\s*(#.*)?$", content):
                    exc_line, exc_content = prev_added_was_bare_except
                    findings.append(
                        Finding(
                            severity="CRITICAL",
                            rule="ERROR_MASKING",
                            file=current_file,
                            line=exc_line,
                            message="Added multi-line 'except: pass' swallowing errors",
                            snippet=redact_snippet(f"{exc_content.strip()} -> pass"),
                        )
                    )
                prev_added_was_bare_except = None

            if re.match(r"^\s*except(\s+[\w.(), ]+)?\s*:\s*(#.*)?$", content):
                prev_added_was_bare_except = (line_num, content)

            # 6. Linter / type-checker suppressions
            for pat, msg in LINTER_SILENCE_PATTERNS:
                if pat.search(content):
                    findings.append(
                        Finding(
                            severity="WARNING",
                            rule="LINTER_SUPPRESSED",
                            file=current_file,
                            line=line_num,
                            message=msg,
                            snippet=redact_snippet(content),
                        )
                    )

            # 7. Debug residue (skip console.log warnings inside test files)
            for pat, msg in DEBUG_RESIDUE_PATTERNS:
                if "console.log" in msg and is_test_file(current_file):
                    continue
                if pat.search(content):
                    findings.append(
                        Finding(
                            severity="WARNING",
                            rule="DEBUG_RESIDUE",
                            file=current_file,
                            line=line_num,
                            message=msg,
                            snippet=redact_snippet(content),
                        )
                    )

    # --- File-level & Diff-level Audits ---

    # Net-deleted assertions in test files
    all_test_files = sorted(set(test_assertions_added.keys()) | set(test_assertions_removed.keys()))
    total_assert_added = 0
    total_assert_removed = 0
    for tf in all_test_files:
        added_cnt = test_assertions_added.get(tf, 0)
        removed_cnt = test_assertions_removed.get(tf, 0)
        total_assert_added += added_cnt
        total_assert_removed += removed_cnt
        if removed_cnt > added_cnt:
            findings.append(
                Finding(
                    severity="CRITICAL",
                    rule="DELETED_TEST_ASSERTIONS",
                    file=tf,
                    line=0,
                    message=(
                        f"Net-deleted {removed_cnt - added_cnt} assertion(s) in test file "
                        f"(-{removed_cnt} removed / +{added_cnt} added)"
                    ),
                )
            )

    # Sensitive path touches
    for fpath in files_seen:
        if is_sensitive_path(fpath):
            findings.append(
                Finding(
                    severity="WARNING",
                    rule="SENSITIVE_FILE_TOUCHED",
                    file=fpath,
                    line=0,
                    message="Diff modifies sensitive config, CI, migration, or lockfile",
                )
            )

    # Out-of-scope paths (when --allow-path is provided)
    normalized_allows = [p.rstrip("/") + "/" if not os.path.splitext(p)[1] else p for p in allow_paths]
    if allow_paths:
        for fpath in files_seen:
            allowed = any(
                fpath == raw.rstrip("/") or fpath.startswith(norm)
                for raw, norm in zip(allow_paths, normalized_allows)
            )
            if not allowed:
                findings.append(
                    Finding(
                        severity="CRITICAL",
                        rule="OUT_OF_SCOPE_EDIT",
                        file=fpath,
                        line=0,
                        message=f"File modified outside allowed paths ({', '.join(allow_paths)})",
                    )
                )

    # Blast radius thresholds
    if len(files_seen) > max_files:
        findings.append(
            Finding(
                severity="WARNING",
                rule="BLAST_RADIUS_FILES",
                file="<diff>",
                line=0,
                message=f"Diff touches {len(files_seen)} files (threshold: {max_files})",
            )
        )
    if (total_added + total_removed) > max_lines:
        findings.append(
            Finding(
                severity="WARNING",
                rule="BLAST_RADIUS_LINES",
                file="<diff>",
                line=0,
                message=f"Diff changes {total_added + total_removed} lines (+{total_added}/-{total_removed}, threshold: {max_lines})",
            )
        )

    critical_count = sum(1 for f in findings if f.severity == "CRITICAL")
    warning_count = sum(1 for f in findings if f.severity == "WARNING")

    summary = {
        "files_changed": len(files_seen),
        "files": files_seen,
        "lines_added": total_added,
        "lines_removed": total_removed,
        "test_assertions_added": total_assert_added,
        "test_assertions_removed": total_assert_removed,
        "critical_count": critical_count,
        "warning_count": warning_count,
        "verdict": "FAIL" if critical_count > 0 else ("WARN" if warning_count > 0 else "PASS"),
    }
    return summary, findings


def format_receipt(scope_label: str, summary: dict, findings: List[Finding]) -> str:
    out = [
        "=== AI DIFF AUDIT RECEIPT ===",
        f"Scope      : {scope_label}",
        f"Verdict    : {summary['verdict']} (critical: {summary['critical_count']}, warnings: {summary['warning_count']})",
        f"Blast      : {summary['files_changed']} file(s), +{summary['lines_added']} / -{summary['lines_removed']} lines",
        f"Assertions : +{summary['test_assertions_added']} / -{summary['test_assertions_removed']} in test files",
    ]
    if not findings:
        out.append("Findings   : None — diff passed all deterministic cheat, secret, and scope checks.")
    else:
        out.append("")
        out.append("Findings:")
        for idx, f in enumerate(findings, 1):
            loc = f"{f.file}:{f.line}" if f.line > 0 else f.file
            out.append(f"  {idx}. [{f.severity}] {f.rule} @ {loc}")
            out.append(f"     {f.message}")
            if f.snippet:
                out.append(f"     > {f.snippet}")
    out.append("=============================")
    return "\n".join(out)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Read-only Git diff auditor that catches AI coding cheats, masked errors, secrets, and blast-radius drift."
    )
    scope_group = parser.add_mutually_exclusive_group()
    scope_group.add_argument("--staged", action="store_true", help="Audit staged changes (git diff --cached)")
    scope_group.add_argument("--working", action="store_true", help="Audit working tree vs HEAD (default)")
    scope_group.add_argument("--base", metavar="REF", help="Audit branch diff against base ref (git diff REF...HEAD)")
    scope_group.add_argument("--diff-file", metavar="PATH", help="Audit a unified diff file (use '-' for stdin)")

    parser.add_argument("--repo", default=".", help="Path to git repository (default: current directory)")
    parser.add_argument("--max-files", type=int, default=15, help="Warn if changed files exceed N (default: 15)")
    parser.add_argument("--max-lines", type=int, default=600, help="Warn if changed lines exceed N (default: 600)")
    parser.add_argument(
        "--allow-path",
        action="append",
        default=[],
        help="Restrict edits to this path prefix (repeatable; edits outside are CRITICAL)",
    )
    parser.add_argument("--strict", action="store_true", help="Exit 1 on WARNING findings as well as CRITICAL")
    parser.add_argument("--json", action="store_true", help="Emit JSON output")
    args = parser.parse_args()

    try:
        if args.diff_file:
            if args.diff_file == "-":
                diff_text = sys.stdin.read()
                scope_label = "stdin unified diff"
            else:
                with open(args.diff_file, "r", encoding="utf-8", errors="replace") as fh:
                    diff_text = fh.read()
                scope_label = f"diff file ({args.diff_file})"
        elif args.staged:
            diff_text = run_git_diff(args.repo, "staged", None)
            scope_label = "git diff --cached (staged)"
        elif args.base:
            diff_text = run_git_diff(args.repo, "base", args.base)
            scope_label = f"git diff {args.base}...HEAD"
        else:
            diff_text = run_git_diff(args.repo, "working", None)
            scope_label = "git diff HEAD (working tree)"
    except Exception as exc:
        print(f"[ai-diff-audit] ERROR: {exc}", file=sys.stderr)
        return 2

    summary, findings = parse_and_audit_diff(
        diff_text=diff_text,
        max_files=args.max_files,
        max_lines=args.max_lines,
        allow_paths=args.allow_path,
    )

    if args.json:
        payload = {
            "scope": scope_label,
            "summary": summary,
            "findings": [asdict(f) for f in findings],
        }
        print(json.dumps(payload, indent=2))
    else:
        print(format_receipt(scope_label, summary, findings))

    if summary["critical_count"] > 0:
        return 1
    if args.strict and summary["warning_count"] > 0:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
