# ai-diff-audit

> **Trust the diff, not the summary.**  
> Zero-dependency, strictly read-only Git diff auditor for **Claude Code**, **Cursor**, **Codex**, and **GitHub Copilot** — catches AI diff cheats before you commit or open a PR.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/Python-3.9%2B%20stdlib-green.svg)](scripts/audit-diff.py)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-Zero-brightgreen.svg)](#)

Built & maintained by **Harvey | Tech Builder** ([harveyi.com](https://harveyi.com) · [@lxy71 on X](https://x.com/lxy71) · Companion repo: [ai-verify-guards](https://github.com/haiwei971-ui/ai-verify-guards)).

---

## Why This Exists

When AI coding agents hit a stubborn test failure or linter error, they often optimize for exit code `0` instead of a real fix:

- Adding `@pytest.mark.skip`, `it.skip(...)`, `t.Skip()`, or `#[ignore]`
- Quietly deleting `assert` / `expect(...)` lines so the test suite turns green
- Swallowing errors with `except: pass`, empty `catch {}`, `set +e`, or `|| true`
- Silencing checks with `# type: ignore`, `# noqa`, `// @ts-ignore`, or `eslint-disable`
- Drifting outside the requested scope into lockfiles, CI workflows, or migrations

`ai-diff-audit` checks changed files and lines in your unified `git diff` using pure Python 3 stdlib + Bash and prints a deterministic **PR Verification Receipt**. It uses adjacent context to catch an existing `except` handler whose body changes to `pass`.

---

## Quick Start

```bash
git clone https://github.com/haiwei971-ui/ai-diff-audit.git

# 1. Audit working tree changes vs HEAD
bash ai-diff-audit/scripts/ai-diff-audit.sh --working

# 2. Audit staged changes before git commit
bash ai-diff-audit/scripts/ai-diff-audit.sh --staged

# 3. Audit an entire branch before opening a PR
bash ai-diff-audit/scripts/ai-diff-audit.sh --base main

# 4. Enforce strict scope (CRITICAL failure if agent touched files outside allowed paths)
bash ai-diff-audit/scripts/ai-diff-audit.sh --working --allow-path src/auth --allow-path tests/auth

# 5. CI / JSON mode (fail on warnings too)
bash ai-diff-audit/scripts/ai-diff-audit.sh --base origin/main --strict --json

# 6. Review a patch supplied by another tool
git diff main...HEAD | bash ai-diff-audit/scripts/ai-diff-audit.sh --diff-file - --json
```

`--working` covers tracked changes, including staged changes. To include a new untracked file, stage it first. `--allow-path` matches the exact path or its descendants and checks both ends of a rename. Deletions, binary files, and permission-only changes count toward scope. A truncated hunk returns exit code 2.

---

## Example Output

```text
=== AI DIFF AUDIT RECEIPT ===
Scope      : git diff HEAD (working tree)
Verdict    : FAIL (critical: 3, warnings: 1)
Blast      : 2 file(s), +11 / -3 lines
Assertions : +0 / -1 in test files

Findings:
  1. [CRITICAL] TEST_SKIP_ADDED @ tests/test_calc.py:4
     Added pytest skip/xfail decorator
     > @pytest.mark.skip(reason="flaky")
  2. [CRITICAL] ERROR_MASKING @ src/calc.py:4
     Added multi-line 'except: pass' swallowing errors
     > except Exception: -> pass
  3. [CRITICAL] DELETED_TEST_ASSERTIONS @ tests/test_calc.py
     Net-deleted 1 assertion(s) in test file (-1 removed / +0 added)
  4. [WARNING] LINTER_SUPPRESSED @ src/calc.py:3
     Added '# type: ignore' silencing type checker
     > return a + b  # type: ignore
=============================
```

---

## What It Checks

| Rule | Severity | What It Catches (Changed Lines Only) |
| :--- | :--- | :--- |
| `TEST_SKIP_ADDED` | `CRITICAL` | `@pytest.mark.skip`, `xfail`, `unittest.skip`, `it.skip`, `xit`, `t.Skip`, `#[ignore]` |
| `DELETED_TEST_ASSERTIONS` | `CRITICAL` | Net-deleted `assert`, `expect(...)`, `assert_eq!`, `t.Error`/`t.Fatal`, including when the whole test file is removed |
| `ERROR_MASKING` | `CRITICAL` | `\|\| true`, `; true`, `set +e`, inline/multi-line `except: pass`, empty `catch {}` |
| `LEAKED_SECRET` | `CRITICAL` | `sk-`, `ghp_`, `github_pat_`, `AKIA`, `xox*`, private key headers, DB password URIs (auto-redacted in output; ignores obvious placeholders) |
| `MERGE_CONFLICT_MARKER` | `CRITICAL` | Unresolved `<<<<<<<`, `=======`, `>>>>>>>` markers |
| `OUT_OF_SCOPE_EDIT` | `CRITICAL` | Modified files outside `--allow-path` prefixes |
| `LINTER_SUPPRESSED` | `WARNING` | `# type: ignore`, `# noqa`, `// @ts-ignore`, `eslint-disable`, `#[allow(...)]` |
| `SENSITIVE_FILE_TOUCHED` | `WARNING` | `.github/workflows/`, `Dockerfile`, lockfiles, `.env*`, `migrations/` |
| `BLAST_RADIUS_FILES` / `LINES` | `WARNING` | Diff exceeding `--max-files` (15) or `--max-lines` (600) |
| `DEBUG_RESIDUE` / `HIDDEN_CRLF` | `WARNING` | `breakpoint()`, `pdb.set_trace()`, `debugger`, non-test `console.log()`, or `\r\n` endings |

---

## Run Tests Locally

A PASS means the diff triggered none of the configured checks. Run the project's tests and review the behavioral changes before merging.

```bash
bash tests/run-tests.sh
```

---

## Agent Skill Support (`SKILL.md`)

This repository includes a standard `SKILL.md` for Claude Code, Cursor, Codex, and Agensi so your coding agent can invoke `ai-diff-audit` automatically before committing or summarizing a PR.

---

## Companion Projects & Daily Receipts

- **Interactive Receipts & Guard Snippets**: [harveyi.com](https://harveyi.com)
- **Companion Repo (Shell & Hook Guards)**: [haiwei971-ui/ai-verify-guards](https://github.com/haiwei971-ui/ai-verify-guards)
- **Daily Verified AI Coding Receipts**: [@lxy71 on X](https://x.com/lxy71)

## License

MIT — see [LICENSE](LICENSE).
