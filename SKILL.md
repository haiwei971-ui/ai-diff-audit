---
name: ai-diff-audit
description: >-
  Read-only Git diff auditor for AI coding agents (Claude Code, Cursor, Codex, Copilot).
  Use before committing or opening a PR to catch AI diff cheats: skipped tests, deleted
  test assertions, swallowed exceptions, '|| true' exit-code masking, silenced linters,
  leaked secrets, debug residue, hidden CRLF endings, and out-of-scope blast-radius drift.
---

# ai-diff-audit — Catch AI Diff Cheats Before Commit or PR

Run a deterministic, zero-dependency, strictly read-only audit on your `git diff` before committing, pushing, or claiming a PR is ready for review.

> Built & maintained by **Harvey | Tech Builder** (`@lxy71` on X · [harveyi.com](https://harveyi.com) · [GitHub](https://github.com/haiwei971-ui)).

---

## Why This Skill Exists

When AI coding agents hit a stubborn test or type error, they sometimes optimize for a green exit code instead of a real fix:
- Adding `@pytest.mark.skip`, `it.skip(...)`, `t.Skip()`, or `#[ignore]`
- Quietly deleting `assert` / `expect(...)` lines from test files
- Swallowing failures with `except: pass`, empty `catch {}`, or `|| true`
- Silencing checks with `# type: ignore`, `# noqa`, `// @ts-ignore`, or `eslint-disable`
- Drifting outside the requested module into lockfiles, CI workflows, or unrelated directories

`ai-diff-audit` inspects **only the changed lines in your diff** (never noisy legacy code) using pure Python 3 stdlib + Bash and emits an objective **PR Verification Receipt**.

---

## When to Run This Skill

Always run `scripts/ai-diff-audit.sh` **before**:
1. Running `git commit` on AI-generated edits (`--staged`).
2. Opening a Pull Request or handing a branch to a human reviewer (`--base main`).
3. Finishing a scoped refactor where only specific folders should be touched (`--allow-path`).
4. Claiming `"All tests pass — ready to merge"` after fixing a failing test suite.

---

## Commands (Zero Dependencies — Pure Python 3 Stdlib & Bash)

```bash
# 1. Audit working tree changes vs HEAD (default)
bash scripts/ai-diff-audit.sh --working

# 2. Audit staged changes right before git commit
bash scripts/ai-diff-audit.sh --staged

# 3. Audit an entire feature branch before opening a PR
bash scripts/ai-diff-audit.sh --base main

# 4. Enforce strict scope — fail if the agent touched anything outside allowed paths
bash scripts/ai-diff-audit.sh --working --allow-path src/payments --allow-path tests/payments

# 5. Strict CI / JSON mode (fails on warnings too, including linter suppressions & blast radius)
bash scripts/ai-diff-audit.sh --base main --strict --json

# 6. Audit a patch file or piped diff directly
git diff main...HEAD | bash scripts/ai-diff-audit.sh --diff-file -
```

### Options
- `--max-files <N>` — Warn when changed files exceed `N` (default: `15`).
- `--max-lines <N>` — Warn when added + removed lines exceed `N` (default: `600`).
- `--allow-path <PREFIX>` — Repeatable. Any modified file outside the listed prefixes is flagged `CRITICAL` (`OUT_OF_SCOPE_EDIT`).
- `--strict` — Return exit code `1` on `WARNING` findings as well as `CRITICAL`.
- `--json` — Emit structured JSON for CI gates or hooks.

### Exit Codes
- `0` — Clean diff (or warnings only when `--strict` is not set).
- `1` — One or more `CRITICAL` findings detected (or any `WARNING` under `--strict`).
- `2` — Invalid arguments or `git diff` execution error.

---

## PR Verification Receipt Protocol

When reporting task completion after running this skill, include the raw `AI DIFF AUDIT RECEIPT` block in your summary or PR description:
1. Exact audit scope (`--staged`, `--working`, or `--base main`).
2. Blast radius (`files_changed`, `+added / -removed` lines) and test assertion delta (`+added / -removed` assertions).
3. Confirmation that `critical: 0` (and explicit explanation for any remaining warnings such as lockfile updates or intentional suppressions).

See `references/cheat-patterns-cheatsheet.md` for the full rule catalog.

---

## More Verified Receipts & Open-Source Guards

- Interactive receipts & guard snippets: **https://harveyi.com**
- Companion skill (`AI Verify Guards`): **https://github.com/haiwei971-ui/ai-verify-guards**
- Daily locally-verified receipts on X: **https://x.com/lxy71**
