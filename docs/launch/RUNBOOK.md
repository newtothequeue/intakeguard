# Launch runbook: IntakeGuard → IntakeGuard 0.1.0a1

Everything below except the steps marked **(owner)** is mechanical. Verified on 2026-11-22 under the IntakeGuard name:
37 Rust tests, 80/80 conformance, 22 Python tests, both demos, `realworld.py` 600/600, the differential run, and
`twine check` PASSED on the wheel and the sdist.

## 1. Accounts and repo: done
The repo is `github.com/newtothequeue/intakeguard` (fresh history, one commit). Still to do: a PyPI account and a
TestPyPI account with 2FA, and a quick trademark search for "IntakeGuard" (a sanity check, not legal advice).

## 2. Before the first release (builder)
Remove the `-bakeoff` suffix from `ENGINE_VERSION` in `core/src/lib.rs`.

## 3. Repo settings (owner, 5 min)
- Settings → General: enable **Discussions**. Create a pinned "What does your upload / ingestion pipeline look like?" thread.
- Settings → Code security: enable **private vulnerability reporting** (SECURITY.md points there).
- Settings → Environments: create `pypi` (**required reviewer: you**) and `testpypi`.
- Topics: `pdf`, `security`, `rag`, `langchain`, `llamaindex`, `sanitization`, `python`, `rust`.

## 4. Trusted publishing (owner, 5 min, no tokens)
On pypi.org → Your account → Publishing → "Add a new pending publisher": project `intakeguard`, owner
`<github-account>`, repo `intakeguard`, workflow `release.yml`, environment `pypi`. Repeat on test.pypi.org with
environment `testpypi`.

## 5. Dry run on TestPyPI
Actions → `release` → Run workflow → target `testpypi`. Every wheel must pass the conformance gate before publish.
Then, in a clean virtualenv:
```bash
pip install -i https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple intakeguard==0.1.0a1
python -c "import intakeguard; print(intakeguard.ENGINE_VERSION)"
```

## 6. Publish (owner approval = the human gate)
```bash
git tag v0.1.0a1 && git push origin v0.1.0a1
```
The workflow builds, gates and then **waits for your approval** on the `pypi` environment. Approve, then check
https://pypi.org/project/intakeguard/.

## 7. Launch (owner reviews and posts)
- `docs/launch/launch-post-draft.md`: Show HN / blog post. It makes security claims, so it's a human gate.
- Post to r/LangChain, r/LocalLLaMA, r/Python; open PRs to "awesome RAG" lists.
- Reply personally to the first ten issues and Discussions posts. The first five pilot users matter more than stars.

## After launch
- Next release: spec 0.1.6 (malformed content strings, ADR 0009) is already specified with fixtures; the builder implements it.
- Ask the first pilot users to run `tools/differential/realworld.py` and `content_syntax_survey.py` on their own
  files and report the summary lines (no file contents).
