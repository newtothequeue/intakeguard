"""Runs both RAG ingestion examples end to end (`--demo --check`), so CI covers them."""

import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[3]
EX = REPO / "examples" / "python-rag-ingestion"


@pytest.mark.parametrize("script, needs", [("ingest.py", "langchain_core"),
                                            ("ingest_llama_index.py", "llama_index.core")])
def test_example_demo_check(tmp_path, script, needs):
    pytest.importorskip(needs)
    pytest.importorskip("pypdf")
    if not (REPO / "corpus" / "build").exists():
        pytest.skip("run `make corpus` first")
    r = subprocess.run([sys.executable, str(EX / script), "--demo", "--check", "--out", str(tmp_path / "out")],
                       capture_output=True, text=True, timeout=300)
    assert r.returncode == 0, r.stdout[-3000:] + r.stderr[-3000:]
    assert "check: all expectations met" in r.stdout
