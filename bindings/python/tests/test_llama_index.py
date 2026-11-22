"""Tests for intakeguard.llama_index (need `make corpus` and llama-index-core)."""

from pathlib import Path

import pytest

pytest.importorskip("llama_index.core")

from llama_index.core import SimpleDirectoryReader  # noqa: E402
from llama_index.core.readers.base import BaseReader  # noqa: E402
from llama_index.core.schema import Document, MetadataMode  # noqa: E402

import intakeguard  # noqa: E402
from intakeguard.llama_index import (NoLoaderConfigured, IntakeGuardDirectoryReader, IntakeGuardReader,  # noqa: E402
                                  IntakeGuardRejected, simple_directory_kwargs)

REPO = Path(__file__).resolve().parents[3]
BUILD = REPO / "corpus" / "build"
POLICY = intakeguard.Policy((REPO / "corpus" / "policies" / "strict.json").read_text())


def fixture(fid: str) -> Path:
    p = BUILD / fid
    if not p.exists():
        pytest.skip("run `make corpus` first")
    return next(p.iterdir())


class Recorder(BaseReader):
    """Records the path and bytes it was given; one Document per file, like most file readers."""
    seen: list = []

    def load_data(self, file, extra_info=None, **kw):
        Recorder.seen.append((str(file), Path(file).read_bytes()))
        return [Document(text="x", metadata={**(extra_info or {}), "file_path": str(file), "page": 0})]


@pytest.fixture(autouse=True)
def _reset():
    Recorder.seen = []


ALL = {m: Recorder() for m in ("application/pdf", "image/jpeg", "image/png", "image/webp")}


def _symlink(link, target, **kw):
    try:
        link.symlink_to(target, **kw)
    except OSError as e:
        if getattr(e, "winerror", None) == 1314:
            pytest.skip("symlink creation not permitted on this Windows account")
        raise


def test_accepted_pdf_loads_inspected_bytes_from_a_private_copy():
    src = fixture("benign-pdf-1page")
    docs = IntakeGuardReader(policy=POLICY, readers=ALL).load_data(src)
    path, data = Recorder.seen[0]
    assert path != str(src) and data == src.read_bytes() and not Path(path).exists()
    md = docs[0].metadata
    assert md["intakeguard_verdict"] == "accepted" and md["file_path"] == str(src) and md["page"] == 0


def test_intakeguard_metadata_is_kept_out_of_embeddings_and_llm_context():
    doc = IntakeGuardReader(policy=POLICY, readers=ALL).load_data(fixture("benign-pdf-1page"))[0]
    for mode in (MetadataMode.EMBED, MetadataMode.LLM):
        assert "intakeguard_" not in doc.get_content(metadata_mode=mode)
    assert "page" in doc.get_content(metadata_mode=MetadataMode.EMBED)  # the reader's own metadata stays
    keep = IntakeGuardReader(policy=POLICY, readers=ALL, exclude_intakeguard_metadata=False).load_data(
        fixture("benign-pdf-1page"))[0]
    assert "intakeguard_verdict" in keep.get_content(metadata_mode=MetadataMode.EMBED)


def test_rejected_raises_or_skips_and_never_reaches_the_reader():
    src = fixture("pdf-active-openaction-js")
    with pytest.raises(IntakeGuardRejected) as e:
        IntakeGuardReader(policy=POLICY, readers=ALL).load_data(src)
    assert "PDF_ACTIVE_CONTENT" in e.value.report.data["reasonCodes"]
    assert IntakeGuardReader(policy=POLICY, readers=ALL, on_reject="skip").load_data(src) == []
    assert Recorder.seen == []


def test_transformed_image_is_the_output_renamed_from_output_mime():
    r = IntakeGuardReader(policy=POLICY, readers=ALL)
    docs = r.load_data(fixture("benign-webp-lossy-alpha-to-png"))
    path, data = Recorder.seen[0]
    assert Path(path).suffix == ".png" and data == r.last_report.output
    assert docs[0].metadata["intakeguard_output_mime"] == "image/png"


def test_missing_reader_is_its_own_error():
    with pytest.raises(NoLoaderConfigured):
        IntakeGuardReader(policy=POLICY, readers={}).load_data(fixture("benign-pdf-1page"))


def test_directory_reader_statuses(tmp_path):
    for fid, name in [("benign-pdf-1page", "a.pdf"), ("pdf-encrypted", "b.pdf"),
                      ("benign-webp-lossy-to-jpeg", "c.webp"), ("benign-png-8x8", "d.png")]:
        (tmp_path / name).write_bytes(fixture(fid).read_bytes())
    readers = {k: v for k, v in ALL.items() if k != "image/png"}
    rd = IntakeGuardDirectoryReader(tmp_path, policy=POLICY, readers=readers)
    docs = rd.load_data()
    assert [(Path(r.path).name, r.status) for r in rd.results] == [
        ("a.pdf", "loaded"), ("b.pdf", "rejected"), ("c.webp", "loaded"), ("d.png", "no-loader")]
    assert len(docs) == 2 and docs[1].metadata["file_name"] == "c.webp"


def test_directory_reader_stays_inside_the_inbox(tmp_path):
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    secret = tmp_path / "secret.pdf"
    secret.write_bytes(fixture("benign-pdf-1page").read_bytes())
    _symlink(inbox / "innocent.pdf", secret)
    rd = IntakeGuardDirectoryReader(inbox, policy=POLICY, readers=ALL)
    assert rd.load_data() == [] and Recorder.seen == []
    assert rd.results[0].status == "skipped-symlink" and rd.results[0].report is None
    rd = IntakeGuardDirectoryReader(inbox, policy=POLICY, readers=ALL, follow_symlinks=True)
    assert rd.load_data() == [] and rd.results[0].status == "skipped-outside"
    with pytest.raises(ValueError):
        IntakeGuardDirectoryReader(inbox, policy=POLICY, readers=ALL, allow_outside=True)


def test_simple_directory_reader_route_never_bypasses_intakeguard(tmp_path):
    (tmp_path / "a.pdf").write_bytes(fixture("benign-pdf-1page").read_bytes())
    (tmp_path / "bad.pdf").write_bytes(fixture("pdf-evasion-js-in-objstm").read_bytes())
    (tmp_path / "notes.txt").write_text("plain text that no IntakeGuard policy allows")
    reader = IntakeGuardReader(policy=POLICY, readers=ALL, on_reject="skip")
    docs = SimpleDirectoryReader(str(tmp_path), **simple_directory_kwargs(reader)).load_data()
    names = [d.metadata.get("file_name") for d in docs]
    assert names == ["a.pdf"], names  # bad.pdf rejected; notes.txt never read by a default reader
    assert docs[0].metadata["intakeguard_verdict"] == "accepted"
