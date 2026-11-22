"""Tests for intakeguard.langchain (need `make corpus` and langchain-core)."""

from pathlib import Path

import pytest

pytest.importorskip("langchain_core")

from langchain_core.document_loaders import BaseLoader  # noqa: E402
from langchain_core.documents import Document  # noqa: E402

import intakeguard  # noqa: E402
from intakeguard.langchain import (NoLoaderConfigured, IntakeGuardDirectoryLoader, IntakeGuardLoader,  # noqa: E402
                                IntakeGuardRejected, output_name)

REPO = Path(__file__).resolve().parents[3]
BUILD = REPO / "corpus" / "build"
POLICY = intakeguard.Policy((REPO / "corpus" / "policies" / "strict.json").read_text())


def fixture(fid: str) -> Path:
    p = BUILD / fid
    if not p.exists():
        pytest.skip("run `make corpus` first")
    return next(p.iterdir())


class Recorder(BaseLoader):
    """Records the path and bytes it was given."""
    seen: list = []

    def __init__(self, path):
        self.path = path

    def lazy_load(self):
        Recorder.seen.append((self.path, Path(self.path).read_bytes()))
        yield Document(page_content="x", metadata={})


@pytest.fixture(autouse=True)
def _reset():
    Recorder.seen = []


ALL = {m: Recorder for m in ("application/pdf", "image/jpeg", "image/png", "image/webp")}


def test_accepted_pdf_loads_inspected_bytes_from_a_private_copy(tmp_path):
    src = fixture("benign-pdf-1page")
    docs = IntakeGuardLoader(src, policy=POLICY, loaders=ALL).load()
    assert docs and docs[0].metadata["intakeguard_verdict"] == "accepted"
    assert docs[0].metadata["source"] == str(src)
    path, data = Recorder.seen[0]
    assert path != str(src) and data == src.read_bytes()
    assert not Path(path).exists()  # work file removed


def test_rejected_pdf_raises_or_skips_and_never_reaches_the_loader():
    src = fixture("pdf-active-openaction-js")
    with pytest.raises(IntakeGuardRejected) as e:
        IntakeGuardLoader(src, policy=POLICY, loaders=ALL).load()
    assert "PDF_ACTIVE_CONTENT" in e.value.report.data["reasonCodes"]
    assert IntakeGuardLoader(src, policy=POLICY, loaders=ALL, on_reject="skip").load() == []
    assert Recorder.seen == []


def test_transformed_image_is_the_output_renamed_from_output_mime():
    src = fixture("benign-webp-lossy-to-jpeg")
    ld = IntakeGuardLoader(src, policy=POLICY, loaders=ALL)
    docs = ld.load()
    path, data = Recorder.seen[0]
    assert Path(path).suffix == ".jpg"
    assert data == ld.report.output and data != src.read_bytes()
    assert docs[0].metadata["intakeguard_output_mime"] == "image/jpeg"


def test_missing_loader_is_its_own_error():
    with pytest.raises(NoLoaderConfigured):
        IntakeGuardLoader(fixture("benign-pdf-1page"), policy=POLICY, loaders={}).load()


def test_directory_loader_records_every_file(tmp_path):
    for fid, name in [("benign-pdf-1page", "a.pdf"), ("pdf-encrypted", "b.pdf"), ("benign-webp-lossy-alpha-to-png", "c.webp")]:
        (tmp_path / name).write_bytes(fixture(fid).read_bytes())
    ld = IntakeGuardDirectoryLoader(tmp_path, policy=POLICY, loaders=ALL)
    docs = ld.load()
    assert [Path(r.path).name for r in ld.results] == ["a.pdf", "b.pdf", "c.webp"]
    assert [r.report.verdict for r in ld.results] == ["accepted", "rejected", "transformed"]
    assert [r.status for r in ld.results] == ["loaded", "rejected", "loaded"]
    assert [r.documents for r in ld.results] == [1, 0, 1]
    assert len(docs) == 2 and Path(Recorder.seen[1][0]).suffix == ".png"


def test_no_loader_is_recorded_distinctly(tmp_path):
    (tmp_path / "a.pdf").write_bytes(fixture("benign-pdf-1page").read_bytes())
    ld = IntakeGuardDirectoryLoader(tmp_path, policy=POLICY, loaders={"image/png": Recorder})
    assert ld.load() == []
    assert [(r.status, r.report.verdict) for r in ld.results] == [("no-loader", "accepted")]


# ---- review-pr3-4 finding 1: never read outside the inbox

def _symlink(link, target, **kw):
    """Create a symlink; skip only if this platform/user can't create symlinks at all (Windows
    without SeCreateSymbolicLinkPrivilege, WinError 1314). Any other error fails the test."""
    try:
        link.symlink_to(target, **kw)
    except OSError as e:
        if getattr(e, "winerror", None) == 1314:
            pytest.skip("symlink creation not permitted on this Windows account")
        raise


def _inbox_with_outside_link(tmp_path):
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    secret = tmp_path / "secret-scan.pdf"
    secret.write_bytes(fixture("benign-pdf-1page").read_bytes())
    _symlink(inbox / "innocent.pdf", secret)
    return inbox, secret


def test_symlink_out_of_the_inbox_is_never_read(tmp_path):
    inbox, _ = _inbox_with_outside_link(tmp_path)
    ld = IntakeGuardDirectoryLoader(inbox, policy=POLICY, loaders=ALL)
    assert ld.load() == [] and Recorder.seen == []
    assert [(Path(r.path).name, r.status, r.report) for r in ld.results] == [("innocent.pdf", "skipped-symlink", None)]
    # Even with follow_symlinks=True, a target outside the inbox is skipped.
    ld = IntakeGuardDirectoryLoader(inbox, policy=POLICY, loaders=ALL, follow_symlinks=True)
    assert ld.load() == [] and Recorder.seen == []
    assert ld.results[0].status == "skipped-outside"
    # Reading outside the inbox takes both explicit opt-ins.
    with pytest.raises(ValueError):
        IntakeGuardDirectoryLoader(inbox, policy=POLICY, loaders=ALL, allow_outside=True)
    ld = IntakeGuardDirectoryLoader(inbox, policy=POLICY, loaders=ALL, follow_symlinks=True, allow_outside=True)
    assert len(ld.load()) == 1 and ld.results[0].status == "loaded"


def test_symlink_inside_the_inbox_is_opt_in(tmp_path):
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    (inbox / "real.pdf").write_bytes(fixture("benign-pdf-1page").read_bytes())
    _symlink(inbox / "alias.pdf", inbox / "real.pdf")
    ld = IntakeGuardDirectoryLoader(inbox, policy=POLICY, loaders=ALL)
    ld.load()
    assert {Path(r.path).name: r.status for r in ld.results} == {"alias.pdf": "skipped-symlink", "real.pdf": "loaded"}
    ld = IntakeGuardDirectoryLoader(inbox, policy=POLICY, loaders=ALL, follow_symlinks=True)
    ld.load()
    assert {Path(r.path).name: r.status for r in ld.results} == {"alias.pdf": "loaded", "real.pdf": "loaded"}


def test_symlinked_directory_is_not_recursed_into(tmp_path):
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "private.pdf").write_bytes(fixture("benign-pdf-1page").read_bytes())
    _symlink(inbox / "sub", elsewhere, target_is_directory=True)
    for follow in (False, True):
        Recorder.seen = []
        ld = IntakeGuardDirectoryLoader(inbox, policy=POLICY, loaders=ALL, recursive=True, follow_symlinks=follow)
        assert ld.load() == [] and Recorder.seen == []
        assert all(r.status in ("skipped-symlink", "skipped-outside") for r in ld.results)


def test_fifo_is_skipped_without_blocking(tmp_path):
    import os
    if not hasattr(os, "mkfifo"):
        pytest.skip("no FIFOs on this platform")
    os.mkfifo(tmp_path / "pipe.pdf")
    ld = IntakeGuardDirectoryLoader(tmp_path, policy=POLICY, loaders=ALL)
    assert ld.load() == []
    assert ld.results[0].status == "skipped-not-regular"


def test_single_file_loader_can_refuse_symlinks(tmp_path):
    inbox, _ = _inbox_with_outside_link(tmp_path)
    from intakeguard.langchain import NotARegularFile
    with pytest.raises(NotARegularFile):
        IntakeGuardLoader(inbox / "innocent.pdf", policy=POLICY, loaders=ALL, follow_symlinks=False).load()
    assert Recorder.seen == []


def test_output_name():
    assert output_name("logo.webp", "image/png") == "logo.png"
    assert output_name("a.jpeg", "image/jpeg") == "a.jpeg"
    assert output_name("noext", "application/pdf") == "noext.pdf"
