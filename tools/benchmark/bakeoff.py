#!/usr/bin/env python3
"""ADR 0002 bake-off harness for the native Rust candidate (PyO3 binding).

  python tools/benchmark/bakeoff.py [--out docs/conformance/bakeoff-native-rust.json] [--quick]

Requires the wheel to be installed (see bindings/python/README.md) and `make corpus`.
Measures: corpus conformance (two scores, see below), report schema validity, p50/p95 latency,
peak RSS per fixture (fresh subprocess each), cancellation latency, maxProcessingMs overshoot,
over-limit stream behavior, and a seeded mutation smoke run (panics / timeouts / allocation).

This tool never edits manifest.jsonl. Expected outcomes are human-owned.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import platform
import random
import os
import statistics
import subprocess
import sys
import threading
import time
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator

import intakeguard
from outputs import check as check_outputs, header_dims, try_pil

ROOT = Path(__file__).resolve().parents[2]
CORPUS = ROOT / "corpus"
BUILD = CORPUS / "build"
CHECKS_SKIP_OK = {"scanner"}  # "not applicable" when no scanners are configured


def load():
    rows = [json.loads(l) for l in (CORPUS / "manifest.jsonl").read_text().splitlines() if l.strip()]
    policies = {p.stem: p.read_text() for p in (CORPUS / "policies").glob("*.json")}
    schema = Draft202012Validator(json.loads((ROOT / "spec/verdict.schema.json").read_text()))
    codes = {c["id"] for c in yaml.safe_load((ROOT / "spec/reasons.yaml").read_text())["codes"]}
    return rows, policies, schema, codes


def fixture(r) -> bytes:
    p = BUILD / r["id"] / r["file"]
    if not p.exists():
        sys.exit(f"missing {p}; run `make corpus` first")
    return p.read_bytes()


def judge(r, rep: dict, decision: str, *, use_decision: bool) -> list[str]:
    """Compare a report with the manifest row. Returns a list of mismatches (empty = pass)."""
    exp = r["expected"]
    bad = []
    want = exp["verdict"]
    if use_decision:
        got = {"accept": "accepted", "transform": "transformed", "reject": "rejected", "error": "rejected"}[decision]
        codes = [c for c in rep["reasonCodes"] if not (c == "UNSUPPORTED_FEATURE" and decision == "transform")]
    else:
        got = "rejected" if rep["verdict"] == "error" else rep["verdict"]
        codes = rep["reasonCodes"]
    if got != want:
        bad.append(f"verdict {got} != {want}")
    if "detectedMime" in exp:
        dm = (rep.get("detectedType") or {}).get("mime")
        if dm != exp["detectedMime"]:
            bad.append(f"detectedMime {dm} != {exp['detectedMime']}")
    for c in exp.get("reasonCodesInclude", []):
        if c not in codes:
            bad.append(f"missing {c}")
    if exp.get("reasonCodesAnyOf") and not set(exp["reasonCodesAnyOf"]) & set(codes):
        bad.append(f"none of {exp['reasonCodesAnyOf']}")
    for c in exp.get("reasonCodesExclude", []):
        if c in codes:
            bad.append(f"forbidden {c}")
    return bad


def invariants(rep: dict, schema, codes, decision: str | None = None, output: bytes | None = None,
               sanitized: bool = True) -> list[str]:
    bad = [f"schema: {e.message}" for e in schema.iter_errors(rep)]
    if rep["verdict"] == "transformed":
        o = rep.get("output") or {}
        if output is None:
            bad.append("transformed without output bytes")
        else:
            if hashlib.sha256(output).hexdigest() != o.get("sha256") or len(output) != o.get("bytes"):
                bad.append("output bytes don't match report.output sha256/bytes")
        if o.get("sha256") == rep["original"]["sha256"]:
            bad.append("output.sha256 equals original.sha256")
        if not any(t["id"] == "image.decode-reencode" for t in rep.get("transformations", [])):
            bad.append("transformed without image.decode-reencode transformation")
    elif output is not None or rep.get("output") is not None:
        bad.append(f"output present with verdict {rep['verdict']}")
    if not sanitized and rep["verdict"] == "transformed":
        bad.append("inspect() returned transformed")
    bad += [f"unregistered code {c}" for c in rep["reasonCodes"] if c not in codes]
    if rep["verdict"] == "accepted":
        for c in rep["checks"]:
            if c["status"] == "failed" or (c["status"] == "skipped" and c["id"] not in CHECKS_SKIP_OK):
                bad.append(f"accepted with check {c['id']}={c['status']}")
    if rep["verdict"] == "rejected" and not rep["reasonCodes"]:
        bad.append("rejected without reason codes")
    if decision is not None and rep.get("policyDecision") != decision:
        bad.append(f"report policyDecision {rep.get('policyDecision')} != binding decision {decision}")
    if rep.get("policyDecision") in ("reject", "error") and rep["verdict"] in ("accepted", "transformed"):
        bad.append(f"policyDecision {rep['policyDecision']} but verdict {rep['verdict']}")
    if rep["original"].get("complete") is False and rep["verdict"] in ("accepted", "transformed"):
        bad.append("incomplete original but usable verdict")
    return bad


def pct(xs, q):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(round(q / 100 * (len(xs) - 1))))]


NATIVE = ROOT / "target/release/examples" / ("inspect_file.exe" if os.name == "nt" else "inspect_file")


def self_peak_mib() -> float | None:
    try:
        import resource
        import platform
        v = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return round(v / (1024 * 1024 if platform.system() == "Darwin" else 1024), 1)
    except ImportError:
        return None


def native(r, policy_path: Path, iters: int, path: Path | None = None) -> dict:
    """Native run in a fresh process: peak RSS of one sanitize (reported by the child for itself),
    then latency over `iters`."""
    if not NATIVE.exists():
        sys.exit(f"missing {NATIVE}; run `cargo build --release -p intakeguard-core --example inspect_file`")
    p = path or BUILD / r["id"] / r["file"]
    def go(n):
        out = subprocess.run([str(NATIVE), str(policy_path), str(p), r["file"], r["claimedMime"] or "-", str(n), "sanitize"],
                             capture_output=True, text=True)
        if out.returncode != 0:
            raise RuntimeError(f"{NATIVE.name} exited {out.returncode}: {out.stderr[-2000:]}")
        return json.loads(out.stdout)
    one, many = go(1), go(iters)
    # The child measures its own peak (VmHWM on Linux, getrusage on macOS, K32GetProcessMemoryInfo on
    # Windows), so the parent's memory never leaks into the number. 0 means unmeasured -> None.
    peak = one["rssPeakKiB"] or None
    delta = round((one["rssPeakKiB"] - one["rssBeforeKiB"]) / 1024, 2) if peak else None
    return {"peakMiB": round(peak / 1024, 2) if peak else None, "deltaMiB": delta,
            "nativeLatencyMs": {"p50": round(many["p50"], 4), "p95": round(many["p95"], 4), "n": many["n"]}}


class Endless:
    """A file-like object producing an unbounded stream; records how much was pulled."""

    def __init__(self, head: bytes):
        self.head, self.pulled = head, 0

    def read(self, n: int) -> bytes:
        if self.pulled < len(self.head):
            b = self.head[self.pulled:self.pulled + n]
        else:
            b = b"\x00" * n
        self.pulled += len(b)
        return b


def mutate(rng: random.Random, d: bytes) -> bytes:
    b = bytearray(d)
    op = rng.randrange(5)
    if op == 0 and b:  # bit flips
        for _ in range(rng.randint(1, 8)):
            i = rng.randrange(len(b)); b[i] ^= 1 << rng.randrange(8)
    elif op == 1 and b:  # truncate
        del b[rng.randrange(len(b)):]
    elif op == 2 and b:  # random bytes at random place
        i = rng.randrange(len(b)); b[i:i] = rng.randbytes(rng.randint(1, 64))
    elif op == 3 and len(b) > 4:  # interesting integers
        i = rng.randrange(len(b) - 4); b[i:i + 4] = rng.choice([b"\xff\xff\xff\xff", b"\x7f\xff\xff\xff", b"\x00\x00\x00\x00", b"\x80\x00\x00\x00"])
    else:  # duplicate a slice
        if b:
            i = rng.randrange(len(b)); j = min(len(b), i + rng.randint(1, 256)); b[j:j] = b[i:j]
    return bytes(b)


def photo_like(w: int, h: int):
    """Deterministic smooth gradient + texture (compresses like a photo, not like noise)."""
    from PIL import Image, ImageFilter
    small = Image.frombytes("RGB", (w // 16, h // 16), random.Random(7).randbytes((w // 16) * (h // 16) * 3))
    base = small.resize((w, h), Image.BICUBIC)
    tex = Image.effect_noise((w, h), 24).convert("RGB")
    return Image.blend(base, tex, 0.15).filter(ImageFilter.SMOOTH)


def transform_perf(strict_src: str, quick: bool) -> list[dict]:
    import tempfile
    out = []
    sizes = [(4000, 3000)] if quick else [(1920, 1080), (4000, 3000), (6000, 6000)]
    tmp = Path(tempfile.mkdtemp(prefix="sf-perf-"))
    pol_path = tmp / "strict.json"
    big = json.loads(strict_src)
    big["limits"]["maxBytes"] = 200 * 1024 * 1024  # let large PNGs in; other limits stay strict
    pol_path.write_text(json.dumps(big))
    for (w, h) in sizes:
        im = photo_like(w, h)
        for fmt, mime, kw in [("JPEG", "image/jpeg", {"quality": 90}), ("PNG", "image/png", {}),
                              ("WEBP", "image/webp", {"quality": 85}), ("WEBP", "image/webp", {"lossless": True})]:
            buf = io.BytesIO()
            im.save(buf, fmt, **kw)
            data = buf.getvalue()
            name = f"{w}x{h}-{fmt.lower()}{'-lossless' if kw.get('lossless') else ''}"
            p = tmp / f"{name}.{fmt.lower()}"
            p.write_bytes(data)
            fake = {"id": name, "file": p.name, "claimedMime": mime}
            nat = native(fake, pol_path, 1 if (quick or w * h > 20e6) else 3, path=p)
            r = intakeguard.sanitize(data, intakeguard.Policy(big), filename=p.name, mime=mime)
            rs = intakeguard.sanitize(data, intakeguard.Policy(strict_src), filename=p.name, mime=mime)
            out.append({"image": name, "inBytes": len(data), "verdict": r.verdict, "codes": r.data["reasonCodes"],
                        "outBytes": len(r.output) if r.output else None,
                        "nativeMs": nat["nativeLatencyMs"]["p50"], "peakRssMiB": nat["peakMiB"],
                        "strictPolicy": {"verdict": rs.verdict, "codes": rs.data["reasonCodes"]}})
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(ROOT / "docs/conformance/bakeoff-native-rust.json"))
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--gate", action="store_true",
                    help="exit 1 on invariant violations, panics, or pre-transform decision mismatches")
    args = ap.parse_args()
    rows, policy_src, schema, codes = load()
    pols = {k: intakeguard.Policy(v) for k, v in policy_src.items()}
    res: dict = {"engine": intakeguard.ENGINE_VERSION, "python": platform.python_version(),
                 "platform": f"{platform.system()} {platform.machine()}", "cpu": platform.processor() or platform.machine()}

    # ---- conformance + invariants (bytes API and streaming API must agree)
    fixtures = []
    for r in rows:
        data = fixture(r)
        kw = dict(filename=r["file"], mime=r["claimedMime"])
        pol = pols[r["policy"]]
        rb = intakeguard.sanitize(data, pol, **kw)
        rs = intakeguard.sanitize(io.BytesIO(data), pol, **kw)
        ri = intakeguard.inspect(data, pol, **kw)
        rep = rb.data
        inv = (invariants(rep, schema, codes, rb.decision, rb.output)
               + invariants(rs.data, schema, codes, rs.decision, rs.output)
               + invariants(ri.data, schema, codes, ri.decision, ri.output, sanitized=False))
        if (rs.verdict, rs.data["reasonCodes"], rs.output) != (rb.verdict, rep["reasonCodes"], rb.output):
            inv.append(f"stream API disagrees: {rs.verdict} {rs.data['reasonCodes']}")
        if ri.decision != rb.decision:
            inv.append(f"inspect() decision {ri.decision} != sanitize() decision {rb.decision}")
        # Report.safe_bytes(): output for transformed, the original for accepted, raise otherwise.
        try:
            sb = rb.safe_bytes(data)
            if rb.verdict == "transformed" and sb != rb.output:
                inv.append("safe_bytes() did not return the output")
            elif rb.verdict == "accepted" and sb != data:
                inv.append("safe_bytes() did not return the original")
            elif rb.verdict not in ("transformed", "accepted"):
                inv.append(f"safe_bytes() returned bytes for verdict {rb.verdict}")
        except intakeguard.Rejected:
            if rb.verdict in ("transformed", "accepted"):
                inv.append(f"safe_bytes() raised for verdict {rb.verdict}")
        if rb.verdict == "accepted":
            try:
                rb.safe_bytes(data + b"x")
                inv.append("safe_bytes() accepted bytes that were not inspected")
            except intakeguard.Rejected:
                pass
        out_bad, out_info = [], None
        exp = r["expected"]
        if "outputMime" in exp and (rep.get("output") or {}).get("mime") != exp["outputMime"]:
            out_bad.append(f"output mime {(rep.get('output') or {}).get('mime')} != {exp['outputMime']}")
        if "outputDimensions" in exp:
            dims = header_dims(rb.output) if rb.output else None
            pil, _ = try_pil(rb.output) if rb.output else (None, None)
            if dims is None or list(dims) != exp["outputDimensions"] or pil is None or list(pil.size) != exp["outputDimensions"]:
                out_bad.append(f"output dimensions {dims} (Pillow {pil.size if pil else None}) != {exp['outputDimensions']}")
        assertions = r["expected"].get("outputAssertions", [])
        if assertions:
            if rb.output is None:
                out_bad.append("no output artifact")
            else:
                ob, out_info = check_outputs(assertions, data, rb.output, rep["output"]["mime"],
                                                  lambda b, pol=pol, m=rep["output"]["mime"]: intakeguard.sanitize(b, pol, mime=m))
                out_bad += ob
        fixtures.append({
            "id": r["id"], "review": r["review"]["status"], "expected": r["expected"]["verdict"],
            "verdict": rep["verdict"], "decision": rb.decision, "reasonCodes": rep["reasonCodes"],
            "reportMismatches": judge(r, rep, rb.decision, use_decision=False) + out_bad,
            "outputAssertionFailures": out_bad, "output": out_info,
            "decisionMismatches": judge(r, rep, rb.decision, use_decision=True),
            "invariantViolations": inv,
            "resourceBounds": r["expected"].get("resourceBounds"),
        })
    n = len(fixtures)
    res["conformance"] = {
        "fixtures": n,
        "reviewed": sum(f["review"] == "reviewed" for f in fixtures),
        "reportPass": sum(not f["reportMismatches"] for f in fixtures),
        "decisionPass": sum(not f["decisionMismatches"] for f in fixtures),
        "invariantViolations": sum(len(f["invariantViolations"]) for f in fixtures),
        "outputAssertions": sum(len(r["expected"].get("outputAssertions", [])) for r in rows),
        "outputAssertionFailures": sum(len(f["outputAssertionFailures"]) for f in fixtures),
    }

    # ---- latency (in-process, bytes API, GIL released inside)
    iters_small, iters_big = (50, 5) if args.quick else (1000, 30)
    for f, r in zip(fixtures, rows):
        data = fixture(r)
        pol = pols[r["policy"]]
        it = iters_big if len(data) > 100_000 else iters_small
        t0 = time.perf_counter()
        intakeguard.sanitize(data, pol, filename=r["file"], mime=r["claimedMime"])
        first = time.perf_counter() - t0
        if first > 0.2:  # slow fixtures (e.g. 36 MP): keep the run bounded
            it = 3
        f["_iters"] = it
        ts = []
        for _ in range(it):
            t0 = time.perf_counter_ns()
            intakeguard.sanitize(data, pol, filename=r["file"], mime=r["claimedMime"])
            ts.append((time.perf_counter_ns() - t0) / 1e6)
        f["latencyMs"] = {"p50": round(pct(ts, 50), 4), "p95": round(pct(ts, 95), 4), "n": it}

    # ---- peak RSS and native latency (fresh native process per fixture, no interpreter)
    for f, r in zip(fixtures, rows):
        f["rss"] = native(r, CORPUS / "policies" / f"{r['policy']}.json", f.pop("_iters"))
        rb_ = f["resourceBounds"] or {}
        # An RSS bound that couldn't be measured is not a pass.
        f["withinBounds"] = (("maxPeakRssMiB" not in rb_ or (f["rss"]["peakMiB"] is not None
                                                            and f["rss"]["peakMiB"] <= rb_["maxPeakRssMiB"]))
                             and ("maxProcessingMs" not in rb_ or f["latencyMs"]["p95"] <= rb_["maxProcessingMs"]))
    res["pythonProcessPeakRssMiB"] = self_peak_mib()

    # ---- cancellation: start the flate bomb with a huge budget, cancel after 5 ms
    bomb = next(r for r in rows if r["id"] == "pdf-bomb-flate")
    big = json.loads(policy_src["strict"])
    big["limits"]["maxDecompressedBytes"] = 1 << 40
    big["limits"]["maxProcessingMs"] = 600_000
    bigpol = intakeguard.Policy(big)
    data = fixture(bomb)
    t0 = time.perf_counter()
    full = intakeguard.inspect(data, bigpol, filename="document.pdf")
    full_ms = (time.perf_counter() - t0) * 1000
    # Each run: a thread inspects the bomb; the main thread cancels after a short delay. A run still
    # going when cancel was set must end as error/ENGINE_CANCELLED, never usable. Two outcomes are not
    # failures:
    # - "finished first": the run had already returned before cancel was set (fast machines);
    # - "finished before noticing": cancel was set while the engine was past its last check. The
    #   report is then a complete run, identical in verdict, codes and every check to the uncancelled
    #   run. A run the engine did abort can only be `error`, so nothing partial can pass this way.
    # At least half the runs must actually be cancelled.
    def _sig(rep):
        d = rep.data
        return (d["verdict"], tuple(d["reasonCodes"]), tuple((c["id"], c["status"]) for c in d["checks"]))
    full_sig = _sig(full)
    lat, cancelled_ok, finished_first, late, wrong = [], 0, 0, 0, []
    runs = 6 if args.quick else 20
    for i in range(runs):
        tok = intakeguard.CancelToken()
        box = {}

        def work():
            box["r"] = intakeguard.inspect(data, bigpol, filename="document.pdf", cancel=tok)
            box["t_return"] = time.perf_counter()

        th = threading.Thread(target=work)
        th.start()
        time.sleep(0.001 * (1 + i % 3))  # 1-3 ms: well inside a ~30-60 ms decode
        tc = time.perf_counter()
        tok.cancel()
        th.join()
        rr = box["r"]
        if box["t_return"] < tc:
            finished_first += 1
            continue
        lat.append((box["t_return"] - tc) * 1000)
        if rr.verdict == "error" and rr.data["reasonCodes"] == ["ENGINE_CANCELLED"] and rr.data.get("policyDecision") == "error":
            cancelled_ok += 1
        elif _sig(rr) == full_sig:
            late += 1
        else:
            wrong.append({"verdict": rr.verdict, "codes": rr.data["reasonCodes"]})
    res["cancellation"] = {
        "uncancelledFullDecodeMs": round(full_ms, 1), "uncancelledVerdict": full.verdict,
        "runs": runs, "cancelled": cancelled_ok, "finishedBeforeCancel": finished_first,
        "finishedBeforeNoticingCancel": late,
        "notCancelledAfterCancel": wrong,
        "cancelToReturnMs": ({"p50": round(pct(lat, 50), 3), "p95": round(pct(lat, 95), 3), "max": round(max(lat), 3)}
                             if lat else None),
        "ok": not wrong and cancelled_ok * 2 >= runs,
    }
    # Deadline: same file, maxProcessingMs=10
    tl = dict(big); tl["limits"] = dict(big["limits"], maxProcessingMs=10)
    t0 = time.perf_counter()
    r_tl = intakeguard.inspect(data, intakeguard.Policy(tl), filename="document.pdf")
    res["deadline"] = {"maxProcessingMs": 10, "returnedAfterMs": round((time.perf_counter() - t0) * 1000, 2),
                       "verdict": r_tl.verdict, "codes": r_tl.data["reasonCodes"]}

    # ---- over-limit streams: unbounded input, record bytes pulled
    over = []
    png_head = fixture(next(r for r in rows if r["id"] == "benign-png-8x8"))
    for name, maxb in [("small-limits (4 KiB)", 4096), ("strict (10 MiB)", 10_485_760)]:
        p = json.loads(policy_src["strict"]); p["limits"]["maxBytes"] = maxb
        src = Endless(png_head)
        t0 = time.perf_counter()
        rep = intakeguard.inspect(src, intakeguard.Policy(p), filename="image.png")
        over.append({"policy": name, "maxBytes": maxb, "bytesPulled": src.pulled, "bytesRead": rep.bytes_read,
                     "guaranteeMax(maxBytes+chunk)": maxb + intakeguard.STREAM_CHUNK, "ok": src.pulled <= maxb + intakeguard.STREAM_CHUNK,
                     "verdict": rep.verdict, "codes": rep.data["reasonCodes"],
                     "originalComplete": rep.data["original"].get("complete"),
                     "ms": round((time.perf_counter() - t0) * 1000, 2)})
    res["overLimitStreams"] = over

    # ---- mutation smoke (seeded): panics, timeouts, schema validity, max latency
    rng = random.Random(20261121)
    seeds = [(fixture(r), pols[r["policy"]], r["file"], r["id"]) for r in rows if r["id"] != "pdf-bomb-flate" and r["bytes"] > 0]
    cases = 2000 if args.quick else 30000
    panics, schema_bad, worst, inv_bad = 0, 0, 0.0, 0
    accepted_from: dict[str, int] = {}
    verdicts: dict[str, int] = {}
    t_all = time.perf_counter()
    for i in range(cases):
        d, pol, fname, sid = rng.choice(seeds)
        m = d
        for _ in range(rng.randint(1, 3)):
            m = mutate(rng, m)
        t0 = time.perf_counter()
        rr = intakeguard.sanitize(m, pol, filename=fname)
        rep = rr.data
        worst = max(worst, (time.perf_counter() - t0) * 1000)
        verdicts[rep["verdict"]] = verdicts.get(rep["verdict"], 0) + 1
        if rep["verdict"] == "accepted":
            accepted_from[sid] = accepted_from.get(sid, 0) + 1
        if any("engine panic" in (c.get("detail") or "") for c in rep["checks"]):
            panics += 1
        if i % 10 == 0 and list(schema.iter_errors(rep)):
            schema_bad += 1
        if invariants(rep, schema, codes, rr.decision, rr.output):
            inv_bad += 1
    res["mutationSmoke"] = {"cases": cases, "seed": 20261121, "panics": panics, "schemaInvalidSampled": schema_bad, "invariantViolations": inv_bad,
                            "verdicts": verdicts, "acceptedBySeed": accepted_from, "worstMs": round(worst, 3),
                            "totalS": round(time.perf_counter() - t_all, 2)}

    # ---- transform cost on realistic sizes (synthetic photo-like images made here, not corpus fixtures)
    res["transformPerf"] = transform_perf(policy_src["strict"], quick=args.quick)

    res["fixtures"] = fixtures
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(res, indent=2) + "\n")
    c = res["conformance"]
    print(f"conformance: report {c['reportPass']}/{n}, decision {c['decisionPass']}/{n}, "
          f"invariant violations {c['invariantViolations']}, reviewed fixtures {c['reviewed']}")
    for f in fixtures:
        probs = f["reportMismatches"] + f["invariantViolations"] + ([] if f["withinBounds"] else [f"outside resourceBounds {f['resourceBounds']}"])
        flag = "" if not probs else "  <- " + "; ".join(probs)
        print(f"  {f['id']:32} {f['verdict']:9} dec={f['decision']:9} p50={f['latencyMs']['p50']:8.4f}ms "
              f"p95={f['latencyMs']['p95']:8.4f}ms native p50={f['rss']['nativeLatencyMs']['p50']:8.4f}ms "
              f"rss={f['rss']['peakMiB'] if f['rss']['peakMiB'] is not None else 'n/a'}MiB{flag}")
    print("cancellation:", json.dumps(res["cancellation"]))
    print("deadline:", json.dumps(res["deadline"]))
    print("over-limit:", json.dumps(over))
    print("mutation:", json.dumps(res["mutationSmoke"]))
    print(f"output assertions: {c['outputAssertions'] - c['outputAssertionFailures']}/{c['outputAssertions']} passed")
    for t in res["transformPerf"]:
        print("transform:", json.dumps(t))
    if args.gate and (c["invariantViolations"] or c["decisionPass"] != n or res["mutationSmoke"]["panics"]
                      or c["reportPass"] != n or c["outputAssertionFailures"] or res["mutationSmoke"]["invariantViolations"]
                      or not all(f["withinBounds"] for f in fixtures)
                      or not all(o["ok"] and o["originalComplete"] is False for o in over)
                      or not res["cancellation"]["ok"]):
        print("GATE FAILED")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
