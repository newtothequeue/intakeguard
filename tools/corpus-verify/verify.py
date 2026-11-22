#!/usr/bin/env python3
"""Spec lint + corpus build + oracle consistency checks.

  python tools/corpus-verify/verify.py               # full check (what CI runs)
  python tools/corpus-verify/verify.py --build-only  # just regenerate corpus/build/
  python tools/corpus-verify/verify.py --print-hashes  # show id/sha256/bytes for authoring rows

This tool never rewrites manifest.jsonl. Expected outcomes are human-owned.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[2]
SPEC = ROOT / "spec"
CORPUS = ROOT / "corpus"
GEN_DIR = CORPUS / "generators"
BUILD = CORPUS / "build"

# Reject-severity codes that a policy can downgrade to warnings, so they may appear in accepted/transformed outcomes.
DOWNGRADABLE = {"TYPE_MISMATCH_EXTENSION", "TYPE_MISMATCH_CLAIMED_MIME", "IMAGE_METADATA_PRESENT"}

errors: list[str] = []


def err(msg: str) -> None:
    errors.append(msg)


def load_json(p: Path):
    return json.loads(p.read_text())


def run_generators() -> dict[str, tuple[str, bytes]]:
    sys.path.insert(0, str(GEN_DIR))
    out: dict[str, tuple[str, bytes]] = {}
    for path in sorted(GEN_DIR.glob("*/*.py")):
        rel = path.relative_to(GEN_DIR).as_posix()
        spec = importlib.util.spec_from_file_location(f"gen_{rel.replace('/', '_')[:-3]}", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        for fid, data in mod.generate().items():
            if fid in out:
                err(f"duplicate fixture id {fid} from {rel} and {out[fid][0]}")
            out[fid] = (rel, data)
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--build-only", action="store_true")
    ap.add_argument("--print-hashes", action="store_true")
    args = ap.parse_args()

    # 1. Schemas are valid JSON Schema
    schemas = {}
    for name, p in {"policy": SPEC / "policy.schema.json", "verdict": SPEC / "verdict.schema.json",
                    "manifest": CORPUS / "manifest.schema.json"}.items():
        s = load_json(p)
        Draft202012Validator.check_schema(s)
        schemas[name] = Draft202012Validator(s)

    # 2. Reason registry
    reg = yaml.safe_load((SPEC / "reasons.yaml").read_text())
    codes = {}
    for c in reg["codes"]:
        if c["id"] in codes:
            err(f"reasons.yaml: duplicate id {c['id']}")
        if c["severity"] not in {"reject", "warn", "error"}:
            err(f"reasons.yaml: {c['id']} bad severity")
        codes[c["id"]] = c

    # 3. Policies validate
    policies = {}
    for p in sorted((CORPUS / "policies").glob("*.json")):
        pol = load_json(p)
        for e in schemas["policy"].iter_errors(pol):
            err(f"policy {p.name}: {e.message}")
        policies[p.stem] = pol

    # 4. Example reports validate
    for p in sorted((SPEC / "examples").glob("*.json")):
        rep = load_json(p)
        for e in schemas["verdict"].iter_errors(rep):
            err(f"example {p.name}: {e.message}")
        for rc in rep.get("reasonCodes", []):
            if rc not in codes:
                err(f"example {p.name}: unknown reason code {rc}")

    # 5. Generate twice (determinism), write the build dir
    first = run_generators()
    second = run_generators()
    for fid in first:
        if first[fid][1] != second.get(fid, (None, None))[1]:
            err(f"generator for {fid} is not deterministic")

    if args.print_hashes:
        for fid, (rel, data) in sorted(first.items()):
            print(f"{fid}\t{rel}\t{hashlib.sha256(data).hexdigest()}\t{len(data)}")
        return 0

    rows = [json.loads(l) for l in (CORPUS / "manifest.jsonl").read_text().splitlines() if l.strip()]
    by_id = {}
    for r in rows:
        if r["id"] in by_id:
            err(f"manifest: duplicate id {r['id']}")
        by_id[r["id"]] = r

    # Rebuild from scratch: stale files from earlier runs (e.g. an old <id>.bin written before a manifest
    # row existed) must not linger next to the real fixture, where a consumer could pick them up.
    import shutil
    shutil.rmtree(BUILD, ignore_errors=True)
    BUILD.mkdir(parents=True, exist_ok=True)
    for fid, (rel, data) in first.items():
        fname = by_id.get(fid, {}).get("file", fid + ".bin")
        d = BUILD / fid
        d.mkdir(exist_ok=True)
        (d / fname).write_bytes(data)
    if args.build_only:
        print(f"built {len(first)} fixtures into {BUILD.relative_to(ROOT)}/")
        return 0 if not errors else 1

    # 6. Manifest consistency
    for r in rows:
        for e in schemas["manifest"].iter_errors(r):
            err(f"manifest {r.get('id')}: {e.message}")
        fid = r["id"]
        if fid not in first:
            err(f"manifest {fid}: no generator produced it")
            continue
        rel, data = first[fid]
        if r["generator"] != rel:
            err(f"manifest {fid}: generator is {rel}, row says {r['generator']}")
        if hashlib.sha256(data).hexdigest() != r["sha256"]:
            err(f"manifest {fid}: sha256 drift (generator output changed — needs human re-review)")
        if len(data) != r["bytes"]:
            err(f"manifest {fid}: byte count drift")
        if r["policy"] not in policies:
            err(f"manifest {fid}: unknown policy {r['policy']}")
        exp = r["expected"]
        listed = exp.get("reasonCodesInclude", []) + exp.get("reasonCodesAnyOf", []) + exp.get("reasonCodesExclude", [])
        for rc in listed:
            if rc not in codes:
                err(f"manifest {fid}: unknown reason code {rc}")
        if exp["verdict"] in ("accepted", "transformed"):
            for rc in exp.get("reasonCodesInclude", []):
                if rc in codes and codes[rc]["severity"] != "warn" and rc not in DOWNGRADABLE:
                    err(f"manifest {fid}: {exp['verdict']} outcome includes rejecting code {rc}")
        if exp["verdict"] == "rejected" and not (exp.get("reasonCodesInclude") or exp.get("reasonCodesAnyOf")):
            err(f"manifest {fid}: rejected outcome must name reason codes")
        for k in ("outputAssertions", "outputMime", "outputDimensions"):
            if exp.get(k) and exp["verdict"] != "transformed":
                err(f"manifest {fid}: {k} only valid for transformed")
    for fid in first:
        if fid not in by_id:
            err(f"fixture {fid} has no manifest row (orphan)")

    # 7. Summary
    status = {}
    for r in rows:
        status[r["review"]["status"]] = status.get(r["review"]["status"], 0) + 1
    verdicts = {}
    for r in rows:
        verdicts[r["expected"]["verdict"]] = verdicts.get(r["expected"]["verdict"], 0) + 1
    print(f"spec: 3 schemas ok, {len(codes)} reason codes, {len(policies)} policies")
    print(f"corpus: {len(rows)} fixtures | verdicts {verdicts} | review {status}")
    if errors:
        print(f"\n{len(errors)} error(s):")
        for e in errors:
            print("  ✗", e)
        return 1
    print("✓ all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
