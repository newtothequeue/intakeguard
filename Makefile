PY ?= python3

.PHONY: check corpus clean core wheel bakeoff fuzz realworld

check:
	$(PY) tools/corpus-verify/verify.py

corpus:
	$(PY) tools/corpus-verify/verify.py --build-only

# --- ADR 0002 native Rust candidate
core:
	cargo test --release -p intakeguard-core
	cargo build --release -p intakeguard-core --example inspect_file

wheel:
	cd bindings/python && maturin build --release -o ../../target/wheels

bakeoff: corpus core wheel
	$(PY) -m pip install --force-reinstall target/wheels/*.whl
	$(PY) tools/benchmark/bakeoff.py

# Independent real-file sweep (verification role). Usage: make realworld PATHS="~/Downloads ~/Documents"
PATHS ?=
realworld:
	$(PY) tools/differential/realworld.py $(if $(PATHS),$(PATHS),--sample) --quiet

clean:
	rm -rf corpus/build target

# --- fuzzing (nightly + cargo-fuzz; see tools/fuzz/README.md). Usage: make fuzz T=pdf SECS=300
T ?= sanitize_any
SECS ?= 60
fuzz: corpus
	$(PY) tools/fuzz/seed.py
	cargo +nightly fuzz run -O --fuzz-dir tools/fuzz $(T) -- -max_total_time=$(SECS) -rss_limit_mb=2048 -timeout=10 \
		$(if $(wildcard tools/fuzz/dict/$(T).dict),-dict=tools/fuzz/dict/$(T).dict,)
