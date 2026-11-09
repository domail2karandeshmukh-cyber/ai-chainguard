# AI-ChainGuard - common commands. Workspace = repository root unless CHAINGUARD_HOME is set.
PY ?= python
export CHAINGUARD_HOME ?= $(CURDIR)

.PHONY: help install keys trust-log mvp demo demo-auto pipeline attacks attacks-fast benchmark trustlog-benchmark figures test test-fast lint api dashboard standalone validate paper up down clean

help:
	@echo "install       install dependencies (CPU PyTorch)"
	@echo "keys          create one Ed25519 key pair per role in keys/"
	@echo "mvp           register -> verify -> tamper -> verify demo"
	@echo "demo          10-minute professor demo, pauses between steps (demo-auto: no pauses)"
	@echo "pipeline      four-stage attested ML pipeline + deployment gateway"
	@echo "attacks       attack scenarios A-G (attacks-fast: all except the slow scenario E)"
	@echo "benchmark     hashing/signing/verification cost vs artifact size"
	@echo "figures       report figures from results/"
	@echo "test          all tests (test-fast skips the backdoor training test)"
	@echo "trust-log     replay and print the signed trust log (v0.4)"
	@echo "trustlog-benchmark  cost of replaying the trust log vs number of records (v0.4)"
	@echo "validate      full validation run -> results/validation_logs (LABEL=\"<machine>\")"
	@echo "paper         regenerate the IEEE paper figures and build paper/signed_is_not_safe.pdf"
	@echo "api           FastAPI on :8000      dashboard  Streamlit on :8501"
	@echo "standalone    dashboard with the API embedded in-process (no second terminal)"
	@echo "up / down     docker compose stack"

install:
	$(PY) -m pip install torch --index-url https://download.pytorch.org/whl/cpu
	$(PY) -m pip install -r requirements-dev.txt

keys:
	$(PY) -m cli.main keys init

trust-log:
	$(PY) -m cli.main keys trust-log

mvp:
	$(PY) -m cli.main mvp-demo

demo:
	$(PY) -m scripts.demo

demo-auto:
	$(PY) -m scripts.demo --auto

pipeline:
	$(PY) -m ml_pipeline.run_pipeline

attacks:
	$(PY) -m attacks.run_all

attacks-fast:
	$(PY) -m attacks.run_all --skip-e

benchmark:
	$(PY) -m scripts.benchmark

trustlog-benchmark:
	$(PY) -m scripts.trustlog_benchmark

figures:
	$(PY) -m scripts.make_figures

test:
	$(PY) -m pytest -q

test-fast:
	$(PY) -m pytest -q -m "not slow"

lint:
	ruff check .

api:
	uvicorn api.main:create_app --factory --reload --port 8000

dashboard:
	streamlit run dashboard/Overview.py --server.port 8501

standalone:
	CHAINGUARD_STANDALONE=1 streamlit run dashboard/Overview.py --server.port 8501

LABEL ?= team laptop - <owner>, <cpu>
validate:
	PYTHON=$(PY) bash scripts/run_validation.sh "$(LABEL)"

paper:
	$(PY) paper/figures/make_figures.py
	$(PY) paper/figures/make_slide_figures.py
	cd paper && pdflatex -interaction=nonstopmode signed_is_not_safe.tex >/dev/null && pdflatex -interaction=nonstopmode signed_is_not_safe.tex >/dev/null && echo "paper/signed_is_not_safe.pdf"

up:
	docker compose -f docker/docker-compose.yml up --build

down:
	docker compose -f docker/docker-compose.yml down

clean:
	rm -rf artifacts demo-ws data/digits_*.csv results/pipeline results/mvp_demo.json .pytest_cache
	@echo "keys/ kept on purpose; delete it manually to start a new trust root"
