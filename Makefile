SHELL := /bin/bash
DEMO_ENV := KUBEPILOT_SOURCE=fixture KUBEPILOT_FIXTURE_DIR=examples/demo-cluster KUBEPILOT_ALLOWLIST=examples/allowlist.yaml
SCRATCH ?= .demo

.PHONY: install test lint typecheck check demo demo-repo serve-demo serve ingest lab-up lab-down image

install:            ## install deps into .venv
	uv sync

test:               ## run the test suite (no cluster needed)
	uv run pytest

lint:
	uv run ruff check src tests && uv run ruff format --check src tests

typecheck:
	uv run mypy

check: lint typecheck test

demo:               ## health + security triage of the bundled demo cluster
	$(DEMO_ENV) uv run kubepilot triage
	$(DEMO_ENV) uv run kubepilot triage --security

demo-repo:          ## scratch git copy of the example GitOps repo (for plan/commit demos)
	rm -rf $(SCRATCH) && mkdir -p $(SCRATCH)
	cp -r examples/gitops-repo $(SCRATCH)/repo
	cd $(SCRATCH)/repo && git init -q -b main && git add -A && git -c user.name=demo -c user.email=demo@local commit -qm init
	@echo "export KUBEPILOT_GITOPS_REPO=$$(pwd)/$(SCRATCH)/repo KUBEPILOT_STATE_DIR=$$(pwd)/$(SCRATCH)/state"

serve-demo: demo-repo   ## MCP server over stdio against the demo fixtures
	$(DEMO_ENV) KUBEPILOT_GITOPS_REPO=$(SCRATCH)/repo KUBEPILOT_STATE_DIR=$(SCRATCH)/state uv run kubepilot serve

serve:              ## MCP server over stdio against your current kube-context
	uv run kubepilot serve

ingest:             ## Falcosidekick webhook receiver on :2801
	uv run kubepilot ingest --host 0.0.0.0

lab-up:             ## kind cluster + Falco/Falcosidekick + Trivy Operator + demo workloads
	./lab/up.sh

lab-down:
	kind delete cluster --name kubepilot

image:
	docker build -t kubepilot:dev .
