SHELL := /bin/bash
DEMO_ENV := CLARIKUBE_SOURCE=fixture
SCRATCH ?= .demo
# k3s's bundled kubectl otherwise falls back to the root-only /etc/rancher/k3s/k3s.yaml
export KUBECONFIG ?= $(HOME)/.kube/config

.PHONY: install test lint typecheck check demo demo-repo serve-demo serve ingest image \
	lab-k3s lab-kind lab-down lab-ingest lab-verify lab-break lab-attack lab-fix lab-approve lab-reset lab-mcp lab-capture

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
	$(DEMO_ENV) uv run clarikube triage
	$(DEMO_ENV) uv run clarikube triage --security

demo-repo:          ## scratch git copy of the example GitOps repo (for plan/commit demos)
	rm -rf $(SCRATCH)
	uv run clarikube demo --setup $(SCRATCH)

serve-demo: demo-repo   ## MCP server over stdio against the demo fixtures
	$(DEMO_ENV) CLARIKUBE_GITOPS_REPO=$(SCRATCH)/repo CLARIKUBE_STATE_DIR=$(SCRATCH)/state uv run clarikube serve

serve:              ## MCP server over stdio against your current kube-context
	uv run clarikube serve

ingest:             ## Falcosidekick webhook receiver on :2801
	uv run clarikube ingest --host 0.0.0.0

# ------------------------------------------------------------------ lab (see docs/TESTING.md)
LAB_STATE ?= $(HOME)/.local/state/clarikube
LAB_REPO  ?= $(HOME)/clarikube-lab-gitops
PHASE     ?= baseline
LAB_ENV := CLARIKUBE_ALERTS_DB=$(LAB_STATE)/alerts.db CLARIKUBE_STATE_DIR=$(LAB_STATE) \
	CLARIKUBE_ALLOWLIST=lab/allowlist.yaml CLARIKUBE_GITOPS_REPO=$(LAB_REPO) CLARIKUBE_DRY_RUN=false

lab-k3s:            ## single machine: k3s + Falco + Trivy + lab workloads (Ubuntu)
	./lab/k3s-install.sh

lab-kind:           ## kind variant (Docker Desktop / WSL2)
	./lab/up.sh

lab-down:
	kind delete cluster --name clarikube

lab-ingest:         ## receive Falco alerts (keep running in its own terminal)
	CLARIKUBE_INGEST_TOKEN=$$(cat $(LAB_STATE)/ingest-token) $(LAB_ENV) uv run clarikube ingest --host 0.0.0.0

lab-verify:         ## check findings: PHASE=baseline|broken|attacked|fixed
	$(LAB_ENV) uv run python lab/verify.py --phase $(PHASE)

lab-break:          ## commit + apply two bad releases (OOM, bad image tag)
	./lab/break.sh

lab-attack:         ## benign attack simulation on shop/payment-api
	./lab/attack.sh

lab-fix:            ## merge a clarikube branch and apply it: BRANCH=clarikube/...
	./lab/apply-fix.sh $(BRANCH)

lab-approve:        ## human approval for cli mode: ID=<plan-id>
	$(LAB_ENV) uv run clarikube approve $(ID)

lab-data:           ## optional data tier: Redis, RabbitMQ, OpenSearch + dependent app (SKIP_SEARCH=1)
	bash lab/data.sh

lab-reset:          ## back to baseline
	./lab/reset.sh

lab-mcp:            ## MCP server over stdio wired to the lab (what Claude Desktop launches)
	./lab/mcp.sh

lab-report:         ## launch report: findings, speed, token savings vs raw kubectl + redacted fixture
	$(LAB_ENV) CLARIKUBE_READ_LOGS=true uv run python lab/report.py

lab-readonly:       ## run clarikube with the read-only ServiceAccount from deploy/rbac.yaml (proves least privilege)
	./lab/readonly.sh

lab-capture:        ## save the live lab as a fixture (turn real bugs into tests)
	uv run clarikube capture --out examples/lab-capture-$$(date +%Y%m%d-%H%M)

sample-report:      ## regenerate docs/sample-report.{html,pdf} from the demo cluster
	CLARIKUBE_SOURCE=fixture uv run clarikube report --client "ACME GmbH (demo)" \
	  --by "clarikube" --contact "you@example.com" --cluster "demo cluster" \
	  --out docs/sample-report.html --pdf

image:
	docker build -t clarikube:dev .
