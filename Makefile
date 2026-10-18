# Shared build entry points. Each Task adds its own targets below the
# "Task targets" line; do not change the shared targets in a feature PR.

GO        ?= go
# ./... covers every Go package in the root module; directories that do not
# exist yet are simply absent, so this never errors on a partial tree.
GO_PKGS   ?= ./...
PY_DIRS   ?= $(wildcard services/discovery services/proposer services/timeline services/intent_check runtime/adk tools/regression tools/integration_runner tools/discovery-snapshot packages/evaluation packages/alignment)

.PHONY: all test go-test go-vet py-test tidy

all: go-vet test

test: go-test py-test

go-test:
	$(GO) test $(GO_PKGS)

go-vet:
	$(GO) vet $(GO_PKGS)

# Python components each carry their own pyproject.toml and uv lock.
py-test:
	@for d in $(PY_DIRS); do \
		if [ -f $$d/pyproject.toml ]; then echo "== $$d"; (cd $$d && uv run --frozen pytest -q) || exit 1; fi; \
	done

# Resolve go.mod/go.sum conflicts by regenerating, never by hand-merging.
tidy:
	$(GO) mod tidy

# ---- Task targets ----

# TASK-02: independent JCS cross-check of packages/canonical/testdata/vectors.json
# against the upstream JavaScript reference (TASK-02 3.3). Needs Node.js.
.PHONY: canonical-crosscheck
canonical-crosscheck:
	node packages/canonical/testdata/crosscheck/crosscheck.mjs
