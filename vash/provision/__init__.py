"""Deterministic, offline project provisioning: fingerprint a repo, source a
build recipe, render a Dockerfile. Text/analysis only — NEVER executes the
target or runs `docker build` (that is the Phase 2 provisioning stage)."""
