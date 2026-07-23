"""Config loading test — make sure stages.yaml is valid."""

from __future__ import annotations

from vash.config import load_config


def test_default_config_loads() -> None:
    cfg = load_config()
    for name in ["recon", "hunt", "validate", "gapfill", "dedupe", "trace",
                 "feedback", "report"]:
        sc = cfg.get(name)
        assert sc.model, f"{name}: missing model"
        assert sc.concurrency >= 1, f"{name}: invalid concurrency"
        assert sc.tools, f"{name}: missing tools"


def test_hunt_validate_model_diversity() -> None:
    """Hunt and Validate MUST use different models — the blog's
    'deliberate disagreement' rule."""
    cfg = load_config()
    assert cfg.get("hunt").model != cfg.get("validate").model
