from __future__ import annotations

import os

import pytest


@pytest.mark.integration
def test_real_baseline_is_opt_in() -> None:
    """Runs the baseline against AWS only when both opt-in variables are set.

    The default test run deselects this marker, so it cannot launch anything.
    """
    if os.environ.get("AMI_PATCHER_INTEGRATION") != "1" or not os.environ.get("AMI_PATCHER_CONFIG"):
        pytest.skip("set AMI_PATCHER_INTEGRATION=1 and AMI_PATCHER_CONFIG to a completed config.yaml")
    from ami_patcher.cli import main

    assert main(["--config", os.environ["AMI_PATCHER_CONFIG"], "run"]) == 0
