from sentinelprior.ai_helper import AIHelper
from sentinelprior.run_logger import RunLogger


def test_fallback_plan_extracts_requested_count() -> None:
    helper = AIHelper(None, "unused-model", RunLogger())

    plan = helper.create_plan("Show the top 3 urgent vulnerabilities")

    assert plan.requested_top_n == 3
    assert len(plan.steps) >= 5
    assert helper.mode == "deterministic fallback"
