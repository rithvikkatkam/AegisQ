"""
llm_query.py
------------
Implements POST /api/query by calling the Anthropic Messages API with the
current /api/risk/summary payload injected as grounding context, and asking
the model to answer strictly from that context plus name which asset_ids it
relied on.

If ANTHROPIC_API_KEY isn't set, this returns a clean error dict instead of
raising, so the demo doesn't crash if the key hasn't been configured yet --
the contract's error shape is used ({error, message, code}).
"""
import json
import os

ANTHROPIC_MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-5-20250929")

SYSTEM_PROMPT = """You are a cyber-risk analyst assistant embedded in the AegisQ platform.
You will be given a JSON snapshot of the organization's current risk posture
(enterprise_risk_score, total_financial_exposure_inr, risk_trend, and
top_risk_contributors). Answer the user's question using ONLY the data
provided -- do not invent figures, asset names, or trends that aren't in the
snapshot. If the data doesn't contain what's needed to answer, say so.

Respond with ONLY a JSON object (no markdown fences, no preamble) of the
exact shape:
{"answer": "<your answer as plain text>", "cited_asset_ids": ["<asset_id>", ...]}

cited_asset_ids must only contain asset_id values that appear in the
top_risk_contributors list you were given, and only include ids you actually
referenced in your answer. If you referenced no specific asset, return an
empty list."""


def answer_query(question: str, risk_summary: dict) -> dict:
    """
    Returns either:
      {"answer": str, "cited_asset_ids": [str, ...]}
    or (on failure)
      {"error": True, "message": str, "code": str}
    """
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return {
            "error": True,
            "message": "ANTHROPIC_API_KEY is not configured on the server.",
            "code": "LLM_NOT_CONFIGURED",
        }

    try:
        import anthropic
    except ImportError:
        return {
            "error": True,
            "message": "The 'anthropic' package is not installed. Run: pip install anthropic",
            "code": "LLM_SDK_MISSING",
        }

    try:
        client = anthropic.Anthropic(api_key=api_key)
        user_content = (
            f"Risk snapshot JSON:\n{json.dumps(risk_summary)}\n\nQuestion: {question}"
        )
        response = client.messages.create(
            model=ANTHROPIC_MODEL,
            max_tokens=1000,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_content}],
        )
        raw_text = "".join(
            block.text for block in response.content if getattr(block, "type", None) == "text"
        ).strip()

        # Strip accidental markdown fences defensively even though the
        # prompt asks for raw JSON.
        cleaned = raw_text.strip()
        if cleaned.startswith("```"):
            cleaned = cleaned.strip("`")
            if cleaned.lower().startswith("json"):
                cleaned = cleaned[4:]
            cleaned = cleaned.strip()

        parsed = json.loads(cleaned)
        answer = parsed.get("answer", "")
        cited_asset_ids = parsed.get("cited_asset_ids", [])
        if not isinstance(cited_asset_ids, list):
            cited_asset_ids = []
        return {"answer": answer, "cited_asset_ids": cited_asset_ids}

    except json.JSONDecodeError:
        # Model didn't return valid JSON -- fall back to raw text as the
        # answer rather than failing the whole request.
        return {"answer": raw_text if "raw_text" in locals() else "", "cited_asset_ids": []}
    except Exception as exc:  # noqa: BLE001 -- surface any SDK/network error to the caller
        return {
            "error": True,
            "message": f"LLM call failed: {exc}",
            "code": "LLM_CALL_FAILED",
        }
