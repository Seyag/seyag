"""Optional Claude verdicts. A missing API key raises and callers fail closed."""
from __future__ import annotations

import base64
import json
import os

VERDICT_SCHEMA = {"type": "object", "additionalProperties": False, "required": ["verdict", "reason"],
                  "properties": {"verdict": {"type": "string", "enum": ["allow", "block"]}, "reason": {"type": "string"}}}
_CLIENT = None


def _client():
    global _CLIENT
    if _CLIENT is None:
        import anthropic

        key = os.environ.get("ANTHROPIC_API_KEY")
        if not key:
            raise RuntimeError("Claude API key is not configured")
        _CLIENT = anthropic.Anthropic(api_key=key, timeout=12, max_retries=1)
    return _CLIENT


def ask(model: str, system: str, text: str, jpeg: bytes | None = None, schema: dict | None = None) -> dict:
    """{"verdict": one of the schema's values, "reason": str}. A refusal is a block; anything unreadable raises."""
    content = []
    if jpeg:
        content.append({"type": "image", "source": {"type": "base64", "media_type": "image/jpeg",
                                                    "data": base64.standard_b64encode(jpeg).decode()}})
    content.append({"type": "text", "text": text})
    r = _client().messages.create(
        model=model, max_tokens=1500, system=system,
        output_config={"effort": "low", "format": {"type": "json_schema", "schema": schema or VERDICT_SCHEMA}},
        messages=[{"role": "user", "content": content}])
    if r.stop_reason == "refusal":
        return {"verdict": "block", "reason": "model refused"}
    verdict = json.loads(next(b.text for b in r.content if b.type == "text"))
    if verdict.get("verdict") not in (schema or VERDICT_SCHEMA)["properties"]["verdict"]["enum"]:
        raise ValueError("unclear model verdict")
    return verdict
