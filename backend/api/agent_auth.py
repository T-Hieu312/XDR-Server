import json
import os
import secrets

from fastapi import HTTPException


def authenticate_agent(agent_id: str, supplied_key: str) -> None:
    """Prefer per-agent credentials; retain the legacy shared key during migration."""
    raw_mapping = os.environ.get("XDR_AGENT_KEYS", "").strip()
    legacy_key = os.environ.get("XDR_AGENT_KEY", "")
    if raw_mapping:
        try:
            mapping = json.loads(raw_mapping)
        except json.JSONDecodeError as error:
            raise HTTPException(status_code=503, detail="XDR_AGENT_KEYS must be a JSON object") from error
        if not isinstance(mapping, dict) or any(
            not isinstance(key, str) or not isinstance(value, str) or not value
            for key, value in mapping.items()
        ):
            raise HTTPException(status_code=503, detail="XDR_AGENT_KEYS must map agent IDs to non-empty keys")
        expected_key = mapping.get(agent_id)
        if expected_key is None or not secrets.compare_digest(supplied_key, expected_key):
            raise HTTPException(status_code=401, detail="Invalid agent credentials")
        return

    if not legacy_key:
        raise HTTPException(status_code=503, detail="Configure XDR_AGENT_KEYS or XDR_AGENT_KEY")
    if not secrets.compare_digest(supplied_key, legacy_key):
        raise HTTPException(status_code=401, detail="Invalid agent credentials")
