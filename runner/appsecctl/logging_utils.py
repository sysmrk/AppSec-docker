from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from typing import Any


def log_event(event: str, level: str = "info", **fields: Any) -> None:
    payload = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "level": level,
        "event": event,
        "service": os.environ.get("APPSEC_SERVICE", "appsec"),
        **fields,
    }
    print(json.dumps(payload, default=str, ensure_ascii=False), file=sys.stdout, flush=True)
