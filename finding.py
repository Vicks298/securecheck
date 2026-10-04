from dataclasses import dataclass, asdict
from datetime import datetime, timezone

SEVERITIES = ("Critical", "High", "Medium", "Low", "Info")


@dataclass
class Finding:
    check: str
    target: str
    severity: str
    title: str
    detail: str
    evidence: str
    why_it_matters: str
    fix: str
    limit: str = ""
    timestamp: str = ""

    def __post_init__(self):
        if self.severity not in SEVERITIES:
            raise ValueError(f"bad severity: {self.severity}")
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")

    def to_dict(self):
        return asdict(self)
