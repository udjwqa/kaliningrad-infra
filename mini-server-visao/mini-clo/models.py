"""Data models — copies of main КЛО models.py (subset for mini-КЛО)."""
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class ScoringDetail:
    check: str
    points: int
    reason: str = ""

    def __dict__(self):
        return {"check": self.check, "points": self.points, "reason": self.reason}


@dataclass
class ScoringResult:
    score: int
    verdict: str  # "grey" | "white"
    rejectionCode: Optional[str] = None
    details: List[ScoringDetail] = field(default_factory=list)
