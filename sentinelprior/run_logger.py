"""In-memory execution trace that can be exported with the report."""

from __future__ import annotations

from .models import RunEvent


class RunLogger:
    def __init__(self) -> None:
        self.events: list[RunEvent] = []

    def log(self, stage: str, status: str, message: str, **details: object) -> None:
        event = RunEvent.create(stage, status, message, **details)
        self.events.append(event)
        print(f"[{stage:<14}] {status:<8} {message}")
