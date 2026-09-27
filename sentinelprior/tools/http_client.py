"""Small HTTP helper with retries and clear error messages."""

from __future__ import annotations

import time
from typing import Any

import requests

from ..run_logger import RunLogger


class HttpClient:
    def __init__(self, timeout: int, max_retries: int, logger: RunLogger) -> None:
        self.timeout = timeout
        self.max_retries = max_retries
        self.logger = logger
        self.session = requests.Session()
        self.session.headers.update(
            {"User-Agent": "SentinelPrior/1.0 educational-assessment"}
        )

    def get_json(
        self,
        url: str,
        *,
        stage: str,
        params: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        simulate_failure: bool = False,
    ) -> dict[str, Any]:
        last_error = "unknown error"

        for attempt in range(1, self.max_retries + 1):
            try:
                if simulate_failure:
                    raise requests.Timeout("deliberately simulated timeout")

                response = self.session.get(
                    url,
                    params=params,
                    headers=headers,
                    timeout=self.timeout,
                )
                response.raise_for_status()
                return response.json()
            except (requests.RequestException, ValueError) as error:
                last_error = f"{type(error).__name__}: {error}"
                self.logger.log(
                    stage,
                    "RETRY",
                    f"Attempt {attempt}/{self.max_retries} failed",
                    error=last_error,
                )
                if attempt < self.max_retries and not simulate_failure:
                    time.sleep(2 ** (attempt - 1))

        raise RuntimeError(last_error)
