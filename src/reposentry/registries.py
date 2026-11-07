"""Public package-registry metadata lookups; packages are never downloaded or run."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen


class RegistryLookupError(RuntimeError):
    pass


@dataclass
class RegistryClient:
    timeout_seconds: int = 10

    def pypi(self, name: str) -> dict[str, Any] | None:
        return self._get(f"https://pypi.org/pypi/{quote(name)}/json")

    def npm(self, name: str) -> dict[str, Any] | None:
        return self._get(f"https://registry.npmjs.org/{quote(name, safe='@/')}")

    def _get(self, url: str) -> dict[str, Any] | None:
        request = Request(url, headers={"Accept": "application/json", "User-Agent": "RepoSentry/0.1"})
        try:
            with urlopen(request, timeout=self.timeout_seconds) as response:
                payload = json.load(response)
                return payload if isinstance(payload, dict) else None
        except HTTPError as error:
            if error.code == 404:
                return None
            raise RegistryLookupError(f"Registry lookup failed with HTTP {error.code}.") from error
        except (URLError, TimeoutError, json.JSONDecodeError) as error:
            raise RegistryLookupError("Registry lookup failed.") from error
