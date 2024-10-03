from typing import ClassVar, Dict

from sigma.backends.kusto.kusto import KustoBackend


class Microsoft365DefenderBackend(KustoBackend):
    """Microsoft 365 Defender Kusto Backend."""

    name: ClassVar[str] = "[DEPRECATED] Microsoft 365 Defender Backend"
    identifier: ClassVar[str] = "microsoft365defender"
    formats: ClassVar[Dict[str, str]] = {
        "default": "Microsoft 365 Defender Kusto Query Language search strings",
    }
