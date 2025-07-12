from dataclasses import dataclass


@dataclass
class DetectionResult:
    url: str
    safe_percentage: float
    phishing_percentage: float
    features: list[dict[str, str]]
    warning: str = None