from pydantic import BaseModel
from typing import Dict


class URLRequest(BaseModel):
    url: str


class DetectionResponse(BaseModel):
    url: str
    safe_percentage: float
    phishing_percentage: float
    features: Dict[str, str]
