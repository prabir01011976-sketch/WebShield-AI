from pydantic import BaseModel

class ScanRequest(BaseModel):
    url: str