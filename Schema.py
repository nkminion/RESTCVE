from pydantic import BaseModel, Field, ConfigDict
from typing import Optional

class CVECore(BaseModel):
    title: str = Field(..., max_length=255, description="A brief summary of the exploit")
    descr: str
    cvss_score: float = Field(..., ge=0.0, le=10.0, description="Severity score from 0.0 to 10.0")
    target_os: Optional[str] = Field(None, max_length=100)
    target_arch: Optional[str] = Field(None, max_length=50)
    notes: Optional[str] = None

class CVECreate(CVECore):
    cveid: str = Field(..., max_length=50, description="The unique CVE identifier")

class CVEUpdate(BaseModel):
    title: Optional[str] = Field(None, max_length=255)
    descr: Optional[str] = None
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    target_os: Optional[str] = Field(None, max_length=100)
    target_arch: Optional[str] = Field(None, max_length=50)
    status: Optional[str] = Field(None, max_length=50)
    notes: Optional[str] = None

class CVEResponse(CVECore):
    cveid: str
    status: str
    model_config = ConfigDict(from_attributes=True)