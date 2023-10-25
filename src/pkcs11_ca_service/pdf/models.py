"""pdf model"""

from typing import Optional
from pydantic import BaseModel, validator


class PDFSignRequest(BaseModel):
    """Class to represent request"""

    transaction_id: str
    field_name: str = "Signature1"
    location: str
    reason: str
    data: str

    @validator("data")
    def data_len(cls, v: str) -> str:
        """validate field 'data' by length"""
        if len(v) < 3:
            raise ValueError("data field needs to be of length 3 or greater")
        return v


class PDFSignReply(BaseModel):
    """Class to represent reply"""

    transaction_id: str
    data: Optional[str] = None
    error: Optional[str] = None
    create_ts: Optional[int]


class PDFValidateRequest(BaseModel):
    """Class to represent request"""

    data: str


class PDFValidateReply(BaseModel):
    """Class to represent reply"""

    valid_signature: bool = False
    transaction_id: Optional[str] = None
    is_revoked: bool = False
    error: Optional[str] = None


class StatusReply(BaseModel):
    """Class to represent status reply"""

    status: str
    message: Optional[str] = None
    last_check: int
    next_check: int
