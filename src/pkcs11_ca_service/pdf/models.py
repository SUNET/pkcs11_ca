from pydantic import BaseModel, validator
from typing import Optional


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
    data: str
    error: str
    create_ts: Optional[int]


class PDFValidateRequest(BaseModel):
    """Class to represent request"""
    data: str


class PDFValidateData(BaseModel):
    """Class to represent validation data"""
    valid: bool


class PDFValidateReply(BaseModel):
    """Class to represent reply"""
    data: PDFValidateData
    error: str
