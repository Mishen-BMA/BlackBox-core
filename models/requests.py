from pydantic import BaseModel, Field


class TextRequest(BaseModel):
    value: str = Field(..., min_length=1)


class HashRequest(TextRequest):
    algorithm: str = "sha256"

