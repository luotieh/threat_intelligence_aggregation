from pydantic import BaseModel


class PushRequest(BaseModel):
    mode: str = "incremental"
