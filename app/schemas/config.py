from pydantic import BaseModel, Field


class ConfigPayload(BaseModel):
    misp_url: str | None = None
    misp_api_key: str | None = None
    misp_verify_cert: bool | None = None
    misp_sync_interval_seconds: int | None = Field(default=None, ge=10)
    ta_node_enabled: bool | None = None
    ta_node_base_url: str | None = None
    ta_node_token: str | None = None
    ta_node_source_name: str | None = None
    ta_node_push_interval_seconds: int | None = Field(default=None, ge=10)
