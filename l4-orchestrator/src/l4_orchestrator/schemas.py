"""Shared base model for existing native Tool input definitions."""
from pydantic import BaseModel, ConfigDict

class WireModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
