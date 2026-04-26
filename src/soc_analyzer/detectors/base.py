"""Detector base class — barcha detectorlar shu interfeysga ega."""
from __future__ import annotations
from abc import ABC, abstractmethod
import pandas as pd

from soc_analyzer.core.models import AttackSession


class Detector(ABC):
    """Har bir detector boyitilgan DataFrame qabul qiladi va AttackSession ro'yxatini qaytaradi."""

    name: str = ""
    attack_type: str = ""

    @abstractmethod
    def detect(self, df: pd.DataFrame) -> list[AttackSession]:
        ...

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}>"
