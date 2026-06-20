from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Optional

from sqlalchemy import DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from db.orm_models import Base

if TYPE_CHECKING:
    from db.orm_models import Client


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    google_id: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    email: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    name: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    role: Mapped[str] = mapped_column(String, nullable=False, default="customer")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
    )

    clients: Mapped[list["Client"]] = relationship("Client", back_populates="user")

    def __repr__(self) -> str:
        return f"<User id={self.id} email={self.email!r}>"
