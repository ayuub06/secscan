from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class Client(Base):
    __tablename__ = "clients"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String, nullable=False)
    contact_email: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
    )

    targets: Mapped[list[Target]] = relationship(
        "Target", back_populates="client", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<Client id={self.id} name={self.name!r}>"


class Target(Base):
    __tablename__ = "targets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    client_id: Mapped[int] = mapped_column(ForeignKey("clients.id"), nullable=False)
    # Scope stores the target as a single string (e.g. "10.0.0.5", "example.com").
    # Multiple scope entries (e.g. a CIDR range expanded to several hosts) are stored
    # comma-separated for now; normalise into a separate scope_entries table if
    # querying or iterating individual IPs becomes a real need.
    scope: Mapped[str] = mapped_column(String, nullable=False)
    authorized_by: Mapped[str] = mapped_column(String, nullable=False)
    schedule_cron: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    skip_cve: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
    )

    client: Mapped[Client] = relationship("Client", back_populates="targets")
    scan_runs: Mapped[list[ScanRun]] = relationship(
        "ScanRun", back_populates="target", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<Target id={self.id} scope={self.scope!r} client_id={self.client_id}>"


class ScanRun(Base):
    __tablename__ = "scan_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"), nullable=False)
    scan_id: Mapped[str] = mapped_column(String, nullable=False)
    status: Mapped[str] = mapped_column(String, nullable=False)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    # Stores the full scan_result.to_dict() output as a JSON string once a scan
    # completes. Normalising findings into their own table is a reasonable future
    # improvement once querying or filtering findings across scans is a real need;
    # a JSON blob is the right level of complexity for now.
    result_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    target: Mapped[Target] = relationship("Target", back_populates="scan_runs")

    def __repr__(self) -> str:
        return f"<ScanRun id={self.id} scan_id={self.scan_id!r} status={self.status!r}>"
