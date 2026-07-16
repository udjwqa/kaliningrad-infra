import uuid
from datetime import datetime
from sqlalchemy import Column, String, Integer, Text, DateTime, Index, Boolean, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID, JSONB
from database import Base


class RequestLog(Base):
    __tablename__ = "request_logs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    ip = Column(String(45), index=True)
    country = Column(String(100))
    country_code = Column(String(5), index=True)
    city = Column(String(200))
    device_model = Column(String(200))
    os = Column(String(100))
    user_agent = Column(Text)
    score = Column(Integer, default=0)
    verdict = Column(String(10), index=True)
    rejection_code = Column(String(50), index=True, nullable=True)
    package_name = Column(String(200), index=True, nullable=True)
    raw_payload = Column(JSONB, default=dict)

    __table_args__ = (
        Index("idx_timestamp_verdict", "timestamp", "verdict"),
        Index("idx_ip_timestamp", "ip", "timestamp"),
        Index("idx_package_timestamp", "package_name", "timestamp"),
    )

    def to_dict(self):
        return {
            "id": str(self.id),
            "timestamp": self.timestamp.isoformat() + "Z" if self.timestamp else "",
            "ip": self.ip or "",
            "country": self.country or "",
            "countryCode": self.country_code or "",
            "city": self.city or "",
            "deviceModel": self.device_model or "",
            "os": self.os or "",
            "score": self.score or 0,
            "verdict": self.verdict or "grey",
            "rejectionCode": self.rejection_code,
            "rawPayload": self.raw_payload or {},
        }


class BannedIP(Base):
    __tablename__ = "banned_ips"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    ip = Column(String(45), unique=True, index=True)
    reason = Column(String(200))
    source = Column(String(50))
    banned_at = Column(DateTime, default=datetime.utcnow)
    cf_rule_id = Column(String(100), nullable=True)

    def to_dict(self):
        return {
            "id": str(self.id),
            "ip": self.ip or "",
            "reason": self.reason or "",
            "source": self.source or "",
            "bannedAt": self.banned_at.isoformat() + "Z" if self.banned_at else "",
            "cfRuleId": self.cf_rule_id,
        }


# 2026-06-23 (Smart Auto-Banlist P1): per-(ip, package_name) negative cache.
# Top-layer защита — IP который один раз попал в hard-kill не прогоняется через
# весь pipeline (IPQS / IPinfo / PI verify / scoring) до expires_at.
# 3-tier model: instance_burnt (Redis 24h per-instance) → auto_ban (этот, 24h-7d
# per-IP) → honeypot_ban (Postgres 365d + CF API global).
class AutoBannedEntry(Base):
    __tablename__ = "auto_banned_entries"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    # IP (IPv4 или IPv6)
    ip = Column(String(45), nullable=False, index=True)
    # package_name прилы — NULL означает global ban (для GLOBAL_AUTOBAN_CODES типа
    # tor_exit, asn_google и asn_vpn где IP плохой для любого приложения)
    package_name = Column(String(200), nullable=True, index=True)
    # rejection_code который вызвал ban (asn_vpn, pi_nonce_replay, etc)
    code = Column(String(50), nullable=False)
    reason = Column(String(500))
    banned_at = Column(DateTime, default=datetime.utcnow, index=True)
    # NULL = permanent (через manual UI), иначе автоматически удаляется after expires
    expires_at = Column(DateTime, nullable=True, index=True)
    # 'auto' (pipeline detection), 'manual' (admin UI), 'audit_row' (audit page button)
    banned_by = Column(String(100), default="auto")
    source = Column(String(20), default="auto")
    # Counter — сколько раз этот же (ip, pkg) попадался в hard-kill (для аналитики)
    strike_count = Column(Integer, default=1)
    # Shadow mode flag: если true — запись существует но НЕ блокирует.
    # Используется для 7-day soak validation перед enforce flip.
    would_ban = Column(Boolean, default=False)
    # Link обратно на request_logs запись которая вызвала ban
    origin_request_id = Column(UUID(as_uuid=True), nullable=True)
    # Классификация actor'а на момент бана (moder_bot / suspicious / etc)
    classification_at_ban = Column(String(50), nullable=True)

    __table_args__ = (
        # Lookup key — основной index для is_banned() (composite)
        UniqueConstraint("package_name", "ip", name="uq_autoban_pkg_ip"),
        Index("idx_autoban_lookup", "package_name", "ip"),
        Index("idx_autoban_recent", "banned_at"),
    )

    def to_dict(self):
        return {
            "id": str(self.id),
            "ip": self.ip or "",
            "packageName": self.package_name,
            "code": self.code or "",
            "reason": self.reason or "",
            "bannedAt": self.banned_at.isoformat() + "Z" if self.banned_at else "",
            "expiresAt": self.expires_at.isoformat() + "Z" if self.expires_at else None,
            "bannedBy": self.banned_by or "auto",
            "source": self.source or "auto",
            "strikeCount": self.strike_count or 1,
            "wouldBan": bool(self.would_ban),
            "originRequestId": str(self.origin_request_id) if self.origin_request_id else None,
            "classificationAtBan": self.classification_at_ban,
        }


# 2026-07-09 Docs Hub: свободные markdown-отчёты, пишутся юзерами панели,
# видны всем (в т.ч. клиенту-Тимуру). Edit/Delete — только автор (проверка
# по email в panel proxy, backend просто хранит). author_* инъектируются
# panel proxy из NextAuth session, чтобы клиент не мог подделать.
class Report(Base):
    __tablename__ = "reports"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    author_email = Column(String(200), nullable=False, index=True)
    author_name = Column(String(200), nullable=True)
    title = Column(String(500), nullable=False)
    body_md = Column(Text, nullable=False, default="")
    # ["fix", "deploy", "betsson"] — свободные метки, без валидации
    tags = Column(JSONB, nullable=False, default=list)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    __table_args__ = (
        Index("idx_reports_created", "created_at"),
    )

    def to_dict(self):
        return {
            "id": str(self.id),
            "author_email": self.author_email or "",
            "author_name": self.author_name,
            "title": self.title or "",
            "body_md": self.body_md or "",
            "tags": list(self.tags or []),
            "created_at": self.created_at.isoformat() + "Z" if self.created_at else "",
            "updated_at": self.updated_at.isoformat() + "Z" if self.updated_at else "",
        }
