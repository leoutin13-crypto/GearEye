"""Request-local company scope used by the persistence layer."""

from contextvars import ContextVar


active_company_id = ContextVar("geareye_active_company_id", default="default")
