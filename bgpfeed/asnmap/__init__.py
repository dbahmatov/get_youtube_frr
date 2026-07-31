"""Сопоставление IP → ASN.

Отдельный подпакет, потому что источник заменяем: сейчас Team Cymru,
завтра может добавиться RIPEstat или локальная таблица BGP.
"""

from .cymru import AsnRecord, lookup

__all__ = ["AsnRecord", "lookup"]
