"""helpers"""
import time
from datetime import datetime, timezone


def unix_ts() -> int:
    """simple unix timestamp returning int"""
    return int(time.time())


def utc_ts() -> datetime:
    """simple utc timestamp"""
    return datetime.now(timezone.utc)
