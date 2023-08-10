import time


def unix_ts() -> int:
    """simple unix timestamp returning int"""
    return int(time.time())
