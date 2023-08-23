import datetime
from typing import Union


def load_file_as_json(relative_file_path: str) -> Union[object, list, dict]:
    import shared
    return shared.load_file_as_json(relative_file_path=relative_file_path,
                                    base_file=__file__)


def load_file_as_str(relative_file_path: str) -> str:
    import shared
    return shared.load_file_as_str(relative_file_path=relative_file_path,
                                   base_file=__file__)


def utc_now() -> datetime.datetime:
    """
    Get the current time in UTC.
    """
    return datetime.datetime.now(datetime.timezone.utc)
