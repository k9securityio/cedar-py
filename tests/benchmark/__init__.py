import os
from typing import Union

import shared


def load_file_as_str(relative_file_path: str) -> str:
    """Load a file as string, relative to the unit test resources directory."""
    # Resources are in tests/unit/resources, so we reference them from there
    unit_dir = os.path.join(os.path.dirname(__file__), '..', 'unit')
    return shared.load_file_as_str(relative_file_path=relative_file_path,
                                   base_file=os.path.join(unit_dir, '__init__.py'))


def load_file_as_json(relative_file_path: str) -> Union[object, list, dict]:
    """Load a file as JSON, relative to the unit test resources directory."""
    unit_dir = os.path.join(os.path.dirname(__file__), '..', 'unit')
    return shared.load_file_as_json(relative_file_path=relative_file_path,
                                    base_file=os.path.join(unit_dir, '__init__.py'))
