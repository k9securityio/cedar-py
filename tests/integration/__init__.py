import json
import os
import pprint
from typing import Union


def pretty_format(o: object) -> str:
    """Pretty print an object representation"""
    return pprint.pformat(object=o, indent=2, width=120)


def load_file_as_json(relative_file_path: str) -> Union[object, list, dict]:
    path = construct_path_relative_to_current_module(relative_file_path)

    try:
        with open(path) as json_file:
            obj = json.load(json_file)
            return obj
    except FileNotFoundError:
        print("File could not be found at: {}".format(path))
        raise


def load_file_as_str(relative_file_path: str) -> str:
    path = construct_path_relative_to_current_module(relative_file_path)

    try:
        with open(path) as f:
            return f.read()
    except FileNotFoundError:
        print("File could not be found at: {}".format(path))
        raise


def construct_path_relative_to_current_module(relative_file_path):
    my_path = os.path.abspath(os.path.dirname(__file__))
    path = os.path.join(my_path, relative_file_path)
    return path
