import json
import os


def load_file_as_json(relative_file_path: str) -> object:
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
