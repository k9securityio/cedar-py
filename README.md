# Cedar Python
![CI (main)](https://github.com/k9securityio/cedar-py/actions/workflows/CI.yml/badge.svg?branch=main)

This repository contains `cedarpy`, a Python package that allows using the (Rust) [Cedar Policy](https://github.com/cedar-policy/cedar/tree/main) library from Python more convenient.

This project is built on the [PyO3](https://docs.rs/pyo3/latest/pyo3/index.html) and [maturin](https://www.maturin.rs/index.html) projects.  These projects are designed to enable Python to use Rust code and vice versa.

Note: This project is _not_ officially supported by AWS or the Cedar Policy team.

## Getting started

You'll need a few things to get started:

* Python +3.9
* Rust and `cargo`

The most common development commands are in the `Makefile`

Note: This project is developed on an M1 Mac with Python 3.9.

### Create virtual env

First create a Python virtual environment for this project with:
`make venv-dev`

In addition to creating a dedicated virtual environment, this will install `cedar-py`'s dependencies.

If this works you should be able to run the following command:
``` shell
maturin --help
```

## Build and run `cedar-py` tests

Ensure the `cedar-py` virtual environment is active by sourcing it in your shell:

```shell
source venv-dev/bin/activate
```

Now run:
```shell
make quick
```

The `make quick` command will build the Rust source code with `maturin` and run the project's tests with `pytest`.

If all goes well, you should see output like:
```shell
(venv-dev) swedish-chef:cedar-py skuenzli$ make quick
Performing quick build
set -e ;\
	maturin develop ;\
	pytest
📦 Including license file "/path/to/cedar-py/LICENSE"
🔗 Found pyo3 bindings
🐍 Found CPython 3.9 at /path/to/cedar-py/venv-dev/bin/python
📡 Using build options features from pyproject.toml
Ignoring maturin: markers 'extra == "dev"' don't match your environment
Ignoring pip-tools: markers 'extra == "dev"' don't match your environment
Ignoring pytest: markers 'extra == "dev"' don't match your environment
💻 Using `MACOSX_DEPLOYMENT_TARGET=11.0` for aarch64-apple-darwin by default
   Compiling cedarpy v0.1.0 (/path/to/cedar-py)
    Finished dev [unoptimized + debuginfo] target(s) in 3.06s
📦 Built wheel for CPython 3.9 to /var/folders/k2/tnw8n1c54tv8nt4557pfx3440000gp/T/.tmpO6aj6c/cedarpy-0.1.0-cp39-cp39-macosx_11_0_arm64.whl
🛠 Installed cedarpy-0.1.0
================================================================================================ test session starts ================================================================================================
platform darwin -- Python 3.9.12, pytest-7.4.0, pluggy-1.2.0
rootdir: /path/to/cedar-py
configfile: pyproject.toml
testpaths: tests/unit
collected 10 items

tests/unit/test_authorize.py::AuthorizeTestCase::test_authorize_basic_ALLOW PASSED                                                                                                                            [ 10%]
tests/unit/test_authorize.py::AuthorizeTestCase::test_authorize_basic_DENY PASSED                                                                                                                             [ 20%]

... snip ... # a bunch of tests passing - please write more!
tests/unit/test_import_module.py::InvokeModuleTestFunctionTestCase::test_invoke_parse_test_policy PASSED                                                                                                      [100%]

================================================================================================ 10 passed in 0.51s =================================================================================================
```

### Integration tests
This project supports validating correctness with official Cedar integration tests. To run those tests you'll need to retrieve the `cedar-integration-tests` data with:

```shell
make submodules
```

Then you can run:
```shell
make integration-tests
```

`cedar-py` currently passes 46 of the 50 'example_use_cases_doc' tests.  We will support executing more tests shortly. See [test_cedar_integration_tests.py](tests/integration/test_cedar_integration_tests.py) for details.

## Using the library
Releases of `cedarpy` will be available on PyPi soon.  For now, if you'd like to use the library, you can build a release locally and install it with `pip`.

If you used `make quick` above, the `cedarpy` module will already be installed. You can also use `make release` to build a release locally.

The release process will build a wheel and output it into `target/wheels/`

You can install that file with pip, e.g.:
```shell
pip install /path/to/cedar-py/target/wheels/cedarpy-0.1.0-cp39-cp39-macosx_11_0_arm64.whl
```

Then you can use the library from your Python project just like the [tests](tests/unit) demonstrate:

```python
from cedarpy import is_authorized, AuthzResult, Decision

policies: str = "//a string containing cedar policies"
entities: list = [  # a list of Cedar entities; can also be a json-formatted string of Cedar entities
    {"uid": {"__expr": "User::\"alice\""}, "attrs": {}, "parents": []}
    # ...
]
request = {
    "principal": "User::\"bob\"",
    "action": "Action::\"view\"",
    "resource": "Photo::\"1234-abcd\"",
    "context": {}
}

authz_result: AuthzResult = is_authorized(request, policies, entities)

# so you can assert on the decision like:
assert Decision.Allow == authz_result.decision

# or use the 'allowed' convenience method 
assert authz_result.allowed

# or even via AuthzResult's attribute subscripting support 
assert authz_result['allowed']

```

### Formatting Cedar policies

You can use `format_policies` to pretty-print Cedar policies according to
convention.

```python
from cedarpy import format_policies

policies: str = """
    permit(
        principal,
        action == Action::"edit",
        resource
    )
    when {
        resource.owner == principal
    };
"""

print(format_policies(policies))
# permit (
#   principal,
#   action == Action::"edit",
#   resource
# )
# when { resource.owner == principal };
```

## Contributing

This project is very early stage. This project uses GitHub [issues](https://github.com/k9securityio/cedar-py/issues). Contributions are welcome.

Some ways to contribute are:
* Use the project and report experience and issues
* Document usage and limitations
* Enhance the library with additional functionality you need
* Add test cases, particularly those from [`cedar-integration-tests`](https://github.com/k9securityio/cedar-py/issues/3)

You can reach peopel interested in this project in the `cedar-py` channel of the Cedar Policy Slack workspace.
