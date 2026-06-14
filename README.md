# Cedar Python
![CI (main)](https://github.com/k9securityio/cedar-py/actions/workflows/CI.yml/badge.svg?branch=main)
&nbsp;[![PyPI version](https://badge.fury.io/py/cedarpy.svg)](https://badge.fury.io/py/cedarpy)

`cedarpy` helps you use the (Rust) [Cedar Policy](https://github.com/cedar-policy/cedar/tree/main) library from Python. You can use `cedarpy` to:
* check whether a request is authorized by the [Cedar Policy](https://www.cedarpolicy.com) engine
* validate policies against a schema
* format policies

`cedarpy` releases correspond to the following Cedar Policy engine versions:
<table>
<thead><tr><th>Cedar Policy (engine) release</th><th>cedarpy release</th><th>cedarpy branch</th></tr></thead>
<tbody>
    <tr><td>v4.8.2</td><td>v4.8.4</td><td>main</td></tr>
    <tr><td>v4.7.2</td><td>v4.7.1</td><td>release/4.7.x</td></tr>
    <tr><td>v4.1.0</td><td>v4.1.0</td><td>release/4.1.x</td></tr>
    <tr><td>v2.2.0</td><td>v0.4.1</td><td>release/2.2.x</td></tr>
</tbody>
</table>

Beginning with v4.1.0, `cedarpy`'s version number indicates the Cedar Policy engine major and minor version that it is based on. `cedarpy` increases the patch number when releasing backwards-compatible changes and bug fixes. So the `cedarpy` and Cedar Engine patch versions can and will diverge. Select the `cedarpy` version that provides the [Cedar Policy](https://www.cedarpolicy.com/en) language and engine features you need. 

`cedarpy` packages are available for the following platforms:
<table>
<thead><tr><th>Operating System</th><th>Processor Architectures</th><th>Python</th></tr></thead>
<tbody>
    <tr><td>Linux</td><td>x86_64, aarch64</td><td>3.9 - 3.14</td></tr>
    <tr><td>Mac</td><td>x86_64, aarch64</td><td>3.11 - 3.14</td></tr>
    <tr><td>Windows</td><td>x86_64</td><td>3.9 - 3.14</td></tr>
</tbody>
</table>

Note: This project is _not_ officially supported by AWS or the Cedar Policy team.

## Using the library
Releases of [`cedarpy`](https://pypi.org/project/cedarpy/) are available on PyPi.  You can install the latest release with:
```shell
pip install cedarpy
```

(See the Developing section for how to use artifacts you've built locally.)

### Authorizing access with Cedar policies in Python
Now you can use the library to authorize access with Cedar from your Python project using the `is_authorized` function.  Here's an example of basic use:

```python
from cedarpy import is_authorized, AuthzResult, Decision

policies: str = "//a string containing cedar policies"
entities: list = [  # a list of Cedar entities; can also be a json-formatted string of Cedar entities
    {"uid": {"__entity": { "type" : "User", "id" : "alice" }}, "attrs": {}, "parents": []}
    # ...
]
request = {
    "principal": 'User::"bob"',
    "action": 'Action::"view"',
    "resource": 'Photo::"1234-abcd"',
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
The [`AuthzResult`](cedarpy/__init__.py) class also provides diagnostics and metrics for the access evaluation request. 

See the [unit tests](tests/unit) for more examples of use and expected behavior.

### Authorize a batch of requests

You can also authorize a batch of requests with the `is_authorized_batch` function.  `is_authorized_batch` accepts a list of requests to evaluate against shared policies, entities, and schema.

Batch authorization is often _much_ more efficient (+10x) than processing authorization requests one by one with `is_authorized`.  This is because the most expensive part of the authorization process is transforming the policies, entities, and schema into objects that Cedar can evaluate.  See [RFC: support batch authorization requests](https://github.com/k9securityio/cedar-py/issues/13) for details.

Here's an example of how to use `is_authorized_batch` and the optional request-result `correlation_id`:

```python3
batch_id:str = randomstr()
requests: List[dict] = []
for action_name in action_names:
    requests.append({
        "principal": f'User::"{user_id}"',
        "action": f'Action::"{action_name}"',
        "resource": f'Resource::"{resource_id}"',
        "context": context_keys,
        "correlation_id": f"authz_req::{batch_id}-{action_name}"
    })

# ... resolve get policies, entities, schema ...

# process authorizations in batch
authz_results: List[AuthzResult] = is_authorized_batch(requests=requests, policies=policies, entities=entities, schema=schema)

# ... verify results came back in correct order via correlation_id ...
for request, result, in zip(requests, authz_results):
    assert request.get('correlation_id') == result.correlation_id

```
cedar-py returns the list of `AuthzResult` objects in the same order as the list of requests provided in the batch.

The above example also supplies an optional `correlation_id` in the request so that you can verify results are returned in the correct order or otherwise map a request to a result.


### Reusing parsed policies for performance

Parsing the policy set (`PolicySet::from_str`) is the dominant per-call cost in `is_authorized`. When your policies are static — for example a code-checked policy set loaded once at startup in a long-running service or AWS Lambda — you can parse them a single time into a reusable `PolicySet` handle and pass that handle wherever you'd pass a policies string. This skips the re-parse on every call.

```python
from cedarpy import PolicySet, is_authorized, is_authorized_batch, Decision

policies: str = "// a string containing cedar policies"

# Parse once (e.g. at process/Lambda cold start). Parse errors raise ValueError here,
# rather than being folded into an authorization result.
policy_set = PolicySet.from_str(policies)

# Reuse the handle across many requests — no re-parse per call:
authz_result = is_authorized(request, policy_set, entities)
authz_results = is_authorized_batch(requests, policy_set, entities)
```

The `PolicySet` handle is accepted anywhere a policies string is accepted: `is_authorized`, `is_authorized_batch`, and `is_authorized_partial`. Passing a plain string still works exactly as before — the handle is purely opt-in and fully backwards compatible. The handle's memory is released automatically when the last Python reference is dropped.

A `PolicySet` can also be built from the Cedar JSON (EST) policy format with `PolicySet.from_json_str(...)`, and supports `len(policy_set)` (number of policies) and `str(policy_set)` (the policy set rendered back to Cedar text).

This complements batch authorization: batching amortizes entity/schema parsing across a set of requests evaluated together, while a reusable `PolicySet` amortizes policy parsing across calls made at different times. The two compose. The speedup grows with policy size — in the project's benchmark suite (release build, ~10-entity calls) reuse is ~1.3x on a single-rule policy but ~9x on a typical production-scale policy (~16 KB / 60 rules), where it removes ~1.4 ms of policy parsing per call.

On a successful evaluation the result's `metrics` reflect the reuse: `parse_policies_duration_micros` measures only the (near-zero) borrow rather than the original parse, and `metrics["policies_pre_parsed"]` is `1` (it is `0` when policies are passed as a string and parsed on that call). As with all `metrics`, these keys are present only on successful evaluations — an error result carries an empty `metrics` map.

> Note: reuse applies to the policy set. Entities and schema are still parsed on each call.

### Partially authorizing a request with unknowns

Sometimes you can't fully evaluate a request up front. A resource entity may not be loaded from the database yet, the caller may not have picked a resource, or `context` may be filled in by a downstream service. `is_authorized_partial` evaluates whatever is known and returns residual policies for the parts that aren't.

`is_authorized_partial` returns either:

* `Decision.Allow` or `Decision.Deny` when the unknowns can't change the outcome, or
* `Decision.NoDecision` plus residual policies for the caller to re-evaluate once the unknowns are bound.

```python
from cedarpy import is_authorized_partial, PartialAuthzResult, Decision

# Allow access to all principals when the resource is public
policies: str = 'permit(principal, action, resource) when { resource.public == true };'

# Resource entity hasn't been loaded from the database yet
entities: list = []

request = {
    "principal": 'User::"alice"',
    "action": 'Action::"view"',
    "resource": 'Photo::"photo1"',
    "context": {},
}

result: PartialAuthzResult = is_authorized_partial(request, policies, entities)

# Cedar can't decide yet: the policy depends on resource.public,
# but Photo::"photo1" hasn't been loaded.
assert result.decision == Decision.NoDecision

# Which entities Cedar needs you to load before it can decide:
assert result.diagnostics.unknown_entities == ['Photo::"photo1"']

# Which policies are still unresolved, identified by the auto-generated policy id:
assert result.diagnostics.nontrivial_residuals == ['policy0']
```

Now you can load the unknown entities and re-evaluate access with `is_authorized` to get a final decision:

```python
from cedarpy import is_authorized

# Load Photo::"photo1" from the database and transform to its Cedar entity representation
entities = [
    {"uid": {"__entity": {"type": "Photo", "id": "photo1"}},
     "attrs": {"public": True}, "parents": []}
]

final_result = is_authorized(request, policies, entities) # new entities; same request and policies
assert final_result.decision == Decision.Allow
```

> **Note:** A partial-eval result is not a final authorization decision. Always re-run `is_authorized` once unknowns are bound.

See the [Partial Authorization Guide](docs/guides/partial-authorization-guide.md) for edge cases, residual structure, and advanced patterns (SQL translation, Cedar text re-evaluation).

### Validating policies against a schema

You can use `validate_policies` to validate Cedar policies against a schema before deploying them. Validation catches common mistakes like typos in entity types, invalid actions, type mismatches, and unsafe access to optional attributes—errors that would otherwise cause policies to silently fail at runtime.

This is particularly useful in CI/CD pipelines to catch policy errors before they reach production. See the [Cedar validation documentation](https://docs.cedarpolicy.com/policies/validation.html) for details on what the validator checks.

Here's an example of basic use:

```python
from cedarpy import validate_policies, ValidationResult

policies: str = "// a string containing Cedar policies"
schema: str = "// a Cedar schema as JSON string, Cedar schema string, or Python dict"

result: ValidationResult = validate_policies(policies, schema)

# so you can check validation passed like:
assert result.validation_passed

# or use ValidationResult in a boolean context
assert result  # True if validation passed

# and if validation fails, iterate over errors:
for error in result.errors:
    print(f"error: {error}")

```
The [`ValidationResult`](cedarpy/__init__.py) class provides the validation outcome and a list of `ValidationError` objects when validation fails.

See the [unit tests](tests/unit) for more examples of use and expected behavior.

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

## Developing


You'll need a few things to get started:

* Python +3.9
* Rust and `cargo`

This project is built on the [PyO3](https://docs.rs/pyo3/latest/pyo3/index.html) and [maturin](https://www.maturin.rs/index.html) projects.  These projects are designed to enable Python to use Rust code and vice versa.

The most common development commands are in the `Makefile`

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

`cedar-py` currently passes all 74 tests defined in the `example_use_cases`, `multi`, `ip`, and `decimal` suites. The integration tests also validate policies against schemas when `shouldValidate` is set in the test definition. See [test_cedar_integration_tests.py](tests/integration/test_cedar_integration_tests.py) for details.

#### Corpus tests

The upstream `cedar-integration-tests` repository also ships a fuzzer-generated corpus (`corpus-tests.tar.gz`) — 7,462 test files containing 59,696 individual request cases. cedar-py passes all 59,696. Runs are kept in a separate target since the suite takes a few minutes:

```shell
make corpus-tests
```

The runner mirrors the leniency rules used by the upstream Rust runner (`cedar-testing/tests/cedar-policy/corpus_tests.rs`) and `cedar-java`'s `SharedIntegrationTests`: reasons compared as a set, errors compared by count, and policy/schema parse failures (cedarpy's `NoDecision`) soft-pass when the fixture's expected decision is `Deny`. See [test_cedar_corpus_tests.py](tests/integration/test_cedar_corpus_tests.py) for details.

### Using locally-built artifacts

If you used `make quick` above, then a development build of the `cedarpy` module will already be installed in the virtual environment. 

If you want to use your local `cedarpy` changes in another Python environment, you'll need to build a release with:

```shell
make release
```

The release process will build a wheel and output it into `target/wheels/`

Now you can install that file with pip, e.g.:
```shell
pip install --force-reinstall /path/to/cedar-py/target/wheels/ccedarpy-*.whl
```


## Contributing

This project is in its early stages and contributions are welcome. Please check the project's GitHub [issues](https://github.com/k9securityio/cedar-py/issues) for work we've already identified.

Some ways to contribute are:
* Use the project and report experience and issues
* Document usage and limitations
* Enhance the library with additional functionality you need
* Add test cases, particularly those from [`cedar-integration-tests`](https://github.com/k9securityio/cedar-py/issues/3)

You can reach people interested in this project in the `#cedar-py` channel of the [Cedar Policy Slack workspace](https://communityinviter.com/apps/cedar-policy/cedar-policy-language).
