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
    <tr><td>v4.8.2</td><td>v4.8.5</td><td>main</td></tr>
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

Parsing the policy set (`PolicySet::from_str`) is the dominant per-call cost in `is_authorized`. When your policies are static, for example a code-checked policy set loaded once at startup in a long-running service or AWS Lambda, you can parse them a single time into a reusable `PolicySet` handle and pass that handle wherever you'd pass a policies string. This skips the re-parse on every call.

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

The `PolicySet` handle is accepted anywhere a policies string is accepted: `is_authorized`, `is_authorized_batch`, and `is_authorized_partial`. Passing a plain string still works exactly as before; the handle is purely opt-in and fully backwards compatible. The handle's memory is released automatically when the last Python reference is dropped.

A `PolicySet` can also be built from the Cedar JSON (EST) policy format with `PolicySet.from_json_str(...)`, and supports `len(policy_set)` (number of policies) and `str(policy_set)` (the policy set rendered back to Cedar text).

This complements batch authorization: batching amortizes entity/schema parsing across a set of requests evaluated together, while a reusable `PolicySet` amortizes policy parsing across calls made at different times. The two compose. The speedup grows with policy size — in the project's benchmark suite (release build, ~10-entity calls) reuse is ~1.3x on a single-rule policy but ~9x on a typical production-scale policy (~16 KB / 60 rules), where it removes ~1.4 ms of policy parsing per call.

On a successful evaluation the result's `metrics` reflect the reuse: `parse_policies_duration_micros` measures only the (near-zero) borrow rather than the original parse, and `metrics["policies_pre_parsed"]` is `1` (it is `0` when policies are passed as a string and parsed on that call). As with all `metrics`, these keys are present only on successful evaluations — an error result carries an empty `metrics` map.

**Advanced: adding per-request policies to a static base.** Most callers reuse a single static `PolicySet` as above. If, however, your policy set is *mostly* static but a few policies vary per request, you don't have to re-parse the whole base text each time — `PolicySet.with_added_str(fragment)` clones the compiled base and parses only the fragment, returning a **new** handle (the base is left unchanged):

```python
base = PolicySet.from_str(static_policies)        # parse the large static base once

# per request: add only the small dynamic fragment — the base is not re-parsed
for_request = base.with_added_str(per_request_policies)
authz_result = is_authorized(request, for_request, entities)
```

The result is equivalent to authorizing against the concatenated base-plus-fragment text. (Cedar assigns surface-syntax policies a positional `PolicyId` — `policy0`, `policy1`, … — per parse, so a fragment parsed on its own restarts at `policy0`; `with_added_str` renumbers the fragment's colliding ids to follow the base, exactly as concatenation would, and any `@id("...")` annotations are preserved and still resolve via `diagnostics.id_annotations_by_reason`.)

### Reusing parsed entities for performance

Entities are parsed on each call too: `is_authorized` deserializes the entities JSON and computes the transitive closure of the `parents` graph. When you authorize many requests against a large, stable entity graph, you can parse it once into a reusable `Entities` handle and pass it wherever you'd pass an entities string or list:

```python
from cedarpy import Entities, PolicySet, is_authorized

base = Entities.from_json_str(entities_json)       # parse the stable graph once
authz_result = is_authorized(request, policy_set, base)
```

The common shape is a large, stable base graph (your organization's users and groups, say) plus a small set of entities that are specific to each request (the resources being acted on). Build the base once and merge the per-request delta with `with_added_json_str`, which parses **only the delta** and returns a new handle — the base is immutable and reused across every request:

```python
base = Entities.from_json_str(org_graph_json)      # users, groups: parsed once, reused

for request in requests:
    # add only this request's entities (e.g. the documents involved); base is not re-parsed
    for_request = base.with_added_json_str(request_entities_json)
    is_authorized(request, policy_set, for_request)
```

`with_added_json_str` is a disjoint union: a delta entity whose uid already exists in the base (and is not identical) raises `ValueError`. An optional `schema` argument to `from_json_str` / `with_added_json_str` validates the entities at construction. The handle is accepted anywhere an entities string/list is accepted (`is_authorized`, `is_authorized_batch`, `is_authorized_partial`), supports `len()` and `str()`, and sets `metrics["entities_pre_parsed"]` to `1` on the reuse path. As with the `PolicySet` handle, passing a string or list still works unchanged — the handle is purely opt-in.

> Note: the `Entities` and `PolicySet` handles are independent and compose — reuse whichever inputs are stable for your workload, or both. Schema is still parsed on each call.

### Linking policy templates

A Cedar [policy template](https://docs.cedarpolicy.com/policies/templates.html) is a policy with `?principal` / `?resource` *slots* — a rule written once and then *linked* to concrete entities to produce real, evaluatable policies. The canonical case is per-principal and per-resource grants — *allow this person to view this photo while their subscription is active*. You write that rule once as a template, then link it per grant.

`PolicySet.from_str` already parses templates; they just authorize nothing until linked. `with_linked` fills a template's slots and returns a **new** `PolicySet` handle (immutable, like `with_added_str` — the base is left unchanged):

```python
from cedarpy import PolicySet, is_authorized, Decision

# one rule: a subscriber may view a photo that's been granted to them
base = PolicySet.from_str(
    '@id("photo-access")\n'
    'permit(principal == ?principal, action == Action::"view", resource == ?resource)\n'
    'when { principal.subscriptionActive };'
)

# fill the slots to grant alice access to one photo
linked = base.with_linked(
    template_id="photo-access",          # which template to fill in
    new_id="alice-vacation",             # id for this link (the filled slots, which act as a policy)
    values={"?principal": 'User::"alice"', "?resource": 'Photo::"vacation.jpg"'},
)

# alice's subscription is active, so she may view the photo
entities = [{"uid": {"type": "User", "id": "alice"},
             "attrs": {"subscriptionActive": True}, "parents": []}]
request = {"principal": 'User::"alice"', "action": 'Action::"view"', "resource": 'Photo::"vacation.jpg"'}

result = is_authorized(request, linked, entities)
assert result.decision == Decision.Allow

# the decision points at the link's own id; the template's @id comes alongside it
result.diagnostics.reasons                    # ['alice-vacation']
result.diagnostics.id_annotations_by_reason   # {'alice-vacation': 'photo-access'}
```

Linking produces a *template-linked policy* — the slots filled with concrete values, which evaluates as a policy in its own right — and `new_id` is the id assigned to it. Linking does not rename or consume the template: the template stays in the set, so you can link it again under a different `new_id` to grant another principal (that's the whole point — one template, many grants). `new_id` is yours to choose; it is neither a template id nor a principal. (This mirrors the Cedar CLI's `link --template-id … --new-id …`.)

To grant many principals at once, use `with_linked_batch`. It is the primary linking path: it clones the base **once** and applies every link to that clone, so a batch pays a single clone rather than one per link, and it is all-or-nothing (if any link fails the whole call raises and no handle is returned):

```python
linked = base.with_linked_batch([
    {"template_id": "photo-access", "new_id": "alice-vacation",
     "values": {"?principal": 'User::"alice"', "?resource": 'Photo::"vacation.jpg"'}},
    {"template_id": "photo-access", "new_id": "bob-skyline",
     "values": {"?principal": {"type": "User", "id": "bob"}, "?resource": 'Photo::"skyline.jpg"'}},
])
```

A slot value is given as a Cedar string (`'User::"alice"'`) or a `{"type": ..., "id": ...}` dict — the same two forms `is_authorized` accepts for a request principal/resource. A linked `PolicySet` is still just a `PolicySet`, so it works everywhere a policies string or handle does (`is_authorized`, `is_authorized_batch`, `is_authorized_partial`), and existing callers are untouched. Note that the slots fill only the principal and resource; the `when { principal.subscriptionActive }` condition is fixed in the template and shared by every link — write the rule (and its conditions) once, vary only who and what.

**Identify a template by its `@id`, not its positional id.** Cedar assigns a surface-syntax policy a positional id — `policy0`, `policy1`, … — per parse, and that position can shift (`with_added_str`, for example, renumbers an incoming fragment's ids when it layers them onto a base). A template's `@id` annotation is invariant across parsing and merging, so it is the stable key to link against. `with_linked` accepts either — it matches the literal id first, then the `@id` — but prefer the `@id`. The match must be unambiguous; two templates sharing one `@id` raises rather than guessing. (An `@id` is [otherwise inert](https://docs.cedarpolicy.com/policies/syntax-policy.html#term-parc-annotations) and is not the template's id; cedarpy resolves it the way the Cedar CLI's `link` command does.)

`templates()` returns the full picture — each template's ids, the slots it needs, and the links (fillings) produced from it:

```python
linked.templates()
# [{'id': 'policy0',                       # positional id (the fragile one)
#   'id_annotation': 'photo-access',       # the @id — the stable key to link by
#   'slots': ['?principal', '?resource'],  # the slot keys a link must fill
#   'links': [                             # the concrete policies produced from this template
#       {'id': 'alice-vacation',
#        'values': {'?principal': 'User::"alice"', '?resource': 'Photo::"vacation.jpg"'}},
#       {'id': 'bob-skyline',
#        'values': {'?principal': 'User::"bob"', '?resource': 'Photo::"skyline.jpg"'}}]}]

# the link ids live under each template's 'links'; pass one to without_linked
# to revoke that grant — returns a NEW handle; `linked` is unchanged
revoked = linked.without_linked("bob-skyline")
# revoked.templates()[0]['links'] now lists only alice-vacation
```

`templates()` is the one introspection call you need: each template's `id` / `id_annotation` / `slots`, and the `links` produced from it (each link's `id` and bound `values`). To act on a single grant — e.g. revoke it — read its id from `links` and pass it to `without_linked(link_id)`. (Order within `templates` and `links` is not guaranteed.)

A linked policy carries two distinct labels, which matters when you read diagnostics. Its **id** is the `new_id` you gave it (`alice-vacation`) — unique to that link, and what appears in `result.diagnostics.reasons` when it fires. Its **`@id`** is *inherited from the template* (`photo-access`) — so every link of one template shares the same `@id` while keeping a distinct id. That is why a matched policy is identified by its id, not its `@id`: link a template for ten grants and ten policies share the `@id`, but each has its own id.

Because an unlinked template is inert — the authorizer only ever evaluates linked and static policies, never the templates themselves — you can parse a whole catalogue of templates into the base once and link only the ones a given request needs; the unused templates cost nothing at evaluation time.

**Should you reach for templates?** It depends on your policies and scale, and it's worth measuring rather than assuming. You would be right to suspect that at small scale and low complexity, generating a policy string per principal and parsing it is the more efficient choice — lower CPU *and* lower memory than linking, since parsing a short policy is cheaper than the per-link work of binding entity uids and cloning the rule's form. The two reach parity once the policy carries a few conditions, and templates pull ahead from there as the body gets richer — the rule is parsed and held *once* instead of copied per grant. In a quick build benchmark at 200 grants, a one-condition policy (like the subscription rule above) still favored generate-and-parse, a ~4-condition policy was about even, and a rich ~10-condition grant built about 2× faster and used about 2.5× less memory as a template. So profile your own policy shapes and grant counts, and take whichever approach gives the best result for your use case.

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
