# sandbox_c

Vendored from the upstream Cedar project's sample data
(`cedar-policy-cli/sample-data/sandbox_c`) to anchor the template-linking unit
tests to official Cedar test data. `policies.cedar` holds the `AccessVacation`
template (a `?principal` slot); `entities.json` is the matching entity store.

The upstream README's `link` walkthrough authorizes without a schema (the
bundled entities carry attributes the sample schema does not declare), so the
schema file is intentionally not vendored — `TemplateUpstreamSandboxCTestCase`
reproduces the schema-free walkthrough.
