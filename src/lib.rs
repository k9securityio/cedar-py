use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::time::Instant;

use anyhow::{Context as _, Error, Result};
use cedar_policy::*;
use cedar_policy_formatter::{Config, policies_str_to_pretty};
use pyo3::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::json;

/// Echo (return) the input string
#[pyfunction]
#[pyo3(signature = (s))]
fn echo(s: String) -> PyResult<String> {
    Ok(s)
}

// Pretty-print the input policy according to the input parameters.
#[pyfunction]
#[pyo3(signature = (s, line_width, indent_width))]
fn format_policies(s: String, line_width: usize, indent_width: isize) -> PyResult<String> {
    let config = Config {
        line_width,
        indent_width,
    };

    match policies_str_to_pretty(&s, &config) {
        Ok(s) => Ok(s),
        Err(e) => Err(pyo3::exceptions::PyValueError::new_err(e.to_string())),
    }
}

#[pyfunction]
#[pyo3(signature = (s))]
fn policies_to_json_str(s: String) -> PyResult<String> {
    match PolicySet::from_str(&s) {
        Ok(p) => match p.to_json() {
            Ok(v) => match serde_json::to_string(&v) {
                Ok(s) => Ok(s),
                Err(e) => Err(pyo3::exceptions::PyValueError::new_err(e.to_string()))
            },
            Err(e) => Err(pyo3::exceptions::PyValueError::new_err(e.to_string()))
        },
        Err(e) => Err(pyo3::exceptions::PyValueError::new_err(e.to_string())),
    }
}

#[pyfunction]
#[pyo3(signature = (s))]
fn policies_from_json_str(s: String) -> PyResult<String> {
    match PolicySet::from_json_str(&s) {
        Ok(p) => Ok(p.to_string()),
        Err(e) => Err(pyo3::exceptions::PyValueError::new_err(e.to_string())),
    }
}


pub struct RequestArgs {
    /// Principal for the request, e.g., User::"alice"
    pub principal: String,
    /// Action for the request, e.g., Action::"view"
    pub action: String,
    /// Resource for the request, e.g., File::"myfile.txt"
    pub resource: String,
    /// A JSON object representing the context for the request.
    /// Should be a (possibly empty) map from keys to values.
    pub context_json: Option<String>,

    /// An optional correlation id that will be copied to the AuthzResponse
    pub correlation_id: Option<String>,
}

impl RequestArgs {
    /// Turn this `RequestArgs` into the appropriate `Request` object
    fn get_request(&self, schema: Option<&Schema>) -> Result<Request> {
        let principal: EntityUid = self.principal.parse().context(format!("Failed to parse principal as entity Uid"))?;
        let action: EntityUid = self.action.parse().context(format!("Failed to parse action as entity Uid"))?;
        let resource: EntityUid = self.resource.parse().context(format!("Failed to parse resource as entity Uid"))?;
        let context: Context = match &self.context_json {
            None => Context::empty(),
            Some(context_json_str) => {
                // Must provide action EUID because actions define their own schemas
                Context::from_json_str(context_json_str,
                                       schema.and_then(|s| Some((s, &action))))?
            },
        };
        Ok(Request::new(principal, action, resource, context, schema)?)
    }
}

#[pyfunction]
#[pyo3(signature = (request, policies, entities, schema = None, verbose = false,))]
fn is_authorized(request: HashMap<String, String>,
                 policies: String,
                 entities: String,
                 schema: Option<String>,
                 verbose: Option<bool>)
                 -> String {
    is_authorized_batch(vec![request], policies, entities, schema, verbose)[0].clone()
}

#[pyfunction]
#[pyo3(signature = (requests, policies, entities, schema = None, verbose = false,))]
fn is_authorized_batch(requests: Vec<HashMap<String, String>>,
                       policies: String,
                       entities: String,
                       schema: Option<String>,
                       verbose: Option<bool>)
                       -> Vec<String> {
    // CLI AuthorizeArgs: https://github.com/cedar-policy/cedar/blob/main/cedar-policy-cli/src/lib.rs#L183
    let verbose = verbose.unwrap_or(false);
    if verbose {
        //println!("requests: {}", requests);
        println!("policies: {}", policies);
        println!("entities: {}", entities);
        println!("schema: {}", schema.clone().unwrap_or(String::from("<none>")));
    }
    let mut errs: Vec<Error> = vec![];

    // probably need to deconstruct execute_authorization_request so that we can reuse the
    // expensive parts (policies, entities, schema):
    // parse policies
    let t_parse_policies = Instant::now();
    let policy_set = match PolicySet::from_str(&policies) {
        Ok(pset) => pset,
        Err(parse_errors) => {
            let err_message = format!("policy parse errors:\n{:#}",
                                      parse_errors.to_string());
            println!("{:#}", err_message);
            errs.push(Error::msg(err_message));
            PolicySet::new()
        }
    };
    let t_parse_policies_duration = t_parse_policies.elapsed();

    // parse schema
    let t_start_schema = Instant::now();
    let schema = make_schema(&schema, verbose, &mut errs);
    let t_parse_schema_duration = t_start_schema.elapsed();

    // load entities
    let t_load_entities = Instant::now();
    let entities = make_entities(entities, &schema, &mut errs);
    let t_load_entities_duration = t_load_entities.elapsed();

    // build a list of RequestArgs
    let mut request_args_vec: Vec<RequestArgs> = Vec::new();
    requests.iter().for_each(|request: &HashMap<String, String>| {
        request_args_vec.push(to_request_args(request));
    });

    let mut responses_vec: Vec<String> = Vec::new();

    // evaluate access one at a time (future work: eval in parallel)
    for request_args in request_args_vec.iter() {
        if errs.is_empty() {
            let ans = execute_authorization_request(&request_args,
                                                    &policy_set,
                                                    &entities,
                                                    &schema,
                                                    verbose);
            let response_string: String = match ans {
                Ok(mut ans) => {
                    ans.metrics.insert(String::from("parse_policies_duration_micros"),
                                       t_parse_policies_duration.as_micros());
                    ans.metrics.insert(String::from("parse_schema_duration_micros"),
                                       t_parse_schema_duration.as_micros());
                    ans.metrics.insert(String::from("load_entities_duration_micros"),
                                       t_load_entities_duration.as_micros());

                    let to_json_str_result = serde_json::to_string(&ans);
                    match to_json_str_result {
                        Ok(json_str) => { json_str }
                        Err(err) => {
                            println!("{:#}", err);
                            make_authz_result_for_errors(&vec![Error::from(err)])
                        }
                    }
                }
                Err(errs) => {
                    for err in &errs {
                        println!("{:#}", err);
                    }
                    make_authz_result_for_errors(&errs)
                }
            };
            responses_vec.push(response_string);
        } else {
            responses_vec.push(make_authz_result_for_errors(&errs))
        }

    }

    return responses_vec;
}

fn make_authz_result_for_errors(errs: &Vec<Error>) -> String {
    let json_obj = json!(
        {
            "decision": "NoDecision",
            "diagnostics": {
                "errors": stringify_errors(&errs)
            }
        });

    return json_obj.to_string();
}

fn stringify_errors(errs: &Vec<Error>) -> Vec<String> {
    errs.iter().map(|e| e.to_string()).collect()
}

fn to_request_args(request: &HashMap<String, String>) -> RequestArgs {
    // collect request arguments into a struct compatible with authorization request
    let principal: String = request.get(String::from("principal").as_str()).unwrap().to_string();
    let action: String = request.get(String::from("action").as_str()).unwrap().to_string();
    let resource: String = request.get(String::from("resource").as_str()).unwrap().to_string();
    let correlation_id: Option<String> = request.get(String::from("correlation_id").as_str()).cloned();

    let context_option = request.get(String::from("context").as_str());
    let context_json: Option<String> = match context_option {
        None => None, // context member not present
        Some(context) => Some(context.to_string())
    };

    RequestArgs {
        principal,
        action,
        resource,
        context_json,
        correlation_id,
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct DiagnosticsSer {
    /// Ids of the policies that contributed to the decision, as the
    /// parser-generated `PolicyId` (e.g., `policy0`). If no policies applied
    /// to the request, this set will be empty.
    ///
    /// The parser id is stable per policy within a `PolicySet` and uniquely
    /// identifies each matched policy even when multiple policies share the
    /// same `@id` annotation. To recover the `@id` annotation value for any
    /// entry, look it up in `id_annotations_by_reason`.
    reason: HashSet<PolicyId>,
    /// Map from each parser-generated policy id in `reason` to the literal
    /// value of its `@id` annotation, when the matched policy declares one.
    /// `@id("foo")` contributes `"foo"`; `@id("")` / `@id` (which the Cedar
    /// docs define as equivalent to `@id("")`) contributes `""`. Policies
    /// with no `@id` annotation are omitted from the map.
    id_annotations_by_reason: HashMap<String, String>,
    /// Errors that occurred during authorization. The errors should be
    /// treated as unordered, since policies may be evaluated in any order.
    errors: Vec<String>,
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub enum DecisionSer {
    /// The `Authorizer` determined that the request should be allowed
    Allow,
    /// The `Authorizer` determined that the request should be denied.
    /// This is also returned if sufficiently fatal errors are encountered such
    /// that no decision could be safely reached; for example, errors parsing
    /// the policies.
    Deny,
}

/// Authorization response returned from the `Authorizer`
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
struct AuthzResponse {
    /// Authorization decision
    decision: DecisionSer,

    /// (Optional) id to correlate this response to the request
    correlation_id: Option<String>,

    /// Diagnostics providing more information on how this decision was reached
    diagnostics: DiagnosticsSer,

    /// Metrics providing timing information on the authorization decision
    metrics: HashMap<String, u128>,
}

/// Serializable validation error for Python
#[derive(Debug, Serialize, Deserialize)]
pub struct ValidationErrorSer {
    /// Parser-generated policy id (e.g., `policy0`) where the error occurred.
    /// To recover the `@id` annotation value when present, look up this id in
    /// `ValidationResultSer::id_annotations_by_policy_id`.
    policy_id: String,
    /// Human-readable error message
    error: String,
}

/// Serializable validation result for Python
#[derive(Debug, Serialize, Deserialize)]
pub struct ValidationResultSer {
    /// Whether validation passed (no errors)
    validation_passed: bool,
    /// List of validation errors
    errors: Vec<ValidationErrorSer>,
    /// Map from each parser-generated policy id appearing in `errors` to
    /// the literal value of its `@id` annotation, when the source policy
    /// declares one. `@id("foo")` contributes `"foo"`; `@id("")` / `@id`
    /// (which the Cedar docs define as equivalent to `@id("")`) contributes
    /// `""`. Policies with no `@id` annotation are omitted from the map.
    id_annotations_by_policy_id: HashMap<String, String>,
}

impl AuthzResponse {
    /// Create a new `AuthzResponse`.
    ///
    /// `policy_set` is the parsed `PolicySet` that produced `response`; it is
    /// used to look up the `@id` annotation (if any) for each matched
    /// `PolicyId`. Annotations are inert in Cedar policy evaluation;
    /// `reason` carries the parser-generated id and the optional
    /// `id_annotations_by_reason` map carries the labels.
    pub fn new(response: Response,
               policy_set: &PolicySet,
               metrics: HashMap<String, u128>,
               correlation_id: Option<String>) -> Self {
        let mut reason: HashSet<PolicyId> = HashSet::new();
        let mut id_annotations_by_reason: HashMap<String, String> = HashMap::new();
        for pid in response.diagnostics().reason() {
            if let Some(annotation) = lookup_id_annotation(policy_set, pid) {
                id_annotations_by_reason.insert(pid.to_string(), annotation);
            }
            reason.insert(pid.clone());
        }
        Self {
            decision: match response.decision() {
                Decision::Allow => DecisionSer::Allow,
                Decision::Deny => DecisionSer::Deny
            },
            correlation_id,
            diagnostics: DiagnosticsSer{
                reason,
                id_annotations_by_reason,
                errors: response.diagnostics().errors().cloned().map(|e|e.to_string()).collect(),
            },
            metrics,
        }
    }
}

/// This uses the Cedar API to call the authorization engine.
fn execute_authorization_request(
    request_args: &RequestArgs,
    policy_set: &PolicySet,
    entities: &Entities,
    schema: &Option<Schema>,
    verbose: bool
) -> Result<AuthzResponse, Vec<Error>> {
    let mut errs: Vec<Error> = vec![];
    let t_build_request = Instant::now();

    // may want to create request in calling method; then we could get relocate errs
    let request = match request_args.get_request(schema.as_ref()) {
        Ok(q) => Some(q),
        Err(e) => {
            errs.push(e.context("failed to parse schema from request"));
            None
        }
    };
    let build_request_duration = t_build_request.elapsed();
    if errs.is_empty() {
        let request = request.expect("if no errors, we should have a valid request");
        let authorizer = Authorizer::new();
        let t_authz = Instant::now();
        let ans = authorizer.is_authorized(&request, &policy_set, &entities);
        let metrics = HashMap::from([
            (String::from("build_request_duration_micros"), build_request_duration.as_micros()),
            (String::from("authz_duration_micros"), t_authz.elapsed().as_micros()),
        ]);
        let authz_response = AuthzResponse::new(ans, policy_set, metrics,
                                                request_args.correlation_id.clone());
        Ok(authz_response)
    } else {
        if verbose {
            println!("encountered errors while building request. \nerrs: {:#?} ", errs);
        }
        Err(errs)
    }
}

fn make_entities(entities_str: String, schema: &Option<Schema>, errs: &mut Vec<Error>) -> Entities {
    match load_entities(entities_str, schema.as_ref()) {
        Ok(entities) => entities,
        Err(e) => {
            errs.push(e);
            Entities::empty()
        }
    }
}

fn make_schema(schema_str: &Option<String>, verbose: bool, errs: &mut Vec<Error>) -> Option<Schema> {
    let schema: Option<Schema> = match &schema_str {
        None => None,
        Some(schema_src) => {
            if verbose {
                println!("schema: {}", schema_src);
            }

            let trimmed_schema_src = schema_src.trim();

            if trimmed_schema_src.is_empty() {
                return None;
            }

            if trimmed_schema_src.starts_with('{') {
                match Schema::from_json_str(trimmed_schema_src) {
                    Ok(schema) => Some(schema),
                    Err(json_err) => {
                        if verbose {
                            println!("!!! could not construct schema from JSON: {}", json_err);
                        }
                        errs.push(Error::msg(format!("failed to parse schema from JSON: {}", json_err)));
                        None
                    }
                }
            } else {
                match Schema::from_str(trimmed_schema_src) {
                    Ok(schema) => Some(schema),
                    Err(str_err) => {
                        if verbose {
                            println!("!!! could not construct schema from str: {}", str_err);
                        }
                        errs.push(Error::msg(format!("failed to parse schema from Cedar: {}", str_err)));
                        None
                    }
                }
            }
        }
    };
    schema
}

/// Load an `Entities` object from the given JSON string and optional schema.
fn load_entities(entities_str: String, schema: Option<&Schema>) -> Result<Entities> {
    return Entities::from_json_str(&entities_str, schema).context(format!(
        "failed to parse entities from:\n{}", entities_str)
    );
}

/// Look up the `@id` annotation value for a policy, if the policy declares
/// one. Returns `Some(value)` whenever `@id` is present — including the
/// empty string for `@id` / `@id("")`, per the Cedar docs which treat the
/// two as equivalent. Returns `None` only when the policy has no `@id`
/// annotation at all, or when no policy exists for `pid` in `policy_set`.
///
/// `Policy::annotations()` returns raw `&str` keys, so we can match on `"id"`
/// without paying Cedar's identifier-parse cost (which `PolicySet::annotation`
/// would incur per lookup). Static policies and template-linked policies both
/// resolve via `policy_set.policy(pid)`.
fn lookup_id_annotation(policy_set: &PolicySet, pid: &PolicyId) -> Option<String> {
    let p = policy_set.policy(pid)?;
    let (_, v) = p.annotations().find(|(k, _)| *k == "id")?;
    Some(v.to_string())
}

/// Validate Cedar policies against a schema and return a JSON result.
#[pyfunction]
#[pyo3(signature = (policies, schema))]
fn validate_policies(policies: String, schema: String) -> String {
    // Parse policies
    let policy_set = match PolicySet::from_str(&policies) {
        Ok(pset) => pset,
        Err(parse_errors) => {
            let result = ValidationResultSer {
                validation_passed: false,
                errors: vec![ValidationErrorSer {
                    policy_id: String::new(),
                    error: format!("Policy parse error: {}", parse_errors),
                }],
                id_annotations_by_policy_id: HashMap::new(),
            };
            return serde_json::to_string(&result).unwrap();
        }
    };

    // Parse schema (required for validation)
    let trimmed_schema = schema.trim();
    if trimmed_schema.is_empty() {
        let result = ValidationResultSer {
            validation_passed: false,
            errors: vec![ValidationErrorSer {
                policy_id: String::new(),
                error: "Schema is required for validation".to_string(),
            }],
            id_annotations_by_policy_id: HashMap::new(),
        };
        return serde_json::to_string(&result).unwrap();
    }

    // Parse schema - handle JSON and Cedar schema syntax separately since they have different error types
    let cedar_schema: Schema = if trimmed_schema.starts_with('{') {
        match Schema::from_json_str(trimmed_schema) {
            Ok(s) => s,
            Err(e) => {
                let result = ValidationResultSer {
                    validation_passed: false,
                    errors: vec![ValidationErrorSer {
                        policy_id: String::new(),
                        error: format!("Schema parse error: {}", e),
                    }],
                    id_annotations_by_policy_id: HashMap::new(),
                };
                return serde_json::to_string(&result).unwrap();
            }
        }
    } else {
        match Schema::from_str(trimmed_schema) {
            Ok(s) => s,
            Err(e) => {
                let result = ValidationResultSer {
                    validation_passed: false,
                    errors: vec![ValidationErrorSer {
                        policy_id: String::new(),
                        error: format!("Schema parse error: {}", e),
                    }],
                    id_annotations_by_policy_id: HashMap::new(),
                };
                return serde_json::to_string(&result).unwrap();
            }
        }
    };

    // Create validator and validate
    let validator = Validator::new(cedar_schema);
    let validation_result = validator.validate(&policy_set, ValidationMode::default());

    // Validation runs against parser-generated PolicyIds; we surface those
    // verbatim on each error and provide a side map of `@id` annotation
    // labels for the same ids. Reverted from the 4.8.2 behavior of renaming
    // policy_id to the `@id` annotation value at response time, which
    // collapsed identity when multiple policies shared the same `@id` —
    // see https://github.com/k9securityio/cedar-py/issues/77.
    let mut id_annotations_by_policy_id: HashMap<String, String> = HashMap::new();
    let errors: Vec<ValidationErrorSer> = validation_result
        .validation_errors()
        .map(|e| {
            let pid_str = e.policy_id().to_string();
            if let Some(annotation) = lookup_id_annotation(&policy_set, e.policy_id()) {
                id_annotations_by_policy_id.insert(pid_str.clone(), annotation);
            }
            ValidationErrorSer {
                policy_id: pid_str,
                error: e.to_string(),
            }
        })
        .collect();
    let result = ValidationResultSer {
        validation_passed: validation_result.validation_passed(),
        errors,
        id_annotations_by_policy_id,
    };

    serde_json::to_string(&result).unwrap()
}

/// Serializable partial authorization response for Python
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PartialAuthzResponse {
    decision: Option<DecisionSer>,
    correlation_id: Option<String>,
    diagnostics: DiagnosticsSer,
    residuals: HashMap<String, serde_json::Value>,
    metrics: HashMap<String, u128>,
}

#[pyfunction]
#[pyo3(signature = (request, policies, entities, schema = None, verbose = false))]
fn is_authorized_partial(
    request: HashMap<String, Option<String>>,
    policies: String,
    entities: String,
    schema: Option<String>,
    verbose: Option<bool>,
) -> String {
    let verbose = verbose.unwrap_or(false);
    let mut errs: Vec<Error> = vec![];

    let t_parse_policies = Instant::now();
    let policy_set = match PolicySet::from_str(&policies) {
        Ok(pset) => pset,
        Err(parse_errors) => {
            let err_message = format!("policy parse errors:\n{:#}", parse_errors);
            if verbose { println!("{:#}", err_message); }
            errs.push(Error::msg(err_message));
            PolicySet::new()
        }
    };
    let t_parse_policies_duration = t_parse_policies.elapsed();

    let t_start_schema = Instant::now();
    let schema = make_schema(&schema, verbose, &mut errs);
    let t_parse_schema_duration = t_start_schema.elapsed();

    let t_load_entities = Instant::now();
    let entities = make_entities(entities, &schema, &mut errs).partial();
    let t_load_entities_duration = t_load_entities.elapsed();

    if !errs.is_empty() {
        return make_partial_result_for_errors(&errs);
    }

    let t_build_request = Instant::now();
    let principal_str = request.get("principal").and_then(|v| v.as_deref());
    let action_str = request.get("action").and_then(|v| v.as_deref());
    let resource_str = request.get("resource").and_then(|v| v.as_deref());
    let context_str = request.get("context").and_then(|v| v.as_deref());
    let correlation_id = request.get("correlation_id").and_then(|v| v.clone());

    let mut builder = Request::builder();

    if let Some(p) = principal_str {
        match p.parse::<EntityUid>() {
            Ok(uid) => { builder = builder.principal(uid); }
            Err(e) => {
                errs.push(Error::msg(format!("Failed to parse principal as entity Uid: {}", e)));
                return make_partial_result_for_errors(&errs);
            }
        }
    }

    if let Some(a) = action_str {
        match a.parse::<EntityUid>() {
            Ok(uid) => { builder = builder.action(uid); }
            Err(e) => {
                errs.push(Error::msg(format!("Failed to parse action as entity Uid: {}", e)));
                return make_partial_result_for_errors(&errs);
            }
        }
    }

    if let Some(r) = resource_str {
        match r.parse::<EntityUid>() {
            Ok(uid) => { builder = builder.resource(uid); }
            Err(e) => {
                errs.push(Error::msg(format!("Failed to parse resource as entity Uid: {}", e)));
                return make_partial_result_for_errors(&errs);
            }
        }
    }

    if let Some(ctx_json) = context_str {
        let action_uid: Option<EntityUid> = action_str.and_then(|a| a.parse().ok());
        match Context::from_json_str(ctx_json, schema.as_ref().and_then(|s| action_uid.as_ref().map(|a| (s, a)))) {
            Ok(ctx) => { builder = builder.context(ctx); }
            Err(e) => {
                errs.push(Error::msg(format!("Failed to parse context: {}", e)));
                return make_partial_result_for_errors(&errs);
            }
        }
    }

    let cedar_request = match &schema {
        Some(s) => match builder.schema(s).build() {
            Ok(r) => r,
            Err(e) => {
                errs.push(Error::msg(format!("Request validation failed: {}", e)));
                return make_partial_result_for_errors(&errs);
            }
        },
        None => builder.build(),
    };
    let build_request_duration = t_build_request.elapsed();

    let authorizer = Authorizer::new();
    let t_authz = Instant::now();
    let partial_response = authorizer.is_authorized_partial(&cedar_request, &policy_set, &entities);
    let authz_duration = t_authz.elapsed();

    let decision = partial_response.decision().map(|d| match d {
        Decision::Allow => DecisionSer::Allow,
        Decision::Deny => DecisionSer::Deny,
    });

    let mut reason: HashSet<PolicyId> = HashSet::new();
    let mut id_annotations_by_reason: HashMap<String, String> = HashMap::new();
    for policy in partial_response.definitely_satisfied() {
        let pid = policy.id().clone();
        if let Some(annotation) = lookup_id_annotation(&policy_set, &pid) {
            id_annotations_by_reason.insert(pid.to_string(), annotation);
        }
        reason.insert(pid);
    }
    let errors: Vec<String> = partial_response.definitely_errored()
        .map(|pid| format!("while evaluating policy `{}`: evaluation error", pid))
        .collect();
    let mut residuals: HashMap<String, serde_json::Value> = HashMap::new();
    for policy in partial_response.all_residuals() {
        let pid_str = policy.id().to_string();
        if let Some(annotation) = lookup_id_annotation(&policy_set, policy.id()) {
            id_annotations_by_reason.insert(pid_str.clone(), annotation);
        }
        residuals.insert(pid_str, policy.to_json().unwrap_or(json!(null)));
    }

    let metrics = HashMap::from([
        (String::from("parse_policies_duration_micros"), t_parse_policies_duration.as_micros()),
        (String::from("parse_schema_duration_micros"), t_parse_schema_duration.as_micros()),
        (String::from("load_entities_duration_micros"), t_load_entities_duration.as_micros()),
        (String::from("build_request_duration_micros"), build_request_duration.as_micros()),
        (String::from("authz_duration_micros"), authz_duration.as_micros()),
    ]);

    let response = PartialAuthzResponse {
        decision,
        correlation_id,
        diagnostics: DiagnosticsSer { reason, id_annotations_by_reason, errors },
        residuals,
        metrics,
    };

    serde_json::to_string(&response).unwrap()
}

fn make_partial_result_for_errors(errs: &[Error]) -> String {
    let json_obj = json!({
        "errors": errs.iter().map(|e| e.to_string()).collect::<Vec<_>>(),
    });
    serde_json::to_string(&json_obj).unwrap()
}

/// A Python module implemented in Rust.
#[pymodule]
fn _internal(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(echo, m)?)?;
    m.add_function(wrap_pyfunction!(is_authorized, m)?)?;
    m.add_function(wrap_pyfunction!(is_authorized_batch, m)?)?;
    m.add_function(wrap_pyfunction!(is_authorized_partial, m)?)?;
    m.add_function(wrap_pyfunction!(format_policies, m)?)?;
    m.add_function(wrap_pyfunction!(policies_to_json_str, m)?)?;
    m.add_function(wrap_pyfunction!(policies_from_json_str, m)?)?;
    m.add_function(wrap_pyfunction!(validate_policies, m)?)?;
    Ok(())
}
