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

//
// ANALYSIS
// ----------------------------------------
// Matches the behavior of cedar-lean-cli's `analyze policies` and `analyze compare` commands.
// See: cedar-spec/cedar-lean-cli/src/analysis.rs

use cedar_policy_symcc::solver::LocalSolver;
use cedar_policy_symcc::{CedarSymCompiler, CompiledPolicy, CompiledPolicySet, Env};

fn format_counterexample(env: &Env) -> String {
    let principal = env.request.principal().map_or_else(|| "unknown".to_string(), |p| p.to_string());
    let action = env.request.action().map_or_else(|| "unknown".to_string(), |a| a.to_string());
    let resource = env.request.resource().map_or_else(|| "unknown".to_string(), |r| r.to_string());
    format!("principal: {principal}, action: {action}, resource: {resource}")
}

// -- Compare types --

#[derive(Serialize)]
struct CompareResultSer {
    request_type_comparisons: Vec<RequestTypeComparisonSer>,
}

#[derive(Serialize)]
struct RequestTypeComparisonSer {
    action: String,
    /// "equivalent", "less_permissive", "more_permissive", "incomparable"
    result: String,
    /// Counterexample where pset1 is more permissive (allows but pset2 denies)
    more_permissive_example: Option<String>,
    /// Counterexample where pset1 is less permissive (denies but pset2 allows)
    less_permissive_example: Option<String>,
}

// -- Analyze types --

/// Vacuity of a policy or policyset for a single request environment.
#[derive(Clone, Copy, PartialEq)]
enum VacuityResult {
    MatchesAll,
    MatchesSome,
    MatchesNone,
}

/// Aggregate vacuity across all request environments.
fn vacuity_across_envs(results: &[VacuityResult]) -> VacuityResult {
    if results.iter().all(|r| *r == VacuityResult::MatchesAll) {
        VacuityResult::MatchesAll
    } else if results.iter().all(|r| *r == VacuityResult::MatchesNone) {
        VacuityResult::MatchesNone
    } else {
        VacuityResult::MatchesSome
    }
}

#[derive(Serialize)]
struct AnalyzeResultSer {
    /// Policyset-level vacuity: "matches_all", "matches_some", "matches_none"
    policyset_vacuity: String,
    /// Per-policy findings (only vacuous policies included, matching CLI behavior)
    vacuous_policies: Vec<VacuousPolicySer>,
    /// Per request type findings (redundancy, shadowing, overriding)
    per_request_type_findings: Vec<PerRequestTypeFindings>,
}

#[derive(Serialize)]
struct VacuousPolicySer {
    policy_id: String,
    effect: String,
    /// "matches_all" or "matches_none"
    vacuity: String,
}

#[derive(Serialize)]
struct PerRequestTypeFindings {
    action: String,
    redundant_groups: Vec<Vec<String>>,
    permit_shadowed_by_permit: Vec<ShadowedFinding>,
    permit_overridden_by_forbid: Vec<ShadowedFinding>,
    forbid_shadowed_by_forbid: Vec<ShadowedFinding>,
}

#[derive(Serialize)]
struct ShadowedFinding {
    policy_id: String,
    by_policy_id: String,
}

/// Compare two Cedar policy sets per request type, matching cedar-lean-cli `analyze compare`.
///
/// Uses check_implies_with_counterexample in both directions (matching the CLI)
/// to classify as equivalent/less_permissive/more_permissive/incomparable per action.
#[pyfunction]
#[pyo3(signature = (baseline_policies, new_policies, schema))]
fn compare_policy_sets(baseline_policies: String, new_policies: String, schema: String) -> PyResult<String> {
    let pset1 = PolicySet::from_str(&baseline_policies)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Failed to parse baseline policies: {e}")))?;
    let pset2 = PolicySet::from_str(&new_policies)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Failed to parse new policies: {e}")))?;
    let schema = Schema::from_str(schema.trim())
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Failed to parse schema: {e}")))?;

    let py_rt_err = |e: cedar_policy_symcc::err::Error| pyo3::exceptions::PyRuntimeError::new_err(e.to_string());

    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
    rt.block_on(async {
        let solver = LocalSolver::cvc5()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("Failed to start CVC5 solver: {e}")))?;
        let mut compiler = CedarSymCompiler::new(solver)
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;

        let mut comparisons = Vec::new();

        for req_env in schema.request_envs() {
            let action = req_env.action().to_string();
            let compiled1 = CompiledPolicySet::compile(&pset1, &req_env, &schema).map_err(py_rt_err)?;
            let compiled2 = CompiledPolicySet::compile(&pset2, &req_env, &schema).map_err(py_rt_err)?;

            // CLI approach: check implies with counterexample in both directions
            // fwd: does pset1 imply pset2? If not, counterexample is where pset1 allows but pset2 denies
            let fwd = compiler.check_implies_with_counterexample_opt(&compiled1, &compiled2).await.map_err(py_rt_err)?;
            // bwd: does pset2 imply pset1? If not, counterexample is where pset2 allows but pset1 denies
            let bwd = compiler.check_implies_with_counterexample_opt(&compiled2, &compiled1).await.map_err(py_rt_err)?;

            let (result, more_ex, less_ex) = match (&fwd, &bwd) {
                (None, None) => ("equivalent", None, None),
                (None, Some(cex)) => ("less_permissive", None, Some(format_counterexample(cex))),
                (Some(cex), None) => ("more_permissive", Some(format_counterexample(cex)), None),
                (Some(more_cex), Some(less_cex)) => (
                    "incomparable",
                    Some(format_counterexample(more_cex)),
                    Some(format_counterexample(less_cex)),
                ),
            };

            comparisons.push(RequestTypeComparisonSer {
                action,
                result: result.to_string(),
                more_permissive_example: more_ex,
                less_permissive_example: less_ex,
            });
        }

        compiler.solver_mut().clean_up().await
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        serde_json::to_string(&CompareResultSer { request_type_comparisons: comparisons })
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
    })
}

/// Analyze a Cedar policy set matching cedar-lean-cli `analyze policies`.
///
/// 1. Computes per-policy vacuity across all request envs (matches_all / matches_none / matches_some)
/// 2. Computes policyset-level vacuity (always allows / always denies)
/// 3. Uses vacuity to short-circuit pairwise checks (matching CLI optimization)
/// 4. For permit pairs: uses check_implies on singleton policysets
/// 5. For forbid pairs and overrides: uses check_matches_implies on individual policies
#[pyfunction]
#[pyo3(signature = (policies, schema))]
fn analyze_policies(policies: String, schema: String) -> PyResult<String> {
    let pset = PolicySet::from_str(&policies)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Failed to parse policies: {e}")))?;
    let schema = Schema::from_str(schema.trim())
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Failed to parse schema: {e}")))?;

    let py_rt_err = |e: cedar_policy_symcc::err::Error| pyo3::exceptions::PyRuntimeError::new_err(e.to_string());

    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
    rt.block_on(async {
        let solver = LocalSolver::cvc5()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("Failed to start CVC5 solver: {e}")))?;
        let mut compiler = CedarSymCompiler::new(solver)
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;

        let all_policies: Vec<&Policy> = pset.policies().collect();
        let req_envs: Vec<RequestEnv> = schema.request_envs().collect();

        // Step 1: Compute per-policy vacuity across all request envs
        // policy_vacuity[i][j] = vacuity of policy i for request env j
        let mut policy_vacuity: Vec<Vec<VacuityResult>> = Vec::new();
        for policy in &all_policies {
            let mut per_env = Vec::new();
            for req_env in &req_envs {
                let compiled = CompiledPolicy::compile(policy, req_env, &schema).map_err(py_rt_err)?;
                if compiler.check_always_matches_opt(&compiled).await.map_err(py_rt_err)? {
                    per_env.push(VacuityResult::MatchesAll);
                } else if compiler.check_never_matches_opt(&compiled).await.map_err(py_rt_err)? {
                    per_env.push(VacuityResult::MatchesNone);
                } else {
                    per_env.push(VacuityResult::MatchesSome);
                }
            }
            policy_vacuity.push(per_env);
        }

        // Step 2: Compute policyset-level vacuity
        let mut pset_vacuity_per_env = Vec::new();
        for req_env in &req_envs {
            let compiled_pset = CompiledPolicySet::compile(&pset, req_env, &schema).map_err(py_rt_err)?;
            if compiler.check_always_allows_opt(&compiled_pset).await.map_err(py_rt_err)? {
                pset_vacuity_per_env.push(VacuityResult::MatchesAll);
            } else if compiler.check_always_denies_opt(&compiled_pset).await.map_err(py_rt_err)? {
                pset_vacuity_per_env.push(VacuityResult::MatchesNone);
            } else {
                pset_vacuity_per_env.push(VacuityResult::MatchesSome);
            }
        }
        let policyset_vacuity = vacuity_across_envs(&pset_vacuity_per_env);

        // Step 3: Build vacuous_policies (only non-MatchesSome, matching CLI)
        let mut vacuous_policies = Vec::new();
        for (i, policy) in all_policies.iter().enumerate() {
            let agg = vacuity_across_envs(&policy_vacuity[i]);
            if agg != VacuityResult::MatchesSome {
                let effect = match policy.effect() {
                    Effect::Permit => "permit",
                    Effect::Forbid => "forbid",
                };
                vacuous_policies.push(VacuousPolicySer {
                    policy_id: policy.id().to_string(),
                    effect: effect.to_string(),
                    vacuity: match agg {
                        VacuityResult::MatchesAll => "matches_all".to_string(),
                        VacuityResult::MatchesNone => "matches_none".to_string(),
                        VacuityResult::MatchesSome => unreachable!(),
                    },
                });
            }
        }

        // Step 4: Per request type pairwise findings (using vacuity to short-circuit)
        let mut per_request_type_findings = Vec::new();
        for (env_idx, req_env) in req_envs.iter().enumerate() {
            let action = req_env.action().to_string();

            let mut redundant_map: HashMap<usize, HashSet<usize>> = HashMap::new();
            let mut permit_shadowed: Vec<ShadowedFinding> = Vec::new();
            let mut permit_overridden: Vec<ShadowedFinding> = Vec::new();
            let mut forbid_shadowed: Vec<ShadowedFinding> = Vec::new();

            for i in 0..all_policies.len() {
                for j in (i + 1)..all_policies.len() {
                    let vr_i = policy_vacuity[i][env_idx];
                    let vr_j = policy_vacuity[j][env_idx];
                    let eff_i = all_policies[i].effect();
                    let eff_j = all_policies[j].effect();

                    match (eff_i, eff_j) {
                        (Effect::Permit, Effect::Permit) => {
                            // Permit shadowing: use check_implies on singleton policysets (matching CLI)
                            let sr = compute_permit_shadowing(
                                &mut compiler, all_policies[i], vr_i, all_policies[j], vr_j, req_env, &schema,
                            ).await.map_err(py_rt_err)?;
                            match sr {
                                ShadowingResult::Equivalent => {
                                    redundant_map.entry(i).or_default().insert(j);
                                    redundant_map.entry(j).or_default().insert(i);
                                }
                                ShadowingResult::Policy1Shadows2 => {
                                    permit_shadowed.push(ShadowedFinding {
                                        policy_id: all_policies[j].id().to_string(),
                                        by_policy_id: all_policies[i].id().to_string(),
                                    });
                                }
                                ShadowingResult::Policy2Shadows1 => {
                                    permit_shadowed.push(ShadowedFinding {
                                        policy_id: all_policies[i].id().to_string(),
                                        by_policy_id: all_policies[j].id().to_string(),
                                    });
                                }
                                ShadowingResult::NoResult => {}
                            }
                        }
                        (Effect::Permit, Effect::Forbid) => {
                            let or = compute_override(
                                &mut compiler, all_policies[j], vr_j, all_policies[i], vr_i, req_env, &schema,
                            ).await.map_err(py_rt_err)?;
                            if or == OverrideResult::Overrides {
                                permit_overridden.push(ShadowedFinding {
                                    policy_id: all_policies[i].id().to_string(),
                                    by_policy_id: all_policies[j].id().to_string(),
                                });
                            }
                        }
                        (Effect::Forbid, Effect::Permit) => {
                            let or = compute_override(
                                &mut compiler, all_policies[i], vr_i, all_policies[j], vr_j, req_env, &schema,
                            ).await.map_err(py_rt_err)?;
                            if or == OverrideResult::Overrides {
                                permit_overridden.push(ShadowedFinding {
                                    policy_id: all_policies[j].id().to_string(),
                                    by_policy_id: all_policies[i].id().to_string(),
                                });
                            }
                        }
                        (Effect::Forbid, Effect::Forbid) => {
                            let sr = compute_forbid_shadowing(
                                &mut compiler, all_policies[i], vr_i, all_policies[j], vr_j, req_env, &schema,
                            ).await.map_err(py_rt_err)?;
                            match sr {
                                ShadowingResult::Equivalent => {
                                    redundant_map.entry(i).or_default().insert(j);
                                    redundant_map.entry(j).or_default().insert(i);
                                }
                                ShadowingResult::Policy1Shadows2 => {
                                    forbid_shadowed.push(ShadowedFinding {
                                        policy_id: all_policies[j].id().to_string(),
                                        by_policy_id: all_policies[i].id().to_string(),
                                    });
                                }
                                ShadowingResult::Policy2Shadows1 => {
                                    forbid_shadowed.push(ShadowedFinding {
                                        policy_id: all_policies[i].id().to_string(),
                                        by_policy_id: all_policies[j].id().to_string(),
                                    });
                                }
                                ShadowingResult::NoResult => {}
                            }
                        }
                    }
                }
            }

            // Build equivalence classes from redundant_map (matching CLI logic)
            let mut redundant_groups: Vec<Vec<String>> = Vec::new();
            let mut visited: HashSet<usize> = HashSet::new();
            for i in 0..all_policies.len() {
                if visited.contains(&i) { continue; }
                if let Some(peers) = redundant_map.get(&i) {
                    let mut group: HashSet<usize> = peers.clone();
                    group.insert(i);
                    if group.len() >= 2 {
                        for &idx in &group { visited.insert(idx); }
                        redundant_groups.push(group.iter().map(|&idx| all_policies[idx].id().to_string()).collect());
                    }
                }
            }

            // Only include this request type if there are findings (matching CLI)
            if !redundant_groups.is_empty() || !permit_shadowed.is_empty() || !permit_overridden.is_empty() || !forbid_shadowed.is_empty() {
                per_request_type_findings.push(PerRequestTypeFindings {
                    action,
                    redundant_groups,
                    permit_shadowed_by_permit: permit_shadowed,
                    permit_overridden_by_forbid: permit_overridden,
                    forbid_shadowed_by_forbid: forbid_shadowed,
                });
            }
        }

        let result = AnalyzeResultSer {
            policyset_vacuity: match policyset_vacuity {
                VacuityResult::MatchesAll => "matches_all".to_string(),
                VacuityResult::MatchesSome => "matches_some".to_string(),
                VacuityResult::MatchesNone => "matches_none".to_string(),
            },
            vacuous_policies,
            per_request_type_findings,
        };

        compiler.solver_mut().clean_up().await
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        serde_json::to_string(&result)
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
    })
}

// HashMap already imported at the top of the file

#[derive(Clone, Copy, PartialEq)]
enum ShadowingResult {
    Equivalent,
    Policy1Shadows2,
    Policy2Shadows1,
    NoResult,
}

#[derive(Clone, Copy, PartialEq)]
enum OverrideResult {
    Overrides,
    NoResult,
}

/// Permit shadowing: uses check_implies on singleton PolicySets (matching CLI).
async fn compute_permit_shadowing<S: cedar_policy_symcc::solver::Solver + Send>(
    compiler: &mut CedarSymCompiler<S>,
    policy1: &Policy, vr1: VacuityResult,
    policy2: &Policy, vr2: VacuityResult,
    req_env: &RequestEnv, schema: &Schema,
) -> Result<ShadowingResult, cedar_policy_symcc::err::Error> {
    match (vr1, vr2) {
        (VacuityResult::MatchesNone, _) | (_, VacuityResult::MatchesNone) => Ok(ShadowingResult::NoResult),
        (VacuityResult::MatchesAll, VacuityResult::MatchesAll) => Ok(ShadowingResult::Equivalent),
        (VacuityResult::MatchesAll, VacuityResult::MatchesSome) => Ok(ShadowingResult::Policy1Shadows2),
        (VacuityResult::MatchesSome, VacuityResult::MatchesAll) => Ok(ShadowingResult::Policy2Shadows1),
        (VacuityResult::MatchesSome, VacuityResult::MatchesSome) => {
            let pset1 = PolicySet::from_policies([policy1.to_owned()]).unwrap();
            let pset2 = PolicySet::from_policies([policy2.to_owned()]).unwrap();
            let cpset1 = CompiledPolicySet::compile(&pset1, req_env, schema)?;
            let cpset2 = CompiledPolicySet::compile(&pset2, req_env, schema)?;
            let p1_implies_p2 = compiler.check_implies_opt(&cpset1, &cpset2).await?;
            let p2_implies_p1 = compiler.check_implies_opt(&cpset2, &cpset1).await?;
            Ok(match (p1_implies_p2, p2_implies_p1) {
                (true, true) => ShadowingResult::Equivalent,
                (true, false) => ShadowingResult::Policy2Shadows1,
                (false, true) => ShadowingResult::Policy1Shadows2,
                (false, false) => ShadowingResult::NoResult,
            })
        }
    }
}

/// Forbid overrides permit: uses check_matches_implies (matching CLI).
async fn compute_override<S: cedar_policy_symcc::solver::Solver + Send>(
    compiler: &mut CedarSymCompiler<S>,
    forbid_policy: &Policy, forbid_vr: VacuityResult,
    permit_policy: &Policy, permit_vr: VacuityResult,
    req_env: &RequestEnv, schema: &Schema,
) -> Result<OverrideResult, cedar_policy_symcc::err::Error> {
    match (forbid_vr, permit_vr) {
        (VacuityResult::MatchesNone, _) | (VacuityResult::MatchesAll, _) |
        (_, VacuityResult::MatchesNone) | (_, VacuityResult::MatchesAll) => Ok(OverrideResult::NoResult),
        _ => {
            let cp = CompiledPolicy::compile(permit_policy, req_env, schema)?;
            let cf = CompiledPolicy::compile(forbid_policy, req_env, schema)?;
            if compiler.check_matches_implies_opt(&cp, &cf).await? {
                Ok(OverrideResult::Overrides)
            } else {
                Ok(OverrideResult::NoResult)
            }
        }
    }
}

/// Forbid shadowing: uses check_matches_implies (matching CLI).
async fn compute_forbid_shadowing<S: cedar_policy_symcc::solver::Solver + Send>(
    compiler: &mut CedarSymCompiler<S>,
    policy1: &Policy, vr1: VacuityResult,
    policy2: &Policy, vr2: VacuityResult,
    req_env: &RequestEnv, schema: &Schema,
) -> Result<ShadowingResult, cedar_policy_symcc::err::Error> {
    match (vr1, vr2) {
        (VacuityResult::MatchesNone, _) | (_, VacuityResult::MatchesNone) => Ok(ShadowingResult::NoResult),
        (VacuityResult::MatchesAll, VacuityResult::MatchesAll) => Ok(ShadowingResult::Equivalent),
        (VacuityResult::MatchesAll, VacuityResult::MatchesSome) => Ok(ShadowingResult::Policy1Shadows2),
        (VacuityResult::MatchesSome, VacuityResult::MatchesAll) => Ok(ShadowingResult::Policy2Shadows1),
        (VacuityResult::MatchesSome, VacuityResult::MatchesSome) => {
            let cp1 = CompiledPolicy::compile(policy1, req_env, schema)?;
            let cp2 = CompiledPolicy::compile(policy2, req_env, schema)?;
            let p1_implies_p2 = compiler.check_matches_implies_opt(&cp1, &cp2).await?;
            let p2_implies_p1 = compiler.check_matches_implies_opt(&cp2, &cp1).await?;
            Ok(match (p1_implies_p2, p2_implies_p1) {
                (true, true) => ShadowingResult::Equivalent,
                (true, false) => ShadowingResult::Policy2Shadows1,
                (false, true) => ShadowingResult::Policy1Shadows2,
                (false, false) => ShadowingResult::NoResult,
            })
        }
    }
}

/// A Python module implemented in Rust.
#[pymodule]
fn _internal(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(echo, m)?)?;
    m.add_function(wrap_pyfunction!(is_authorized, m)?)?;
    m.add_function(wrap_pyfunction!(is_authorized_batch, m)?)?;
    m.add_function(wrap_pyfunction!(format_policies, m)?)?;
    m.add_function(wrap_pyfunction!(policies_to_json_str, m)?)?;
    m.add_function(wrap_pyfunction!(policies_from_json_str, m)?)?;
    m.add_function(wrap_pyfunction!(validate_policies, m)?)?;
    m.add_function(wrap_pyfunction!(compare_policy_sets, m)?)?;
    m.add_function(wrap_pyfunction!(analyze_policies, m)?)?;
    Ok(())
}
