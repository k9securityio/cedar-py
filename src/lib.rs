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
    let schema = make_schema(&schema, verbose);
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
    /// `PolicyId`s of the policies that contributed to the decision.
    /// If no policies applied to the request, this set will be empty.
    reason: HashSet<PolicyId>,
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

impl AuthzResponse {
    /// Create a new `AuthzResponse`
    pub fn new(response: Response, metrics: HashMap<String, u128>, correlation_id: Option<String>) -> Self {
        Self {
            decision: match response.decision() {
                Decision::Allow => DecisionSer::Allow,
                Decision::Deny => DecisionSer::Deny
            },
            correlation_id,
            diagnostics: DiagnosticsSer{
                reason: response.diagnostics().reason().cloned().collect(),
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
        let authz_response = AuthzResponse::new(ans, metrics,
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

fn make_schema(schema_str: &Option<String>, verbose: bool) -> Option<Schema> {
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

/// A Python module implemented in Rust.
#[pymodule]
fn _internal(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(echo, m)?)?;
    m.add_function(wrap_pyfunction!(is_authorized, m)?)?;
    m.add_function(wrap_pyfunction!(is_authorized_batch, m)?)?;
    m.add_function(wrap_pyfunction!(format_policies, m)?)?;
    m.add_function(wrap_pyfunction!(policies_to_json_str, m)?)?;
    m.add_function(wrap_pyfunction!(policies_from_json_str, m)?)?;
    Ok(())
}