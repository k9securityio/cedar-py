use std::collections::HashMap;
use std::str::FromStr;
use std::time::Instant;

use anyhow::{Context as _, Error, Result};
use cedar_policy::*;
use cedar_policy_formatter::{Config, policies_str_to_pretty};
use pyo3::prelude::*;
use pyo3::types::{IntoPyDict, PyDict, PyList, PyString};
use serde::{Deserialize, Serialize};

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

pub struct RequestArgs {
    /// Principal for the request, e.g., User::"alice"
    pub principal: Option<String>,
    /// Action for the request, e.g., Action::"view"
    pub action: Option<String>,
    /// Resource for the request, e.g., File::"myfile.txt"
    pub resource: Option<String>,
    /// A JSON object representing the context for the request.
    /// Should be a (possibly empty) map from keys to values.
    pub context_json: Option<String>,
}

impl RequestArgs {
    /// Turn this `RequestArgs` into the appropriate `Request` object
    fn get_request(&self, schema: Option<&Schema>) -> Result<Request> {
        let principal = self
            .principal
            .as_ref()
            .map(|s| {
                s.parse()
                    .context(format!("failed to parse principal {s} as entity Uid"))
            })
            .transpose()?;
        let action = self
            .action
            .as_ref()
            .map(|s| {
                s.parse()
                    .context(format!("failed to parse action {s} as entity Uid"))
            })
            .transpose()?;
        let resource = self
            .resource
            .as_ref()
            .map(|s| {
                s.parse()
                    .context(format!("failed to parse resource {s} as entity Uid"))
            })
            .transpose()?;
        let context: Context = match &self.context_json {
            None => Context::empty(),
            Some(context_json_str) => {
                // Must provide action EUID because actions define their own schemas
                Context::from_json_str(context_json_str,
                                       schema.and_then(|s| Some((s, action.as_ref()?))))?
            },
        };
        Ok(Request::new(principal, action, resource, context))
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
    is_batch_authorized(vec![request], policies, entities, schema, verbose)[0].clone()
}

#[pyfunction]
#[pyo3(signature = (requests, policies, entities, schema = None, verbose = false,))]
fn is_batch_authorized(requests: Vec<HashMap<String, String>>,
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
    let mut parse_errs: Vec<ParseErrors> = vec![];
    let mut errs: Vec<Error> = vec![];
    let t_total = Instant::now();


    // probably need to deconstruct execute_authorization_request so that we can reuse the
    // expensive parts (policies, entities, schema):
    // parse policies
    let t_parse_policies = Instant::now();
    let policy_set = match PolicySet::from_str(&policies) {
        Ok(pset) => pset,
        Err(e) => {
            parse_errs.push(e);
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
    let entities = make_entities(entities, &&schema, &mut errs);
    let t_load_entities_duration = t_load_entities.elapsed();

    // build a list of RequestArgs
    // evaluate access one at a time (future work: eval in parallel)


    // build a vector of RequestArgs with e.g. requests.iter().map()
    let mut request_args_vec: Vec<RequestArgs> = Vec::new();
    requests.iter().for_each(|request: &HashMap<String, String>| {
        request_args_vec.push(to_request_args(request));
    });

    let mut responses_vec: Vec<String> = Vec::new();

    for request_args in request_args_vec.iter() {
        // println!("> {}", request_args);
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
                        //Err(to_pyerr(&Vec::from([err])))
                        r#"{"errors": ["{}"]}"#.to_string()
                    }
                }
            }
            Err(errs) => {
                for err in &errs {
                    println!("{:#}", err);
                }
                r#"{"errors": ["{}"]}"#.to_string()
            }
        };

        responses_vec.push(response_string);
    }



    return responses_vec;
}

fn to_request_args(request: &HashMap<String, String>) -> RequestArgs {
    // collect request arguments into a struct compatible with authorization request
    let principal: String = request.get(String::from("principal").as_str()).unwrap().to_string();
    let action: String = request.get(String::from("action").as_str()).unwrap().to_string();
    let resource: String = request.get(String::from("resource").as_str()).unwrap().to_string();

    let context_option = request.get(String::from("context").as_str());
    let context_json_option: Option<String> = match context_option {
        None => None, // context member not present
        Some(context) => Some(context.to_string())
    };

    RequestArgs {
        principal: Some(principal),
        action: Some(action),
        resource: Some(resource),
        context_json: context_json_option,
    }
}

fn to_pyerr<E: ToString>(errs: &Vec<E>) -> PyErr {
    let mut err_str = "Errors: ".to_string();
    for err in errs.iter() {
        err_str.push_str(" ");
        err_str.push_str(&err.to_string());
    }
    pyo3::exceptions::PyValueError::new_err(err_str)
}

/// Authorization response returned from the `Authorizer`
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
struct AuthzResponse {
    /// Authorization decision
    decision: Decision,

    /// Diagnostics providing more information on how this decision was reached
    diagnostics: Diagnostics,

    /// Metrics providing timing information on the authorization decision
    metrics: HashMap<String, u128>,
}

impl AuthzResponse {
    /// Create a new `AuthzResponse`
    pub fn new(response: Response, metrics: HashMap<String, u128>) -> Self {
        Self {
            decision: response.decision(),
            diagnostics: response.diagnostics().clone(),
            metrics,
        }
    }
}

/// This uses the Cedar API to call the authorization engine.
fn execute_authorization_request(
    request: &RequestArgs,
    policy_set: &PolicySet,
    entities: &Entities,
    schema: &Option<Schema>,
    verbose: bool
) -> Result<AuthzResponse, Vec<Error>> {
    let mut errs: Vec<Error> = vec![];
    let t_total = Instant::now();

    let request = match request.get_request(schema.as_ref()) {
        Ok(q) => Some(q),
        Err(e) => {
            errs.push(e.context("failed to parse schema from request"));
            None
        }
    };
    if errs.is_empty() {
        let request = request.expect("if no errors, we should have a valid request");
        let authorizer = Authorizer::new();
        let t_authz = Instant::now();
        let ans = authorizer.is_authorized(&request, &policy_set, &entities);
        let metrics = HashMap::from([
            (String::from("total_duration_micros"), t_total.elapsed().as_micros()),
            (String::from("authz_duration_micros"), t_authz.elapsed().as_micros()),
        ]);
        let authz_response = AuthzResponse::new(ans, metrics);
        Ok(authz_response)
    } else {
        if verbose {
            println!("encountered errors while building request. \nerrs: {:#?} ", errs);
        }
        Err(errs)
    }
}

fn make_entities(entities_str: String, schema: &&Option<Schema>, errs: &mut Vec<Error>) -> Entities {
    let entities = match load_entities(entities_str, schema.as_ref()) {
        Ok(entities) => entities,
        Err(e) => {
            errs.push(e);
            Entities::empty()
        }
    };
    // load actions from the schema and append into entities
    // we could/may integrate this into the load_entities match
    let entities = match load_actions_from_schema(entities, &schema) {
        Ok(entities) => entities,
        Err(e) => {
            errs.push(e);
            Entities::empty()
        }
    };
    entities
}

fn make_schema(schema_str: &Option<String>, verbose: bool) -> Option<Schema> {
    let schema: Option<Schema> = match &schema_str {
        None => None,
        Some(schema_src) => {
            if verbose {
                println!("schema: {}", schema_src.as_str());
            }
            match Schema::from_str(&schema_src) {
                Ok(schema) => Some(schema),
                Err(e) => {
                    // TODO: record this error
                    // errs.push(e);
                    if verbose {
                        println!("!!! error constructing schema: {}", e);
                    }
                    None
                }
            }
        }
    };
    schema
}

/// Load an `Entities` object from the given JSON string and optional schema.
fn load_entities(entities_str: String, schema: Option<&Schema>) -> Result<Entities> {
    return Entities::from_json_str(&entities_str, schema).context(format!(
        "failed to parse entities from:\n{}", entities_str
    ));
}

fn load_actions_from_schema(entities: Entities, schema: &Option<Schema>) -> Result<Entities> {
    match schema {
        Some(schema) => match schema.action_entities() {
            Ok(action_entities) => Entities::from_entities(
                entities
                    .iter()
                    .cloned()
                    .chain(action_entities.iter().cloned()),
            )
            .context("failed to merge action entities with entity file"),
            Err(e) => Err(e).context("failed to construct action entities"),
        },
        None => Ok(entities),
    }
}


/// A Python module implemented in Rust.
#[pymodule]
fn _internal(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(echo, m)?)?;
    m.add_function(wrap_pyfunction!(is_authorized, m)?)?;
    m.add_function(wrap_pyfunction!(is_batch_authorized, m)?)?;
    m.add_function(wrap_pyfunction!(format_policies, m)?)?;
    Ok(())
}