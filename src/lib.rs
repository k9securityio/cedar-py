use std::str::FromStr;
use std::time::Instant;

use anyhow::{Context as _, Error, Result};
use cedar_policy::*;
use cedar_policy::PrincipalConstraint::{Any, Eq, In};
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyString};

/// Echo (return) the input string
#[pyfunction]
#[pyo3(signature = (s))]
fn echo(s: String) -> PyResult<String> {
    Ok(s)
}

#[pyfunction]
#[pyo3(signature = ())]
fn parse_test_policy() -> PyResult<String> {
    println!("Example: Parsing a Cedar Policy");
    // this policy has a type error, but parses.
    let src = r#"
    permit(
        principal == User::"bob",
        action == Action::"view",
        resource
    )
    when { 10 > "hello" };
"#;
    let parse_result = PolicySet::from_str(src);
    return match parse_result {
        Ok(p_set) => {
            let pid = PolicyId::from_str("policy_id_00").unwrap();
            let policy = PolicySet::policy(&p_set, &pid);
            if let Some(p) = policy {
                println!("Policy:{}", p);
                let pr = Policy::principal_constraint(p);
                match pr {
                    Any => println!("No Principal"),
                    In(euid) => println!("Principal Constraint: Principal in {}", euid),
                    Eq(euid) => println!("Principal Constraint: Principal=={}", euid),
                }
            }
            Ok(String::from("Ok!"))
        }
        Err(e) => {
            println!("{:?}", e);
            Err(PyRuntimeError::new_err("Could nor parse test policy :("))
        }
    };
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
#[pyo3(signature = (request, policies, entities, schema=None, verbose=false,))]
fn is_authorized(request: &PyDict,
                 policies: String,
                 entities: String,
                 schema: Option<String>,
                 verbose: Option<bool>)
                 -> PyResult<String> {
    // CLI AuthorizeArgs: https://github.com/cedar-policy/cedar/blob/main/cedar-policy-cli/src/lib.rs#L183
    let verbose = verbose.unwrap_or(false);
    if verbose{
        println!("request: {}", request);
        println!("policies: {}", policies);
        println!("entities: {}", entities);
        println!("schema: {}", schema.clone().unwrap_or(String::from("<none>")));
    }

    // collect request arguments into a struct compatible with authorization request
    let principal: String = request.get_item(String::from("principal")).unwrap().downcast::<PyString>()?.to_string();
    let action: String = request.get_item(String::from("action")).unwrap().downcast::<PyString>()?.to_string();
    let resource: String = request.get_item(String::from("resource")).unwrap().downcast::<PyString>()?.to_string();

    let context_option = request.get_item(String::from("context"));
    let context_json_option: Option<String> = match context_option {
        None => None, // context member not present
        Some(context) => {
            if context.is_none(){
                None  // context member present, but value of None/null
            } else {
                //present and has a value
                // TODO: accept context as a PyDict instead of PyString so it's more convenient in Python binding
                // the real work is adjusting context creation with e.g. Context::from_json_val
                Some(context.downcast::<PyString>()?.to_string())
            }
        }
    };

    if verbose{
        println!("context_json_option: {}", context_json_option.clone().unwrap_or(String::from("<none>")));
    }

    let request = RequestArgs {
        principal: Some(principal),
        action: Some(action),
        resource: Some(resource),
        context_json: context_json_option,
    };

    let ans = execute_authorization_request(&request,
                                            policies,
                                            entities,
                                            schema,
                                            true);
    match ans {
        Ok(ans) => {
            let to_json_str_result = serde_json::to_string(&ans);
            match to_json_str_result {
                Ok(json_str) => { Ok(json_str) },
                Err(err) => {
                    Err(to_pyerr(&Vec::from([err])))
                },
            }
        }
        Err(errs) => {
            for err in &errs {
                println!("{:#}", err);
            }
            Err(to_pyerr(&errs))
        }
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

/// This uses the Cedar API to call the authorization engine.
fn execute_authorization_request(
    request: &RequestArgs,
    policies_str: String,
    // links_filename: Option<impl AsRef<Path>>,
    entities_str: String,
    schema_str: Option<String>,
    compute_duration: bool,
) -> Result<Response, Vec<Error>> {
    let mut parse_errs:Vec<ParseErrors> = vec![];
    let mut errs:Vec<Error> = vec![];

    let policies = match PolicySet::from_str(&policies_str) {
        Ok(pset) => pset,
        Err(e) => {
            parse_errs.push(e);
            PolicySet::new()
        }
    };

    let schema: Option<Schema> = match &schema_str {
        None => None,
        Some(schema_src) => {
            println!("schema: {}", schema_src.as_str());
            match Schema::from_str(&schema_src) {
                Ok(schema) => Some(schema),
                Err(e) => {
                    // errs.push(e);
                    println!("!!! error constructing schema: {}", e);
                    None
                }
            }
        }
    };

    let entities = match load_entities(entities_str, schema.as_ref()) {
        Ok(entities) => entities,
        Err(e) => {
            errs.push(e);
            Entities::empty()
        }
    };
    // curious that this seems to set actions into entities
    let entities = match load_actions_from_schema(entities, &schema) {
        Ok(entities) => entities,
        Err(e) => {
            errs.push(e);
            Entities::empty()
        }
    };

    let request = match request.get_request(schema.as_ref()) {
        Ok(q) => Some(q),
        Err(e) => {
            errs.push(e.context("failed to parse schema from request"));
            None
        }
    };
    if parse_errs.is_empty() && errs.is_empty() {
        let request = request.expect("if no errors, we should have a valid request");
        let authorizer = Authorizer::new();
        let auth_start = Instant::now();
        let ans = authorizer.is_authorized(&request, &policies, &entities);
        let auth_dur = auth_start.elapsed();
        if compute_duration {
            println!(
                "Authorization Time (micro seconds) : {}",
                auth_dur.as_micros()
            );
        }
        Ok(ans)
    } else {
        println!("encountered errors while building request.\nparse_errs: {:#?}\nerrs: {:#?} ",
                 parse_errs, errs);
        Err(errs)
    }
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
fn _cedarpolicy(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(echo, m)?)?;
    m.add_function(wrap_pyfunction!(parse_test_policy, m)?)?;
    m.add_function(wrap_pyfunction!(is_authorized, m)?)?;
    Ok(())
}