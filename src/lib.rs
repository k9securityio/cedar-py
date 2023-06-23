use std::path::Path;
use std::str::FromStr;
use pyo3::prelude::*;

use anyhow::{Context as _, Error, Result};
use cedar_policy::{Decision, Policy, PolicyId, PolicySet, Response};
use cedar_policy::PrincipalConstraint::{Any, Eq, In};
use cedar_policy_cli::{AuthorizeArgs, CedarExitCode, RequestArgs};
// use cedar_policy::*;
use cedar_policy_formatter::{policies_str_to_pretty, Config};
use pyo3::exceptions::PyRuntimeError;
use pyo3::types::PyDict;

/// Echo (return) the input string
#[pyfunction]
#[pyo3(signature = (s))]
fn echo(s: String) -> PyResult<String> {
    Ok(s)
}

#[pyfunction]
#[pyo3(signature = ())]
fn parse_test_policy() -> PyResult<String>{
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
    }
}

// #[pyfunction]
// fn format_policies(file_name: String, line_width: usize, indent_width: isize) -> PyResult<()> {
//     let policies_str = read_from_file_or_stdin(Some(file_name).as_ref(),
//                                                "policy set")?;
//     let config = Config {
//         line_width,
//         indent_width,
//     };
//     println!("{}", policies_str_to_pretty(&policies_str, &config)?);
//     Ok(())
// }

// Read from a file (when `filename` is a `Some`) or stdin (when `filename` is `None`)
fn read_from_file_or_stdin(filename: Option<impl AsRef<Path>>, context: &str) -> Result<String> {
    let mut src_str = String::new();
    match filename.as_ref() {
        Some(path) => {
            src_str = std::fs::read_to_string(path).context(format!(
                "failed to open {} file {}",
                context,
                path.as_ref().display()
            ))?;
        }
        None => {
            std::io::Read::read_to_string(&mut std::io::stdin(), &mut src_str)
                .context(format!("failed to read {} from stdin", context))?;
        }
    };
    Ok(src_str)
}

/// Echo (return) the input string
#[pyfunction]
#[pyo3(signature = (request, policies, entities))]
fn is_authorized(request: &PyDict, policies: String, entities: String) -> PyResult<String> {
    // CLI AuthorizeArgs: https://github.com/cedar-policy/cedar/blob/main/cedar-policy-cli/src/lib.rs#L183
    // TODO: Convert entities to &PyList (list<dict> in python)

    // validate & deconstruct request
    println!("request: {}", request);

    // load policy set
    println!("policies: {}", policies);

    // load policy set
    println!("entities: {}", entities);

    // invoke authorize

    Ok(String::from("DENY"))
}
/*pub fn authorize(args: &AuthorizeArgs) -> CedarExitCode {
    println!();
    let ans = execute_request(
        &args.request,
        &args.policies_file,
        args.template_linked_file.as_ref(),
        &args.entities_file,
        args.schema_file.as_ref(),
        args.timing,
    );
    match ans {
        Ok(ans) => {
            let status = match ans.decision() {
                Decision::Allow => {
                    println!("ALLOW");
                    CedarExitCode::Success
                }
                Decision::Deny => {
                    println!("DENY");
                    CedarExitCode::AuthorizeDeny
                }
            };
            if ans.diagnostics().errors().peekable().peek().is_some() {
                println!();
                for err in ans.diagnostics().errors() {
                    println!("{}", err);
                }
            }
            if args.verbose {
                println!();
                if ans.diagnostics().reason().peekable().peek().is_none() {
                    println!("note: no policies applied to this request");
                } else {
                    println!("note: this decision was due to the following policies:");
                    for reason in ans.diagnostics().reason() {
                        println!("  {}", reason);
                    }
                    println!();
                }
            }
            status
        }
        Err(errs) => {
            for err in errs {
                println!("{:#}", err);
            }
            CedarExitCode::Failure
        }
    }
}
*/
/*/// This uses the Cedar API to call the authorization engine.
fn execute_request(
    request: &RequestArgs,
    policies_filename: impl AsRef<Path> + std::marker::Copy,
    links_filename: Option<impl AsRef<Path>>,
    entities_filename: impl AsRef<Path>,
    schema_filename: Option<impl AsRef<Path> + std::marker::Copy>,
    compute_duration: bool,
) -> Result<Response, Vec<Error>> {
    let mut errs = vec![];
    let policies = match read_policy_and_links(policies_filename.as_ref(), links_filename) {
        Ok(pset) => pset,
        Err(e) => {
            errs.push(e);
            PolicySet::new()
        }
    };
    let schema = match schema_filename.map(read_schema_file) {
        None => None,
        Some(Ok(schema)) => Some(schema),
        Some(Err(e)) => {
            errs.push(e);
            None
        }
    };
    let entities = match load_entities(entities_filename, schema.as_ref()) {
        Ok(entities) => entities,
        Err(e) => {
            errs.push(e);
            Entities::empty()
        }
    };
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
            errs.push(e.context("failed to parse request"));
            None
        }
    };
    if errs.is_empty() {
        let request = request.expect("if errs is empty, we should have a request");
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
        Err(errs)
    }
}
*/

/// A Python module implemented in Rust.
#[pymodule]
fn cedarpolicy(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(echo, m)?)?;
    m.add_function(wrap_pyfunction!(parse_test_policy, m)?)?;
    m.add_function(wrap_pyfunction!(is_authorized, m)?)?;
    Ok(())
}