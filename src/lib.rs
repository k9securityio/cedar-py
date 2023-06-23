use std::path::Path;
use std::str::FromStr;
use pyo3::prelude::*;

use anyhow::{Context as _, Error, Result};
use cedar_policy::{Policy, PolicyId, PolicySet};
use cedar_policy::PrincipalConstraint::{Any, Eq, In};
// use cedar_policy::*;
use cedar_policy_formatter::{policies_str_to_pretty, Config};
use pyo3::exceptions::PyRuntimeError;

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

/// A Python module implemented in Rust.
#[pymodule]
fn cedarpolicy(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(echo, m)?)?;
    m.add_function(wrap_pyfunction!(parse_test_policy, m)?)?;
    Ok(())
}