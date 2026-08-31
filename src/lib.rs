use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::time::Instant;

use anyhow::{Context as _, Error, Result};
use cedar_policy::*;
use cedar_policy_formatter::{Config, policies_str_to_pretty};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyString, PyTuple};
use cedar_policy::pst;
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

struct PstClasses<'py> {
    frozen_map: Bound<'py, PyAny>,
    entity_type: Bound<'py, PyAny>,
    entity_uid: Bound<'py, PyAny>,
    slot: Bound<'py, PyAny>,
    var: Bound<'py, PyAny>,
    bool_lit: Bound<'py, PyAny>,
    long_lit: Bound<'py, PyAny>,
    string_lit: Bound<'py, PyAny>,
    entity_lit: Bound<'py, PyAny>,
    unary_op: Bound<'py, PyAny>,
    binary_op: Bound<'py, PyAny>,
    get_attr: Bound<'py, PyAny>,
    has_attr: Bound<'py, PyAny>,
    char: Bound<'py, PyAny>,
    wildcard: Bound<'py, PyAny>,
    like: Bound<'py, PyAny>,
    is_: Bound<'py, PyAny>,
    if_then_else: Bound<'py, PyAny>,
    set: Bound<'py, PyAny>,
    record: Bound<'py, PyAny>,
    when: Bound<'py, PyAny>,
    unless: Bound<'py, PyAny>,
    scope_any: Bound<'py, PyAny>,
    scope_eq: Bound<'py, PyAny>,
    scope_in: Bound<'py, PyAny>,
    scope_is: Bound<'py, PyAny>,
    scope_is_in: Bound<'py, PyAny>,
    action_eq: Bound<'py, PyAny>,
    action_in: Bound<'py, PyAny>,
    template: Bound<'py, PyAny>,
    template_link: Bound<'py, PyAny>,
    policy_set: Bound<'py, PyAny>,
}

impl<'py> PstClasses<'py> {
    fn load(py: Python<'py>) -> PyResult<Self> {
        let m = PyModule::import(py, "cedarpy.pst")?;
        let get = |name: &str| m.getattr(name);
        Ok(Self {
            frozen_map: get("FrozenMap")?,
            entity_type: get("EntityType")?,
            entity_uid: get("EntityUid")?,
            slot: get("Slot")?,
            var: get("Var")?,
            bool_lit: get("BoolLit")?,
            long_lit: get("LongLit")?,
            string_lit: get("StringLit")?,
            entity_lit: get("EntityLit")?,
            unary_op: get("UnaryOp")?,
            binary_op: get("BinaryOp")?,
            get_attr: get("GetAttr")?,
            has_attr: get("HasAttr")?,
            char: get("Char")?,
            wildcard: get("Wildcard")?,
            like: get("Like")?,
            is_: get("Is")?,
            if_then_else: get("IfThenElse")?,
            set: get("Set")?,
            record: get("Record")?,
            when: get("When")?,
            unless: get("Unless")?,
            scope_any: get("ScopeAny")?,
            scope_eq: get("ScopeEq")?,
            scope_in: get("ScopeIn")?,
            scope_is: get("ScopeIs")?,
            scope_is_in: get("ScopeIsIn")?,
            action_eq: get("ActionEq")?,
            action_in: get("ActionIn")?,
            template: get("Template")?,
            template_link: get("TemplateLink")?,
            policy_set: get("PolicySet")?,
        })
    }
}

fn pst_error<T: std::fmt::Debug>(context: &str, value: T) -> PyErr {
    pyo3::exceptions::PyValueError::new_err(format!(
        "cedarpy: unrepresentable {context}: {value:?} (this cedar-policy release added a variant policies_to_pst does not yet handle)"
    ))
}

fn build_mapping<'py>(
    c: &PstClasses<'py>,
    items: impl IntoIterator<Item = (String, Py<PyAny>)>,
) -> PyResult<Py<PyAny>> {
    let py = c.frozen_map.py();
    let mut pairs: Vec<Py<PyAny>> = vec![];
    for (k, v) in items {
        pairs.push(PyTuple::new(py, [k.into_pyobject(py)?.into_any().unbind(), v])?.unbind().into());
    }
    Ok(c.frozen_map.call1((PyTuple::new(py, pairs)?,))?.unbind())
}

fn build_entity_type<'py>(c: &PstClasses<'py>, et: &pst::EntityType) -> PyResult<Py<PyAny>> {
    let py = c.entity_type.py();
    let namespace: Vec<String> = et.0.namespace.iter().map(|id| id.to_string()).collect();
    Ok(c.entity_type
        .call1((et.0.id.to_string(), PyTuple::new(py, namespace)?))?
        .unbind())
}

fn build_entity_uid<'py>(c: &PstClasses<'py>, euid: &pst::EntityUID) -> PyResult<Py<PyAny>> {
    Ok(c.entity_uid.call1((build_entity_type(c, &euid.ty)?, euid.eid.to_string()))?.unbind())
}

fn build_slot_id<'py>(c: &PstClasses<'py>, slot: pst::SlotId) -> PyResult<Py<PyAny>> {
    let name = match slot {
        pst::SlotId::Principal => "principal",
        pst::SlotId::Resource => "resource",
        other => return Err(pst_error("SlotId variant", other)),
    };
    Ok(c.slot.call1((name,))?.unbind())
}

fn build_entity_or_slot<'py>(c: &PstClasses<'py>, eos: &pst::EntityOrSlot) -> PyResult<Py<PyAny>> {
    match eos {
        pst::EntityOrSlot::Entity(euid) => build_entity_uid(c, euid),
        pst::EntityOrSlot::Slot(slot) => build_slot_id(c, *slot),
    }
}

fn build_principal_constraint<'py>(
    c: &PstClasses<'py>,
    constraint: &pst::PrincipalConstraint,
) -> PyResult<Py<PyAny>> {
    match constraint {
        pst::PrincipalConstraint::Any => Ok(c.scope_any.call0()?.unbind()),
        pst::PrincipalConstraint::Eq(eos) => Ok(c.scope_eq.call1((build_entity_or_slot(c, eos)?,))?.unbind()),
        pst::PrincipalConstraint::In(eos) => Ok(c.scope_in.call1((build_entity_or_slot(c, eos)?,))?.unbind()),
        pst::PrincipalConstraint::Is(et) => Ok(c.scope_is.call1((build_entity_type(c, et)?,))?.unbind()),
        pst::PrincipalConstraint::IsIn(et, eos) => {
            Ok(c.scope_is_in.call1((build_entity_type(c, et)?, build_entity_or_slot(c, eos)?))?.unbind())
        }
    }
}

fn build_resource_constraint<'py>(
    c: &PstClasses<'py>,
    constraint: &pst::ResourceConstraint,
) -> PyResult<Py<PyAny>> {
    match constraint {
        pst::ResourceConstraint::Any => Ok(c.scope_any.call0()?.unbind()),
        pst::ResourceConstraint::Eq(eos) => Ok(c.scope_eq.call1((build_entity_or_slot(c, eos)?,))?.unbind()),
        pst::ResourceConstraint::In(eos) => Ok(c.scope_in.call1((build_entity_or_slot(c, eos)?,))?.unbind()),
        pst::ResourceConstraint::Is(et) => Ok(c.scope_is.call1((build_entity_type(c, et)?,))?.unbind()),
        pst::ResourceConstraint::IsIn(et, eos) => {
            Ok(c.scope_is_in.call1((build_entity_type(c, et)?, build_entity_or_slot(c, eos)?))?.unbind())
        }
    }
}

fn build_action_constraint<'py>(
    c: &PstClasses<'py>,
    constraint: &pst::ActionConstraint,
) -> PyResult<Py<PyAny>> {
    match constraint {
        pst::ActionConstraint::Any => Ok(c.scope_any.call0()?.unbind()),
        pst::ActionConstraint::Eq(euid) => Ok(c.action_eq.call1((build_entity_uid(c, euid)?,))?.unbind()),
        pst::ActionConstraint::In(euids) => {
            let mut items = Vec::with_capacity(euids.len());
            for euid in euids {
                items.push(build_entity_uid(c, euid)?);
            }
            let tuple = PyTuple::new(c.action_in.py(), items)?;
            Ok(c.action_in.call1((tuple,))?.unbind())
        }
    }
}

fn build_pattern<'py>(c: &PstClasses<'py>, pattern: &[pst::PatternElem]) -> PyResult<Py<PyAny>> {
    let mut items = Vec::with_capacity(pattern.len());
    for elem in pattern {
        items.push(match elem {
            pst::PatternElem::Char(ch) => c.char.call1((ch.to_string(),))?.unbind(),
            pst::PatternElem::Wildcard => c.wildcard.call0()?.unbind(),
        });
    }
    Ok(PyTuple::new(c.char.py(), items)?.unbind().into())
}

fn build_literal<'py>(c: &PstClasses<'py>, literal: &pst::Literal) -> PyResult<Py<PyAny>> {
    let py = c.bool_lit.py();
    match literal {
        pst::Literal::Bool(b) => Ok(c.bool_lit.call1((*b,))?.unbind()),
        pst::Literal::Long(n) => Ok(c.long_lit.call1((*n,))?.unbind()),
        pst::Literal::String(s) => Ok(c.string_lit.call1((s.to_string().into_pyobject(py)?,))?.unbind()),
        pst::Literal::EntityUID(euid) => Ok(c.entity_lit.call1((build_entity_uid(c, euid)?,))?.unbind()),
        other => Err(pst_error("Literal variant", other)),
    }
}

fn build_expr<'py>(c: &PstClasses<'py>, expr: &pst::Expr) -> PyResult<Py<PyAny>> {
    match expr {
        pst::Expr::Literal(lit) => build_literal(c, lit),
        pst::Expr::Var(var) => {
            let name = match var {
                pst::Var::Principal => "principal",
                pst::Var::Action => "action",
                pst::Var::Resource => "resource",
                pst::Var::Context => "context",
            };
            Ok(c.var.call1((name,))?.unbind())
        }
        pst::Expr::Slot(slot) => build_slot_id(c, *slot),
        pst::Expr::UnaryOp { op, expr: arg } => {
            let name = unary_op_name(*op)?;
            Ok(c.unary_op.call1((name, build_expr(c, arg)?))?.unbind())
        }
        pst::Expr::BinaryOp { op, left, right } => {
            let name = binary_op_name(*op)?;
            Ok(c.binary_op.call1((name, build_expr(c, left)?, build_expr(c, right)?))?.unbind())
        }
        pst::Expr::GetAttr { expr: base, attr } => {
            Ok(c.get_attr.call1((build_expr(c, base)?, attr.to_string()))?.unbind())
        }
        pst::Expr::HasAttr { expr: base, attrs } => {
            let items: Vec<String> = attrs.iter().map(|a| a.to_string()).collect();
            let tuple = PyTuple::new(c.has_attr.py(), items)?;
            Ok(c.has_attr.call1((build_expr(c, base)?, tuple))?.unbind())
        }
        pst::Expr::Like { expr: base, pattern } => {
            Ok(c.like.call1((build_expr(c, base)?, build_pattern(c, pattern)?))?.unbind())
        }
        pst::Expr::Is { expr: base, entity_type, in_expr } => {
            let in_expr = match in_expr {
                Some(e) => Some(build_expr(c, e)?),
                None => None,
            };
            Ok(c.is_.call1((build_expr(c, base)?, build_entity_type(c, entity_type)?, in_expr))?.unbind())
        }
        pst::Expr::IfThenElse { cond, then_expr, else_expr } => Ok(c
            .if_then_else
            .call1((build_expr(c, cond)?, build_expr(c, then_expr)?, build_expr(c, else_expr)?))?
            .unbind()),
        pst::Expr::Set(elements) => {
            let mut items = Vec::with_capacity(elements.len());
            for e in elements {
                items.push(build_expr(c, e)?);
            }
            let tuple = PyTuple::new(c.set.py(), items)?;
            Ok(c.set.call1((tuple,))?.unbind())
        }
        pst::Expr::Record(fields) => {
            let mut items = Vec::with_capacity(fields.len());
            for (k, v) in fields {
                items.push((k.clone(), build_expr(c, v)?));
            }
            Ok(c.record.call1((build_mapping(c, items)?,))?.unbind())
        }
        other => Err(pst_error("Expr variant", other)),
    }
}

fn unary_op_name(op: pst::UnaryOp) -> PyResult<&'static str> {
    use pst::UnaryOp::*;
    match op {
        Not => Ok("not"), Neg => Ok("neg"), IsEmpty => Ok("is_empty"),
        Datetime => Ok("datetime"), Decimal => Ok("decimal"), Duration => Ok("duration"), Ip => Ok("ip"),
        IsIPv4 => Ok("is_ipv4"), IsIPV6 => Ok("is_ipv6"),
        IsLoopback => Ok("is_loopback"), IsMulticast => Ok("is_multicast"),
        ToDate => Ok("to_date"), ToTime => Ok("to_time"),
        ToMilliseconds => Ok("to_milliseconds"), ToSeconds => Ok("to_seconds"),
        ToMinutes => Ok("to_minutes"), ToHours => Ok("to_hours"), ToDays => Ok("to_days"),
        other => Err(pst_error("UnaryOp variant", other)),
    }
}

fn binary_op_name(op: pst::BinaryOp) -> PyResult<&'static str> {
    use pst::BinaryOp::*;
    match op {
        Eq => Ok("eq"), NotEq => Ok("not_eq"), Less => Ok("less"), LessEq => Ok("less_eq"),
        Greater => Ok("greater"), GreaterEq => Ok("greater_eq"),
        And => Ok("and"), Or => Ok("or"),
        Add => Ok("add"), Sub => Ok("sub"), Mul => Ok("mul"),
        In => Ok("in"), Contains => Ok("contains"), ContainsAll => Ok("contains_all"), ContainsAny => Ok("contains_any"),
        GetTag => Ok("get_tag"), HasTag => Ok("has_tag"),
        IsInRange => Ok("is_in_range"), Offset => Ok("offset"), DurationSince => Ok("duration_since"),
        DecimalLessThan => Ok("decimal_less_than"), DecimalLessEq => Ok("decimal_less_eq"),
        DecimalGreater => Ok("decimal_greater"), DecimalGreaterEq => Ok("decimal_greater_eq"),
        other => Err(pst_error("BinaryOp variant", other)),
    }
}

fn build_clause<'py>(c: &PstClasses<'py>, clause: &pst::Clause) -> PyResult<Py<PyAny>> {
    match clause {
        pst::Clause::When(e) => Ok(c.when.call1((build_expr(c, e)?,))?.unbind()),
        pst::Clause::Unless(e) => Ok(c.unless.call1((build_expr(c, e)?,))?.unbind()),
    }
}

fn build_template<'py>(c: &PstClasses<'py>, template: &pst::Template) -> PyResult<Py<PyAny>> {
    let effect = match template.effect {
        pst::Effect::Permit => "permit",
        pst::Effect::Forbid => "forbid",
    };
    let mut clauses = Vec::with_capacity(template.clauses().len());
    for clause in template.clauses() {
        clauses.push(build_clause(c, clause)?);
    }
    let clauses = PyTuple::new(c.template.py(), clauses)?;
    let annotations: Vec<(String, Py<PyAny>)> = template
        .annotations
        .iter()
        .map(|(k, v)| Ok((k.clone(), v.to_string().into_pyobject(c.template.py())?.into_any().unbind())))
        .collect::<PyResult<_>>()?;
    Ok(c.template
        .call1((
            template.id.0.to_string(),
            effect,
            build_principal_constraint(c, &template.principal)?,
            build_action_constraint(c, &template.action)?,
            build_resource_constraint(c, &template.resource)?,
            clauses,
            build_mapping(c, annotations)?,
        ))?
        .unbind())
}

fn build_slot_values<'py>(
    c: &PstClasses<'py>,
    values: &std::collections::HashMap<pst::SlotId, pst::EntityUID>,
) -> PyResult<Py<PyAny>> {
    let mut items = Vec::with_capacity(values.len());
    for (slot, euid) in values {
        let name = match slot {
            pst::SlotId::Principal => "principal",
            pst::SlotId::Resource => "resource",
            other => return Err(pst_error("SlotId variant", other)),
        };
        items.push((name.to_string(), build_entity_uid(c, euid)?));
    }
    build_mapping(c, items)
}

fn build_policy_set<'py>(c: &PstClasses<'py>, policy_set: &pst::PolicySet) -> PyResult<Py<PyAny>> {
    let mut templates = Vec::with_capacity(policy_set.templates.len());
    for (id, template) in policy_set.templates.iter() {
        templates.push((id.0.to_string(), build_template(c, template)?));
    }
    let mut static_policies = Vec::with_capacity(policy_set.policies.len());
    for (id, static_policy) in policy_set.policies.iter() {
        static_policies.push((id.0.to_string(), build_template(c, static_policy.body())?));
    }
    let mut links = Vec::with_capacity(policy_set.template_links.len());
    for link in &policy_set.template_links {
        links.push(
            c.template_link
                .call1((
                    link.template_id.0.to_string(),
                    link.new_id.0.to_string(),
                    build_slot_values(c, &link.values)?,
                ))?
                .unbind(),
        );
    }
    let links = PyTuple::new(c.policy_set.py(), links)?;
    Ok(c.policy_set
        .call1((build_mapping(c, templates)?, build_mapping(c, static_policies)?, links))?
        .unbind())
}

/// Parse Cedar policy text into typed cedarpy.pst nodes.
#[pyfunction]
#[pyo3(signature = (s))]
fn policies_to_pst(py: Python<'_>, s: String) -> PyResult<Py<PyAny>> {
    let policies = PolicySet::from_str(&s).map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
    let pst = policies.to_pst().map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
    let classes = PstClasses::load(py)?;
    build_policy_set(&classes, &pst)
}

/// An opaque, reusable handle wrapping a parsed Cedar policy set.
///
/// Parsing policies is the dominant per-call cost in `is_authorized`. Callers
/// whose policies are static can parse them once into a `PolicySet` and reuse
/// the handle across many authorization calls, avoiding the re-parse each time:
///
///     ps = PolicySet.from_str(policies)        # parse once
///     for req in requests:
///         is_authorized(req, ps, entities)     # reuse — no re-parse
///
/// A `PolicySet` is accepted anywhere a policies string is accepted:
/// `is_authorized`, `is_authorized_batch`, and `is_authorized_partial`.
///
/// Construct with `PolicySet.from_str(cedar_text)`,
/// `PolicySet.from_json_str(cedar_json)`, or `PolicySet.from_pst(nodes)`; all
/// raise `ValueError` on parse errors. The handle is immutable, and its memory is released automatically
/// when the last Python reference is dropped.
///
/// A set may also contain Cedar *templates* (policies with `?principal` /
/// `?resource` slots). A template authorizes nothing until it is linked to
/// concrete values: `with_linked` / `with_linked_batch` return a NEW handle with
/// the linked policy added (immutable, like `with_added_str`). `templates`
/// (which lists each template's links) and `without_linked` round out the
/// lifecycle.
// `frozen` makes the handle immutable so the authorization functions can borrow
// the inner PolicySet without a runtime borrow check (and share it across
// threads); see `PoliciesArg::resolve`.
#[pyclass(name = "PolicySet", frozen)]
struct PyPolicySet {
    inner: PolicySet,
}

#[pymethods]
impl PyPolicySet {
    /// Parse a `PolicySet` from Cedar policy text (e.g. `permit(...);`).
    ///
    /// Unlike passing policy text to `is_authorized`, parse errors are raised
    /// eagerly here rather than folded into an authorization result.
    ///
    /// :raises ValueError: if the policies cannot be parsed.
    #[staticmethod]
    fn from_str(s: &str) -> PyResult<Self> {
        match PolicySet::from_str(s) {
            Ok(inner) => Ok(PyPolicySet { inner }),
            // `{:#}` renders the full, span-annotated set of parse errors,
            // matching the detail of the string-authorization parse path.
            Err(e) => Err(pyo3::exceptions::PyValueError::new_err(format!("{:#}", e))),
        }
    }

    /// Parse a `PolicySet` from the Cedar JSON (EST) policy format.
    ///
    /// :raises ValueError: if the JSON policies cannot be parsed.
    #[staticmethod]
    fn from_json_str(s: &str) -> PyResult<Self> {
        match PolicySet::from_json_str(s) {
            Ok(inner) => Ok(PyPolicySet { inner }),
            Err(e) => Err(pyo3::exceptions::PyValueError::new_err(format!("{:#}", e))),
        }
    }

    /// Return this policy set as the typed nodes from `cedarpy.pst`.
    ///
    /// `policies_to_pst(text)` is `PolicySet.from_str(text).to_pst()`.
    ///
    /// :raises ValueError: if the set cannot be represented as PST nodes.
    fn to_pst(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        let pst = self
            .inner
            .to_pst()
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("{:#}", e)))?;
        let classes = PstClasses::load(py)?;
        build_policy_set(&classes, &pst)
    }

    /// Build a `PolicySet` from the typed nodes `policies_to_pst` returns.
    ///
    /// The inverse of `PolicySet.to_pst`, so a policy set can be read as
    /// nodes, rewritten, and handed back to the engine.
    ///
    /// :raises TypeError: if given something other than a `cedarpy.pst` node.
    /// :raises ValueError: if the nodes do not form a valid policy set.
    #[staticmethod]
    fn from_pst(node: &Bound<'_, PyAny>) -> PyResult<Self> {
        let pst_set = read_policy_set(node)?;
        match PolicySet::from_pst(pst_set) {
            Ok(inner) => Ok(PyPolicySet { inner }),
            Err(e) => Err(pyo3::exceptions::PyValueError::new_err(format!("{:#}", e))),
        }
    }

    /// Return a NEW `PolicySet` handle: this (compiled) set plus the policies
    /// parsed from `fragment`. The base is cloned, not re-parsed — only the
    /// (typically small) fragment is parsed — so a caller with a static base and
    /// small dynamic fragments avoids re-parsing the base on every call. The
    /// handle is immutable; the base is left unchanged.
    ///
    /// The result is equivalent (same authorization decisions) to parsing the
    /// concatenated base-plus-fragment policy text. Cedar derives a `PolicyId`
    /// for surface-syntax policies positionally per parse (`policy0`, `policy1`,
    /// …), so a fragment parsed on its own restarts at `policy0` and would
    /// collide with the base. To stay equivalent to the concatenated parse, the
    /// fragment's colliding ids are renumbered to follow the base (the way
    /// concatenated text numbers them); non-colliding ids are preserved. A
    /// fragment policy's `@id` annotation (which Cedar treats as inert) is
    /// unaffected.
    ///
    /// :raises ValueError: if `fragment` cannot be parsed.
    fn with_added_str(&self, fragment: &str) -> PyResult<Self> {
        let added = PolicySet::from_str(fragment)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("{:#}", e)))?;
        let mut merged = self.inner.clone();
        // `rename_duplicates = true`: renumber the fragment's per-parse ids that
        // collide with the base, so a surface-syntax fragment (whose ids always
        // restart at `policy0`) composes with a non-empty base exactly as the
        // concatenated text would. cedar updates any internal references to the
        // renamed ids. The only error path left is a malformed fragment, caught
        // by `from_str` above; `merge` itself cannot fail here.
        merged
            .merge(&added, true)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
        Ok(PyPolicySet { inner: merged })
    }

    /// Return a NEW `PolicySet` handle: this set with `links` applied. Each
    /// link instantiates a template in the set into a concrete, evaluatable
    /// policy by filling its slots. This is the primary linking entry point;
    /// `with_linked` is the single-link convenience over it.
    ///
    /// Linking does not modify or rename the template: it creates a *new*
    /// policy (the template with its slots filled) and adds it to the returned
    /// set. The template stays in the set and can be linked again under a
    /// different `new_id`, which is how one template grants many principals.
    ///
    /// `links` is a list of dicts, each with:
    ///   - `template_id`: which template to fill in — its `@id` annotation
    ///     value, or the parser-assigned `policy<N>` id (see resolution below),
    ///   - `new_id`: the id assigned to the new template-linked policy this
    ///     creates. It is the caller's to choose — neither a template id nor a
    ///     principal — and mirrors the Cedar CLI's `--new-id`,
    ///   - `values`: a dict mapping each slot (`"?principal"` / `"?resource"`)
    ///     to an entity uid, given as a Cedar string (`'User::"jane"'`) or a
    ///     `{"type": ..., "id": ...}` dict — the same two forms `is_authorized`
    ///     accepts for a request principal/resource.
    ///
    /// The base is cloned once and every link is applied to the clone, so a
    /// batch of links pays a single clone rather than one per link. The base is
    /// left unchanged. The operation is all-or-nothing: if any link fails, the
    /// partially-built clone is discarded and `ValueError` is raised, so the
    /// returned handle (when one is returned) reflects every requested link.
    ///
    /// :raises ValueError: if a `template_id` is not a template in the set, a
    ///     `new_id` collides with an existing policy id, a slot value cannot be
    ///     parsed, or the slots a template declares are not exactly filled.
    /// :raises KeyError: if a link dict is missing `template_id`, `new_id`, or
    ///     `values`.
    /// A `template_id` may be either the template's literal Cedar id or, when no
    /// template has that literal id, the value of a template's `@id` annotation
    /// (see `with_linked` / `resolve_template_id` for the resolution rule).
    fn with_linked_batch(&self, links: Vec<Bound<'_, PyDict>>) -> PyResult<Self> {
        let mut specs = Vec::with_capacity(links.len());
        for link in &links {
            specs.push(parse_link_spec(link)?);
        }
        self.apply_links(specs)
    }

    /// Return a NEW `PolicySet` handle with a single template linked. Sugar for
    /// `with_linked_batch` with one link; see it for the slot-value forms and
    /// error semantics.
    ///
    /// `template_id` is resolved to a template in the set by its literal Cedar
    /// id first; if no template has that literal id, it is matched against the
    /// value of each template's `@id` annotation (the labeling convention the
    /// Cedar CLI uses for linking — an `@id` is otherwise inert and is not the
    /// template's id). An `@id` match must be unambiguous.
    ///
    /// :raises ValueError: as `with_linked_batch`.
    #[pyo3(signature = (template_id, new_id, values))]
    fn with_linked(
        &self,
        template_id: &str,
        new_id: &str,
        values: &Bound<'_, PyDict>,
    ) -> PyResult<Self> {
        let spec = (
            template_id.to_string(),
            new_id.to_string(),
            parse_slot_values(values)?,
        );
        self.apply_links(vec![spec])
    }

    /// The templates in this set — the linkable `?principal` / `?resource`
    /// policies — as a list of dicts, one per template:
    ///
    ///   - `id`: the template's literal Cedar id (the positional `policy<N>`,
    ///     or an explicit id if one was assigned).
    ///   - `id_annotation`: the value of its `@id` annotation, or `None` when it
    ///     has none. **Prefer this when linking** — an `@id` is stable across
    ///     parsing and merging, whereas the positional `id` is not (see
    ///     `with_linked`). Either is accepted as `template_id`.
    ///   - `slots`: the slot keys it declares, e.g. `["?principal"]` — the keys
    ///     a link's `values` must fill.
    ///   - `links`: the template-linked policies derived from this template,
    ///     each `{"id": <new_id>, "values": {slot: entity_uid}}`. Empty until
    ///     the template is linked. This is the filled-in view: it shows every
    ///     concrete policy produced from the template and what each slot was
    ///     bound to.
    ///
    /// Templates themselves are not counted by `len()` and authorize nothing;
    /// their `links` are policies and do count.
    fn templates<'py>(&self, py: Python<'py>) -> PyResult<Vec<Bound<'py, PyDict>>> {
        // Group the set's template-linked policies by the template they came
        // from (one pass over policies()), then attach each group to its
        // template below.
        let mut links_by_template: HashMap<String, Vec<Bound<'py, PyDict>>> = HashMap::new();
        for p in self.inner.policies() {
            let Some(template_pid) = p.template_id() else { continue };
            let link = PyDict::new(py);
            link.set_item("id", p.id().to_string())?;
            let values = PyDict::new(py);
            if let Some(slot_values) = p.template_links() {
                for (slot, euid) in slot_values {
                    values.set_item(slot.to_string(), euid.to_string())?;
                }
            }
            link.set_item("values", values)?;
            links_by_template
                .entry(template_pid.to_string())
                .or_default()
                .push(link);
        }

        let mut out = Vec::new();
        for t in self.inner.templates() {
            let tid = t.id().to_string();
            let d = PyDict::new(py);
            // `@id` value, if declared (`""` for bare `@id` / `@id("")`); `None`
            // when absent. Raw `&str` keys, like `lookup_id_annotation`.
            let id_annotation = t
                .annotations()
                .find(|(k, _)| *k == "id")
                .map(|(_, v)| v.to_string());
            let slots: Vec<String> = t.slots().map(|s| s.to_string()).collect();
            let links = links_by_template.remove(&tid).unwrap_or_default();
            d.set_item("id", tid)?;
            d.set_item("id_annotation", id_annotation)?;
            d.set_item("slots", slots)?;
            d.set_item("links", links)?;
            out.push(d);
        }
        Ok(out)
    }

    /// Return a NEW `PolicySet` handle with the template-linked policy
    /// `link_id` removed (the immutable counterpart to `with_linked`). The base
    /// is cloned and left unchanged.
    ///
    /// :raises ValueError: if `link_id` is not a template-linked policy in the
    ///     set (no such id, or it names a static policy or a template).
    fn without_linked(&self, link_id: &str) -> PyResult<Self> {
        let mut merged = self.inner.clone();
        merged
            .unlink(PolicyId::new(link_id))
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("unlink failed: {e}")))?;
        Ok(PyPolicySet { inner: merged })
    }

    /// The number of policies in the set.
    fn __len__(&self) -> usize {
        self.inner.policies().count()
    }

    /// The policy set rendered back to Cedar policy text.
    fn __str__(&self) -> String {
        self.inner.to_string()
    }

    fn __repr__(&self) -> String {
        format!("PolicySet(<{} policies>)", self.inner.policies().count())
    }
}

impl PyPolicySet {
    /// Clone the base once and apply every link to the clone, returning a NEW
    /// handle. Single and batch linking share this so they have identical
    /// semantics and the batch case pays one clone. A failed link aborts the
    /// whole operation: the partially-built clone is dropped and the base
    /// (borrowed immutably) is untouched.
    ///
    /// `@id`-based `template_id` resolution is indexed once up front rather than
    /// scanned per link: a batch of `L` links over a set of `T` templates costs
    /// `O(T + L)`, not `O(T * L)`. Linking never adds or removes templates, so
    /// the index stays valid across the whole batch.
    fn apply_links(
        &self,
        specs: Vec<(String, String, HashMap<SlotId, EntityUid>)>,
    ) -> PyResult<Self> {
        let mut merged = self.inner.clone();
        let id_index = build_template_id_index(&merged);
        for (template_id, new_id, values) in specs {
            let resolved = resolve_template_id(&merged, &id_index, &template_id)?;
            merged
                .link(resolved, PolicyId::new(new_id), values)
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("template link failed: {e}")))?;
        }
        Ok(PyPolicySet { inner: merged })
    }
}

/// Index each template's `@id` annotation value to its `PolicyId`, for cheap
/// repeated resolution across a batch. A value declared by more than one
/// template maps to `None` (ambiguous), so resolution can reject it rather than
/// link an arbitrary one (cf. the duplicate-`@id` concern in #77).
/// `Template::annotations()` yields raw `&str` keys, so this avoids Cedar's
/// identifier-parse cost.
fn build_template_id_index(pset: &PolicySet) -> HashMap<String, Option<PolicyId>> {
    let mut index: HashMap<String, Option<PolicyId>> = HashMap::new();
    for t in pset.templates() {
        if let Some((_, v)) = t.annotations().find(|(k, _)| *k == "id") {
            index
                .entry(v.to_string())
                .and_modify(|e| *e = None) // already seen this @id => ambiguous
                .or_insert_with(|| Some(t.id().clone()));
        }
    }
    index
}

/// Resolve a caller-supplied template id to a template's real `PolicyId`.
///
/// Cedar identifies a template by its parser-assigned `PolicyId` (`policy0`,
/// …); an `@id("name")` annotation is inert and is NOT the id (the Cedar CLI
/// applies `@id` as a labeling convention at load time; the library does not).
/// To keep linking ergonomic and match that CLI convention, we accept either
/// the literal template id (an `O(1)` lookup) or — when no template has that
/// literal id — the value of a template's `@id` annotation, via the prebuilt
/// `id_index` (also `O(1)`). An `@id` match must be unambiguous. Resolution
/// never renames or rebuilds the set; it only maps the friendly name to the
/// authoritative parser id.
fn resolve_template_id(
    pset: &PolicySet,
    id_index: &HashMap<String, Option<PolicyId>>,
    given: &str,
) -> PyResult<PolicyId> {
    let literal = PolicyId::new(given);
    if pset.template(&literal).is_some() {
        return Ok(literal);
    }
    match id_index.get(given) {
        Some(Some(pid)) => Ok(pid.clone()),
        Some(None) => Err(pyo3::exceptions::PyValueError::new_err(format!(
            "ambiguous template @id {given:?}: multiple templates declare it; link by the literal template id instead"
        ))),
        None => Err(pyo3::exceptions::PyValueError::new_err(format!(
            "no template with id or @id {given:?} in the policy set"
        ))),
    }
}

/// Map a Python slot key to a Cedar `SlotId`. Only the two GA template slots
/// exist; anything else is a caller error.
fn parse_slot_id(key: &str) -> PyResult<SlotId> {
    match key {
        "?principal" => Ok(SlotId::principal()),
        "?resource" => Ok(SlotId::resource()),
        other => Err(pyo3::exceptions::PyValueError::new_err(format!(
            "unknown template slot {other:?}; expected \"?principal\" or \"?resource\""
        ))),
    }
}

/// Parse a `values` dict — slot key (`"?principal"`/`"?resource"`) to an entity
/// uid in either accepted form — into the `HashMap` `PolicySet::link` takes.
fn parse_slot_values(values: &Bound<'_, PyDict>) -> PyResult<HashMap<SlotId, EntityUid>> {
    let mut out: HashMap<SlotId, EntityUid> = HashMap::new();
    for (k, v) in values.iter() {
        let key: String = k.extract().map_err(|_| {
            pyo3::exceptions::PyTypeError::new_err("template slot key must be a string")
        })?;
        let slot = parse_slot_id(&key)?;
        let what = format!("template slot {key:?} value");
        let euid = euid_input_from_value(&v, || what.clone())?
            .parse(&what)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("{e:#}")))?;
        out.insert(slot, euid);
    }
    Ok(out)
}

/// Parse one link spec dict — `{"template_id", "new_id", "values"}` — into the
/// `(template_id, new_id, slot values)` tuple `apply_links` consumes. The ids
/// stay as strings; `template_id` is resolved to a real template `PolicyId`
/// later, against the live set (see `resolve_template_id`).
fn parse_link_spec(
    link: &Bound<'_, PyDict>,
) -> PyResult<(String, String, HashMap<SlotId, EntityUid>)> {
    let template_id: String = link
        .get_item("template_id")?
        .ok_or_else(|| pyo3::exceptions::PyKeyError::new_err("link dict missing 'template_id' key"))?
        .extract()?;
    let new_id: String = link
        .get_item("new_id")?
        .ok_or_else(|| pyo3::exceptions::PyKeyError::new_err("link dict missing 'new_id' key"))?
        .extract()?;
    let values_obj = link
        .get_item("values")?
        .ok_or_else(|| pyo3::exceptions::PyKeyError::new_err("link dict missing 'values' key"))?;
    let values_dict = values_obj.cast::<PyDict>().map_err(|_| {
        pyo3::exceptions::PyTypeError::new_err(
            "link 'values' must be a dict mapping slot keys to entity uids",
        )
    })?;
    Ok((template_id, new_id, parse_slot_values(values_dict)?))
}

/// An opaque, reusable handle wrapping a parsed Cedar entity set.
///
/// Parsing entities (deserializing the JSON and computing the transitive
/// closure of the `parents` graph) is a per-call cost in `is_authorized`.
/// Callers who authorize many requests against a large, stable base graph can
/// parse it once into an `Entities` handle and reuse it, avoiding the re-parse
/// each time:
///
///     base = Entities.from_json_str(entities_json)   # parse once
///     for req in requests:
///         is_authorized(req, policy_set, base)        # reuse — no re-parse
///
/// An `Entities` is accepted anywhere an entities string/list is accepted:
/// `is_authorized`, `is_authorized_batch`, and `is_authorized_partial`.
///
/// For the common "stable base plus a tiny per-request delta" pattern, build
/// the base once and add the delta per call with `with_added_json_str`, which
/// parses only the delta:
///
///     per_request = base.with_added_json_str(delta_json)
///     is_authorized(req, policy_set, per_request)
///
/// Construct with `Entities.from_json_str(cedar_json, schema=None)`. The handle
/// is immutable — `with_added_json_str` returns a NEW handle and leaves the base
/// unchanged — and its memory is released automatically when the last Python
/// reference is dropped.
///
/// The optional `schema` is applied when the handle is built; it is not
/// re-applied later. A handle reused in an `is_authorized(..., schema=...)`
/// call does NOT get its entities re-validated against that schema — same
/// pre-parsed-handle contract as `PolicySet`.
// `frozen` makes the handle immutable so the authorization functions can borrow
// the inner Entities without a runtime borrow check (and share it across
// threads); see `EntitiesArg::resolve`.
#[pyclass(name = "Entities", frozen)]
struct PyEntities {
    inner: Entities,
}

#[pymethods]
impl PyEntities {
    /// Parse an `Entities` handle from a Cedar JSON entities document.
    ///
    /// `schema` (optional) is Cedar schema text, JSON, or a pre-parsed `Schema`
    /// handle; when supplied, the entities are validated against it at
    /// construction time. Parse errors are raised eagerly here rather than
    /// folded into an authorization result.
    ///
    /// :raises ValueError: if the entities (or schema) cannot be parsed, or the
    ///     entities do not conform to `schema`.
    #[staticmethod]
    #[pyo3(signature = (s, schema = None))]
    fn from_json_str(s: &str, schema: Option<SchemaArg>) -> PyResult<Self> {
        let mut slot: Option<Schema> = None;
        let schema_ref = resolve_schema_arg_eager(&schema, &mut slot)?;
        match Entities::from_json_str(s, schema_ref) {
            Ok(inner) => Ok(PyEntities { inner }),
            Err(e) => Err(pyo3::exceptions::PyValueError::new_err(format!("{:#}", e))),
        }
    }

    /// Return a NEW `Entities` handle: this base set plus the entities parsed
    /// from `delta`. The base is cloned, not re-parsed — only `delta` is parsed
    /// — so the stable base is reused across calls. The merge is a disjoint
    /// union: an entity in `delta` whose uid already exists in the base (and is
    /// not byte-identical) is an error.
    ///
    /// `schema` (optional), when supplied, validates the combined set.
    ///
    /// :raises ValueError: if `delta` (or `schema`) cannot be parsed, if a
    ///     `delta` uid duplicates a base uid, or the result violates `schema`.
    #[pyo3(signature = (delta, schema = None))]
    fn with_added_json_str(&self, delta: &str, schema: Option<SchemaArg>) -> PyResult<Self> {
        let mut slot: Option<Schema> = None;
        let schema_ref = resolve_schema_arg_eager(&schema, &mut slot)?;
        // Clone keeps the handle immutable; `add_entities_from_json_str` consumes
        // the clone and parses only `delta` (not the base) before recomputing the
        // transitive closure.
        match self.inner.clone().add_entities_from_json_str(delta, schema_ref) {
            Ok(inner) => Ok(PyEntities { inner }),
            Err(e) => Err(pyo3::exceptions::PyValueError::new_err(format!("{:#}", e))),
        }
    }

    /// The number of entities in the set.
    fn __len__(&self) -> usize {
        self.inner.iter().count()
    }

    /// The entity set rendered back to Cedar JSON (suitable for `from_json_str`).
    fn __str__(&self) -> String {
        // `Entities` exposes only `write_to_json` (to a writer), not a
        // string/value dump, so render through an in-memory buffer.
        let mut buf: Vec<u8> = Vec::new();
        match self.inner.write_to_json(&mut buf) {
            Ok(()) => String::from_utf8_lossy(&buf).into_owned(),
            Err(e) => format!("<unrenderable Entities: {e}>"),
        }
    }

    fn __repr__(&self) -> String {
        format!("Entities(<{} entities>)", self.inner.iter().count())
    }
}

/// An opaque, reusable handle wrapping a parsed Cedar schema.
///
/// Parsing a schema is a per-call cost in `is_authorized` (and
/// `validate_policies`). Callers whose schema is static can parse it once
/// into a `Schema` and reuse the handle across many calls, avoiding the
/// re-parse each time:
///
///     schema = Schema.from_str(cedar_schema_text)   # parse once
///     for req in requests:
///         is_authorized(req, ps, entities, schema)  # reuse — no re-parse
///
/// A `Schema` is accepted anywhere a schema string is accepted:
/// `is_authorized`, `is_authorized_batch`, `is_authorized_partial`,
/// `validate_policies`, and the `schema` parameter of
/// `Entities.from_json_str` / `Entities.with_added_json_str`.
///
/// Construct with `Schema.from_str(cedar_text)` for the Cedar human-readable
/// schema syntax, or `Schema.from_json_str(json_text)` for the JSON schema
/// format. Both raise `ValueError` on parse errors. The handle is immutable,
/// and its memory is released automatically when the last Python reference is
/// dropped. `str()` renders the schema to Cedar schema syntax (suitable for
/// `Schema.from_str`, whichever format it was constructed from).
#[pyclass(name = "Schema", frozen)]
struct PySchema {
    inner: Schema,
    // The pre-compilation fragment. `Schema` is a one-way compilation with no
    // render-back API, but `SchemaFragment` round-trips — keep it so `__str__`
    // can render the schema.
    fragment: SchemaFragment,
}

impl PySchema {
    /// Compile `fragment` into the validated `Schema` and build the handle,
    /// keeping the fragment for `__str__`. Compilation errors (e.g. an
    /// undeclared entity type) raise `ValueError`, like the parse errors in
    /// the constructors.
    fn from_fragment(fragment: SchemaFragment) -> PyResult<Self> {
        match Schema::from_schema_fragments([fragment.clone()]) {
            Ok(inner) => Ok(PySchema { inner, fragment }),
            Err(e) => Err(pyo3::exceptions::PyValueError::new_err(format!("{:#}", e))),
        }
    }
}

#[pymethods]
impl PySchema {
    /// Parse a `Schema` from Cedar human-readable schema syntax.
    ///
    /// :raises ValueError: if the schema cannot be parsed.
    #[staticmethod]
    fn from_str(s: &str) -> PyResult<Self> {
        // Parse to a fragment first (rather than `Schema::from_str`) so the
        // handle can render itself; `Schema`'s own constructors go through the
        // same fragment parse internally. Schema warnings are dropped, as
        // `Schema::from_str` drops them.
        match SchemaFragment::from_cedarschema_str(s) {
            Ok((fragment, _warnings)) => Self::from_fragment(fragment),
            Err(e) => Err(pyo3::exceptions::PyValueError::new_err(format!("{:#}", e))),
        }
    }

    /// Parse a `Schema` from the Cedar JSON schema format.
    ///
    /// :raises ValueError: if the JSON schema cannot be parsed.
    #[staticmethod]
    fn from_json_str(s: &str) -> PyResult<Self> {
        match SchemaFragment::from_json_str(s) {
            Ok(fragment) => Self::from_fragment(fragment),
            Err(e) => Err(pyo3::exceptions::PyValueError::new_err(format!("{:#}", e))),
        }
    }

    /// The schema rendered to Cedar schema syntax (suitable for
    /// `Schema.from_str`), whichever format the handle was constructed from.
    fn __str__(&self) -> String {
        // `to_cedarschema` can fail on JSON-schema constructs with no Cedar
        // syntax spelling; report rather than raise, as `Entities.__str__` does.
        match self.fragment.to_cedarschema() {
            Ok(rendered) => rendered,
            Err(e) => format!("<unrenderable Schema: {e}>"),
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "Schema(<{} entity types, {} actions>)",
            self.inner.entity_types().count(),
            self.inner.actions().count()
        )
    }
}

/// The `schema` argument accepted by the authorization and validation
/// functions: either Cedar schema text / JSON (`str`) or a pre-parsed
/// `Schema` handle. `Source` is tried first so a `str` argument pays no
/// failed handle extraction; a `Schema` handle falls through to `Handle`.
#[derive(FromPyObject)]
enum SchemaArg {
    Source(String),
    Handle(Py<PySchema>),
}

/// Resolve an optional `SchemaArg` on the authorization path: parse errors
/// are collected in `errs` (the authz path folds schema errors into the
/// response). Returns `None` when no schema is provided, when the source is
/// empty, or on parse failure.
fn resolve_schema_arg<'a>(
    arg: &'a Option<SchemaArg>,
    slot: &'a mut Option<Schema>,
    errs: &mut Vec<Error>,
    verbose: bool,
) -> Option<&'a Schema> {
    match arg {
        None => None,
        Some(SchemaArg::Handle(handle)) => Some(&handle.get().inner),
        Some(SchemaArg::Source(s)) => {
            if verbose { println!("schema: {}", s); }
            let trimmed = s.trim();
            if trimmed.is_empty() {
                return None;
            }
            match parse_schema_src(trimmed) {
                Ok(schema) => {
                    *slot = Some(schema);
                    slot.as_ref()
                }
                Err((was_json, e)) => {
                    if verbose {
                        println!("!!! could not construct schema from {}: {}",
                                 if was_json { "JSON" } else { "str" }, e);
                    }
                    errs.push(Error::msg(format!("failed to parse schema from {}: {}",
                                                 if was_json { "JSON" } else { "Cedar" }, e)));
                    None
                }
            }
        }
    }
}

/// Resolve an optional `SchemaArg` on the constructor path: parse errors
/// raise `ValueError` eagerly.
fn resolve_schema_arg_eager<'a>(
    arg: &'a Option<SchemaArg>,
    slot: &'a mut Option<Schema>,
) -> PyResult<Option<&'a Schema>> {
    match arg {
        None => Ok(None),
        Some(SchemaArg::Handle(handle)) => Ok(Some(&handle.get().inner)),
        Some(SchemaArg::Source(s)) => {
            *slot = parse_schema_arg(Some(s.as_str()))?;
            Ok(slot.as_ref())
        }
    }
}

/// Dispatch a trimmed, non-empty schema source to the right Cedar parser:
/// a `{...}` source is parsed as JSON, anything else as Cedar schema syntax.
/// Returns the parsed `Schema`, or `(was_json, error_string)` so each caller
/// can format its own message and tell which parser was attempted. The
/// empty/`None` source and how the error is surfaced (raise / collect /
/// serialize) are the caller's concern — see `parse_schema_arg`,
/// `resolve_schema_arg`, and `validate_policies`.
fn parse_schema_src(trimmed: &str) -> Result<Schema, (bool, String)> {
    if trimmed.starts_with('{') {
        Schema::from_json_str(trimmed).map_err(|e| (true, e.to_string()))
    } else {
        Schema::from_str(trimmed).map_err(|e| (false, e.to_string()))
    }
}

/// Parse the optional `schema` argument (Cedar schema text or JSON) shared by
/// the handle constructors. Raises `ValueError` eagerly (these are
/// constructors, not authz calls) and treats an empty/whitespace string as
/// "no schema".
fn parse_schema_arg(schema: Option<&str>) -> PyResult<Option<Schema>> {
    let Some(src) = schema else { return Ok(None) };
    let trimmed = src.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    parse_schema_src(trimmed)
        .map(Some)
        .map_err(|(_, e)| pyo3::exceptions::PyValueError::new_err(format!("failed to parse schema: {e}")))
}

/// The `policies` argument accepted by the authorization functions: either
/// Cedar policy text (`str`) or a pre-parsed `PolicySet` handle. `Source` (the
/// common string path) is tried first so a `str` argument pays no failed handle
/// extraction; a `PolicySet` handle falls through to `Handle`. Order matters:
/// trying `Handle` first would churn a discarded `PyErr` on every string call.
#[derive(FromPyObject)]
enum PoliciesArg {
    Source(String),
    Handle(Py<PyPolicySet>),
}

impl PoliciesArg {
    /// Resolve to a borrowed `PolicySet`. The handle path borrows the parsed
    /// set with no re-parse; the source path parses the text, recording any
    /// parse error in `errs` and yielding an empty set (preserving the prior
    /// string-path behavior). The returned reference borrows from `slot`,
    /// which the caller must keep alive for the duration of use. A parse error
    /// is printed to stdout only when `verbose`, consistent with the other
    /// diagnostic output on the authorization path.
    fn resolve<'a>(&'a self, slot: &'a mut Option<PolicySet>, errs: &mut Vec<Error>, verbose: bool) -> &'a PolicySet {
        match self {
            PoliciesArg::Handle(handle) => &handle.get().inner,
            PoliciesArg::Source(policies) => {
                let pset = match PolicySet::from_str(policies) {
                    Ok(pset) => pset,
                    Err(parse_errors) => {
                        let err_message = format!("policy parse errors:\n{:#}", parse_errors);
                        if verbose { println!("{:#}", err_message); }
                        errs.push(Error::msg(err_message));
                        PolicySet::new()
                    }
                };
                slot.insert(pset)
            }
        }
    }
}

/// The `entities` argument accepted by the authorization functions: either a
/// Cedar JSON entities string (`str`) or a pre-parsed `Entities` handle. Mirrors
/// `PoliciesArg`: `Source` (the common string path) is tried first so a `str`
/// argument pays no failed handle extraction; a handle falls through to
/// `Handle`. Order matters — trying `Handle` first would churn a discarded
/// `PyErr` on every string call. (Python lists are serialized to a JSON string
/// by the wrapper before they reach here, so only `str` and the handle arrive.)
#[derive(FromPyObject)]
enum EntitiesArg {
    Source(String),
    Handle(Py<PyEntities>),
}

impl EntitiesArg {
    /// Resolve to a borrowed `Entities`. The handle path borrows the parsed set
    /// with no re-parse; the source path parses the JSON (with `schema`),
    /// recording any error in `errs` and yielding an empty set (preserving the
    /// prior string-path behavior). The returned reference borrows from `slot`,
    /// which the caller must keep alive for the duration of use.
    fn resolve<'a>(
        &'a self,
        slot: &'a mut Option<Entities>,
        schema: Option<&Schema>,
        errs: &mut Vec<Error>,
    ) -> &'a Entities {
        match self {
            EntitiesArg::Handle(handle) => &handle.get().inner,
            EntitiesArg::Source(entities) => {
                slot.insert(make_entities(entities, schema, errs))
            }
        }
    }

    /// Resolve to an owned partial `Entities` for the partial-eval path.
    /// `Entities::partial` consumes `self`, so the handle path clones first
    /// (still cheaper than re-deserializing the base JSON); the source path
    /// parses as usual. Either way the result is owned, matching the prior
    /// string-path local.
    fn resolve_partial(&self, schema: Option<&Schema>, errs: &mut Vec<Error>) -> Entities {
        match self {
            EntitiesArg::Handle(handle) => handle.get().inner.clone().partial(),
            EntitiesArg::Source(entities) => {
                make_entities(entities, schema, errs).partial()
            }
        }
    }
}


/// How a principal/action/resource was supplied by the Python caller.
///
/// `Cedar` is the surface-syntax string form (e.g. `User::"alice"`),
/// parsed via `EntityUid::from_str`. This is constrained by Cedar's
/// surface grammar — entity ids containing whitespace or other
/// characters that are not valid in the surface syntax cannot be
/// expressed this way.
///
/// `Json` is the structured form (e.g. `{"type": "User", "id":
/// "alice"}`), parsed via `EntityUid::from_json`. This bypasses the
/// surface-syntax restriction and matches the `JsonEUID` form used by
/// cedar-java's request API.
pub enum EntityUidInput {
    Cedar(String),
    Json(serde_json::Value),
}

impl EntityUidInput {
    fn parse(&self, what: &str) -> Result<EntityUid> {
        match self {
            EntityUidInput::Cedar(s) => s
                .parse()
                .context(format!("Failed to parse {what} as entity Uid")),
            EntityUidInput::Json(v) => EntityUid::from_json(v.clone())
                .context(format!("Failed to parse {what} as entity Uid (JSON form)")),
        }
    }
}

pub struct RequestArgs {
    /// Principal for the request — surface-syntax string `User::"alice"`
    /// or structured `{"type": "User", "id": "alice"}`.
    pub principal: EntityUidInput,
    /// Action for the request — same form options as `principal`.
    pub action: EntityUidInput,
    /// Resource for the request — same form options as `principal`.
    pub resource: EntityUidInput,
    /// A JSON object representing the context for the request.
    /// Should be a (possibly empty) map from keys to values.
    pub context_json: Option<String>,

    /// An optional correlation id that will be copied to the AuthzResponse
    pub correlation_id: Option<String>,
}

impl RequestArgs {
    /// Turn this `RequestArgs` into the appropriate `Request` object
    fn get_request(&self, schema: Option<&Schema>) -> Result<Request> {
        let principal: EntityUid = self.principal.parse("principal")?;
        let action: EntityUid = self.action.parse("action")?;
        let resource: EntityUid = self.resource.parse("resource")?;
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
fn is_authorized(request: Bound<'_, PyDict>,
                 policies: PoliciesArg,
                 entities: EntitiesArg,
                 schema: Option<SchemaArg>,
                 verbose: Option<bool>)
                 -> PyResult<String> {
    Ok(is_authorized_batch(vec![request], policies, entities, schema, verbose)?[0].clone())
}

#[pyfunction]
#[pyo3(signature = (requests, policies, entities, schema = None, verbose = false,))]
fn is_authorized_batch(requests: Vec<Bound<'_, PyDict>>,
                       policies: PoliciesArg,
                       entities: EntitiesArg,
                       schema: Option<SchemaArg>,
                       verbose: Option<bool>)
                       -> PyResult<Vec<String>> {
    // CLI AuthorizeArgs: https://github.com/cedar-policy/cedar/blob/main/cedar-policy-cli/src/lib.rs#L183
    let verbose = verbose.unwrap_or(false);
    if verbose {
        //println!("requests: {}", requests);
        match &policies {
            PoliciesArg::Source(p) => println!("policies: {}", p),
            PoliciesArg::Handle(_) => println!("policies: <pre-parsed PolicySet handle>"),
        }
        match &entities {
            EntitiesArg::Source(e) => println!("entities: {}", e),
            EntitiesArg::Handle(_) => println!("entities: <pre-parsed Entities handle>"),
        }
        match &schema {
            None => println!("schema: <none>"),
            Some(SchemaArg::Source(s)) => println!("schema: {}", s),
            Some(SchemaArg::Handle(_)) => println!("schema: <pre-parsed Schema handle>"),
        }
    }
    let mut errs: Vec<Error> = vec![];

    // probably need to deconstruct execute_authorization_request so that we can reuse the
    // expensive parts (policies, entities, schema):
    // parse policies (or borrow the pre-parsed PolicySet handle, skipping the parse)
    // When a pre-parsed handle is supplied, parse_policies_duration_micros measures only
    // the (near-zero) borrow, not the original parse; policies_pre_parsed flags this.
    let policies_pre_parsed = matches!(&policies, PoliciesArg::Handle(_));
    let t_parse_policies = Instant::now();
    let mut policy_set_slot: Option<PolicySet> = None;
    let policy_set = policies.resolve(&mut policy_set_slot, &mut errs, verbose);
    let t_parse_policies_duration = t_parse_policies.elapsed();

    // parse schema (or borrow the pre-parsed Schema handle, skipping the parse)
    let schema_pre_parsed = matches!(&schema, Some(SchemaArg::Handle(_)));
    let t_start_schema = Instant::now();
    let mut schema_slot: Option<Schema> = None;
    let schema_ref = resolve_schema_arg(&schema, &mut schema_slot, &mut errs, verbose);
    let t_parse_schema_duration = t_start_schema.elapsed();
    // load entities (or borrow the pre-parsed Entities handle, skipping the parse)
    let entities_pre_parsed = matches!(&entities, EntitiesArg::Handle(_));
    let t_load_entities = Instant::now();
    let mut entities_slot: Option<Entities> = None;
    let entities = entities.resolve(&mut entities_slot, schema_ref, &mut errs);
    let t_load_entities_duration = t_load_entities.elapsed();

    // build a list of RequestArgs
    let mut request_args_vec: Vec<RequestArgs> = Vec::new();
    for request in requests.iter() {
        request_args_vec.push(to_request_args(request)?);
    }

    let mut responses_vec: Vec<String> = Vec::new();

    // evaluate access one at a time (future work: eval in parallel)
    for request_args in request_args_vec.iter() {
        if errs.is_empty() {
            let ans = execute_authorization_request(&request_args,
                                                    policy_set,
                                                    entities,
                                                    schema_ref,
                                                    verbose);
            let response_string: String = match ans {
                Ok(mut ans) => {
                    ans.metrics.insert(String::from("parse_policies_duration_micros"),
                                       t_parse_policies_duration.as_micros());
                    ans.metrics.insert(String::from("policies_pre_parsed"),
                                       policies_pre_parsed as u128);
                    ans.metrics.insert(String::from("parse_schema_duration_micros"),
                                       t_parse_schema_duration.as_micros());
                    ans.metrics.insert(String::from("schema_pre_parsed"),
                                       schema_pre_parsed as u128);
                    ans.metrics.insert(String::from("load_entities_duration_micros"),
                                       t_load_entities_duration.as_micros());
                    ans.metrics.insert(String::from("entities_pre_parsed"),
                                       entities_pre_parsed as u128);

                    let to_json_str_result = serde_json::to_string(&ans);
                    match to_json_str_result {
                        Ok(json_str) => { json_str }
                        Err(err) => {
                            if verbose { println!("{:#}", err); }
                            make_authz_result_for_errors(&vec![Error::from(err)])
                        }
                    }
                }
                Err(errs) => {
                    if verbose {
                        for err in &errs {
                            println!("{:#}", err);
                        }
                    }
                    make_authz_result_for_errors(&errs)
                }
            };
            responses_vec.push(response_string);
        } else {
            responses_vec.push(make_authz_result_for_errors(&errs))
        }

    }

    Ok(responses_vec)
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

/// Classify a Python entity-uid value as a Cedar surface-syntax string
/// (e.g. `User::"alice"`) or a structured `{"type": ..., "id": ...}` dict
/// (parsed via `EntityUid::from_json`). `what` labels the value in error
/// messages (e.g. `request[principal]` or `template slot "?principal" value`)
/// and is computed lazily — it is only needed on an error, so the success path
/// (the hot per-request case) allocates no label. Shared by request
/// principal/action/resource extraction and template slot values, so both
/// accept the same two forms.
fn euid_input_from_value(
    value: &Bound<'_, PyAny>,
    what: impl Fn() -> String,
) -> PyResult<EntityUidInput> {
    if let Ok(s) = value.cast::<PyString>() {
        Ok(EntityUidInput::Cedar(s.to_string()))
    } else if let Ok(d) = value.cast::<PyDict>() {
        let type_name: String = d
            .get_item("type")?
            .ok_or_else(|| pyo3::exceptions::PyKeyError::new_err(
                format!("{} dict missing 'type' key", what())))?
            .extract()?;
        let id: String = d
            .get_item("id")?
            .ok_or_else(|| pyo3::exceptions::PyKeyError::new_err(
                format!("{} dict missing 'id' key", what())))?
            .extract()?;
        Ok(EntityUidInput::Json(json!({"type": type_name, "id": id})))
    } else {
        Err(pyo3::exceptions::PyTypeError::new_err(format!(
            "{} must be a string (e.g. 'User::\"alice\"') or a dict with 'type' and 'id' keys",
            what(),
        )))
    }
}

/// Extract a principal/action/resource value from a Python request
/// dict. Accepts either a string (Cedar surface syntax, e.g.
/// `User::"alice"`) or a dict with `type` and `id` keys (the
/// structured form, parsed via `EntityUid::from_json`).
fn extract_euid_field(
    request: &Bound<'_, PyDict>,
    field: &str,
) -> PyResult<EntityUidInput> {
    let value = request
        .get_item(field)?
        .ok_or_else(|| pyo3::exceptions::PyKeyError::new_err(field.to_string()))?;
    euid_input_from_value(&value, || format!("request[{field}]"))
}

fn to_request_args(request: &Bound<'_, PyDict>) -> PyResult<RequestArgs> {
    let principal = extract_euid_field(request, "principal")?;
    let action = extract_euid_field(request, "action")?;
    let resource = extract_euid_field(request, "resource")?;

    let correlation_id: Option<String> = match request.get_item("correlation_id")? {
        None => None,
        Some(v) => Some(v.extract()?),
    };
    let context_json: Option<String> = match request.get_item("context")? {
        None => None,
        Some(v) => Some(v.extract()?),
    };

    Ok(RequestArgs {
        principal,
        action,
        resource,
        context_json,
        correlation_id,
    })
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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PartialDiagnosticsSer {
    reason: HashSet<PolicyId>,
    id_annotations_by_reason: HashMap<String, String>,
    errors: Vec<String>,
    may_be_determining: Vec<String>,
    must_be_determining: Vec<String>,
    nontrivial_residuals: Vec<String>,
    unknown_entities: Vec<String>,
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
    schema: Option<&Schema>,
    verbose: bool
) -> Result<AuthzResponse, Vec<Error>> {
    let mut errs: Vec<Error> = vec![];
    let t_build_request = Instant::now();

    // may want to create request in calling method; then we could get relocate errs
    let request = match request_args.get_request(schema) {
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

fn make_entities(entities_str: &str, schema: Option<&Schema>, errs: &mut Vec<Error>) -> Entities {
    match load_entities(entities_str, schema) {
        Ok(entities) => entities,
        Err(e) => {
            errs.push(e);
            Entities::empty()
        }
    }
}


/// Load an `Entities` object from the given JSON string and optional schema.
fn load_entities(entities_str: &str, schema: Option<&Schema>) -> Result<Entities> {
    return Entities::from_json_str(entities_str, schema).context(format!(
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
fn validate_policies(policies: String, schema: SchemaArg) -> String {
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

    // Resolve schema (required for validation)
    let cedar_schema: Schema = match schema {
        SchemaArg::Handle(handle) => handle.get().inner.clone(),
        SchemaArg::Source(s) => {
            let trimmed_schema = s.trim();
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
            match parse_schema_src(trimmed_schema) {
                Ok(s) => s,
                Err((_, e)) => {
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
    diagnostics: PartialDiagnosticsSer,
    residuals: HashMap<String, serde_json::Value>,
    metrics: HashMap<String, u128>,
}

#[pyfunction]
#[pyo3(signature = (request, policies, entities, schema = None, verbose = false))]
fn is_authorized_partial(
    request: HashMap<String, Option<String>>,
    policies: PoliciesArg,
    entities: EntitiesArg,
    schema: Option<SchemaArg>,
    verbose: Option<bool>,
) -> String {
    let verbose = verbose.unwrap_or(false);
    let mut errs: Vec<Error> = vec![];

    let policies_pre_parsed = matches!(&policies, PoliciesArg::Handle(_));
    let t_parse_policies = Instant::now();
    let mut policy_set_slot: Option<PolicySet> = None;
    let policy_set = policies.resolve(&mut policy_set_slot, &mut errs, verbose);
    let t_parse_policies_duration = t_parse_policies.elapsed();

    let schema_pre_parsed = matches!(&schema, Some(SchemaArg::Handle(_)));
    let t_start_schema = Instant::now();
    let mut schema_slot: Option<Schema> = None;
    let schema_ref = resolve_schema_arg(&schema, &mut schema_slot, &mut errs, verbose);
    let t_parse_schema_duration = t_start_schema.elapsed();
    let schema = schema_ref;

    let entities_pre_parsed = matches!(&entities, EntitiesArg::Handle(_));
    let t_load_entities = Instant::now();
    let entities = entities.resolve_partial(schema, &mut errs);
    let t_load_entities_duration = t_load_entities.elapsed();

    if !errs.is_empty() {
        return make_authz_result_for_errors(&errs);
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
                return make_authz_result_for_errors(&errs);
            }
        }
    }

    if let Some(a) = action_str {
        match a.parse::<EntityUid>() {
            Ok(uid) => { builder = builder.action(uid); }
            Err(e) => {
                errs.push(Error::msg(format!("Failed to parse action as entity Uid: {}", e)));
                return make_authz_result_for_errors(&errs);
            }
        }
    }

    if let Some(r) = resource_str {
        match r.parse::<EntityUid>() {
            Ok(uid) => { builder = builder.resource(uid); }
            Err(e) => {
                errs.push(Error::msg(format!("Failed to parse resource as entity Uid: {}", e)));
                return make_authz_result_for_errors(&errs);
            }
        }
    }

    if let Some(ctx_json) = context_str {
        let action_uid: Option<EntityUid> = action_str.and_then(|a| a.parse().ok());
        match Context::from_json_str(ctx_json, schema.and_then(|s| action_uid.as_ref().map(|a| (s, a)))) {
            Ok(ctx) => { builder = builder.context(ctx); }
            Err(e) => {
                errs.push(Error::msg(format!("Failed to parse context: {}", e)));
                return make_authz_result_for_errors(&errs);
            }
        }
    }

    let cedar_request = match schema {
        Some(s) => match builder.schema(s).build() {
            Ok(r) => r,
            Err(e) => {
                errs.push(Error::msg(format!("Request validation failed: {}", e)));
                return make_authz_result_for_errors(&errs);
            }
        },
        None => builder.build(),
    };
    let build_request_duration = t_build_request.elapsed();

    let authorizer = Authorizer::new();
    let t_authz = Instant::now();
    let partial_response = authorizer.is_authorized_partial(&cedar_request, policy_set, &entities);
    let authz_duration = t_authz.elapsed();

    let decision = partial_response.decision().map(|d| match d {
        Decision::Allow => DecisionSer::Allow,
        Decision::Deny => DecisionSer::Deny,
    });

    let mut reason: HashSet<PolicyId> = HashSet::new();
    for policy in partial_response.definitely_satisfied() {
        reason.insert(policy.id().clone());
    }
    let errored_ids: Vec<&PolicyId> = partial_response.definitely_errored().collect();
    let errors: Vec<String> = if errored_ids.is_empty() {
        Vec::new()
    } else {
        // definitely_errored() yields ids but not messages; concretize() is the
        // documented way to recover the per-policy error strings. Safe here
        // because these policies error regardless of how unknowns are bound.
        let concretized = partial_response.clone().concretize();
        let error_map: HashMap<&PolicyId, String> = concretized.diagnostics().errors()
            .map(|e| {
                let AuthorizationError::PolicyEvaluationError(pe) = e;
                (pe.policy_id(), e.to_string())
            })
            .collect();
        errored_ids.iter()
            .map(|pid| error_map.get(pid).cloned()
                .unwrap_or_else(|| format!("error while evaluating policy `{pid}`: unknown error")))
            .collect()
    };
    let may_be_determining: Vec<String> = partial_response.may_be_determining()
        .map(|p| p.id().to_string()).collect();
    let must_be_determining: Vec<String> = partial_response.must_be_determining()
        .map(|p| p.id().to_string()).collect();
    let nontrivial_residuals: Vec<String> = partial_response.nontrivial_residuals()
        .map(|p| p.id().to_string()).collect();
    let unknown_entities: Vec<String> = partial_response.unknown_entities()
        .into_iter().map(|e| e.to_string()).collect();

    let mut id_annotations_by_reason: HashMap<String, String> = HashMap::new();
    let mut residuals: HashMap<String, serde_json::Value> = HashMap::new();
    for policy in partial_response.all_residuals() {
        let pid_str = policy.id().to_string();
        if let Some(annotation) = lookup_id_annotation(policy_set, policy.id()) {
            id_annotations_by_reason.insert(pid_str.clone(), annotation);
        }
        residuals.insert(pid_str, policy.to_json().unwrap_or(json!(null)));
    }

    let metrics = HashMap::from([
        (String::from("parse_policies_duration_micros"), t_parse_policies_duration.as_micros()),
        (String::from("policies_pre_parsed"), policies_pre_parsed as u128),
        (String::from("parse_schema_duration_micros"), t_parse_schema_duration.as_micros()),
        (String::from("schema_pre_parsed"), schema_pre_parsed as u128),
        (String::from("load_entities_duration_micros"), t_load_entities_duration.as_micros()),
        (String::from("entities_pre_parsed"), entities_pre_parsed as u128),
        (String::from("build_request_duration_micros"), build_request_duration.as_micros()),
        (String::from("authz_duration_micros"), authz_duration.as_micros()),
    ]);

    let response = PartialAuthzResponse {
        decision,
        correlation_id,
        diagnostics: PartialDiagnosticsSer {
            reason, id_annotations_by_reason, errors,
            may_be_determining, must_be_determining,
            nontrivial_residuals, unknown_entities,
        },
        residuals,
        metrics,
    };

    serde_json::to_string(&response).unwrap()
}

/// A Python module implemented in Rust.
#[pymodule]
fn _internal(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyPolicySet>()?;
    m.add_class::<PyEntities>()?;
    m.add_class::<PySchema>()?;
    m.add_function(wrap_pyfunction!(echo, m)?)?;
    m.add_function(wrap_pyfunction!(is_authorized, m)?)?;
    m.add_function(wrap_pyfunction!(is_authorized_batch, m)?)?;
    m.add_function(wrap_pyfunction!(is_authorized_partial, m)?)?;
    m.add_function(wrap_pyfunction!(format_policies, m)?)?;
    m.add_function(wrap_pyfunction!(policies_to_json_str, m)?)?;
    m.add_function(wrap_pyfunction!(policies_from_json_str, m)?)?;
    m.add_function(wrap_pyfunction!(policies_to_pst, m)?)?;
    m.add_function(wrap_pyfunction!(validate_policies, m)?)?;
    Ok(())
}

// The reverse of the `build_*` functions above: reads cedarpy.pst dataclasses
// back into cedar_policy::pst types. Dispatches on the class name, since
// cedarpy.pst is a closed set of dataclasses.

fn node_kind(obj: &Bound<'_, PyAny>) -> PyResult<String> {
    Ok(obj.get_type().name()?.to_string())
}

fn read_error(context: &str, kind: &str) -> PyErr {
    pyo3::exceptions::PyTypeError::new_err(format!(
        "cedarpy: expected a cedarpy.pst {context}, got {kind}"
    ))
}

fn pst_construction_error(e: impl std::fmt::Display) -> PyErr {
    pyo3::exceptions::PyValueError::new_err(e.to_string())
}

fn read_entity_type(obj: &Bound<'_, PyAny>) -> PyResult<pst::EntityType> {
    let kind = node_kind(obj)?;
    if kind != "EntityType" {
        return Err(read_error("EntityType", &kind));
    }
    let basename: String = obj.getattr("basename")?.extract()?;
    let namespace: Vec<String> = obj.getattr("namespace")?.extract()?;
    let name = if namespace.is_empty() {
        pst::Name::unqualified(&basename)
    } else {
        pst::Name::qualified(namespace.iter().map(String::as_str), &basename)
    }
    .map_err(pst_construction_error)?;
    Ok(pst::EntityType::from_name(name))
}

fn read_entity_uid(obj: &Bound<'_, PyAny>) -> PyResult<pst::EntityUID> {
    let kind = node_kind(obj)?;
    if kind != "EntityUid" {
        return Err(read_error("EntityUid", &kind));
    }
    let id: String = obj.getattr("id")?.extract()?;
    Ok(pst::EntityUID {
        ty: read_entity_type(&obj.getattr("type")?)?,
        eid: id.into(),
    })
}

fn read_slot_id(name: &str) -> PyResult<pst::SlotId> {
    match name {
        "principal" => Ok(pst::SlotId::Principal),
        "resource" => Ok(pst::SlotId::Resource),
        other => Err(pyo3::exceptions::PyValueError::new_err(format!(
            "cedarpy: unknown slot name {other:?}"
        ))),
    }
}

fn read_entity_or_slot(obj: &Bound<'_, PyAny>) -> PyResult<pst::EntityOrSlot> {
    match node_kind(obj)?.as_str() {
        "EntityUid" => Ok(pst::EntityOrSlot::Entity(read_entity_uid(obj)?)),
        "Slot" => Ok(pst::EntityOrSlot::Slot(read_slot_id(
            &obj.getattr("name")?.extract::<String>()?,
        )?)),
        other => Err(read_error("EntityUid or Slot", other)),
    }
}

fn read_var(name: &str) -> PyResult<pst::Var> {
    match name {
        "principal" => Ok(pst::Var::Principal),
        "action" => Ok(pst::Var::Action),
        "resource" => Ok(pst::Var::Resource),
        "context" => Ok(pst::Var::Context),
        other => Err(pyo3::exceptions::PyValueError::new_err(format!(
            "cedarpy: unknown var name {other:?}"
        ))),
    }
}

fn read_unary_op(name: &str) -> PyResult<pst::UnaryOp> {
    use pst::UnaryOp::*;
    match name {
        "not" => Ok(Not), "neg" => Ok(Neg), "is_empty" => Ok(IsEmpty),
        "datetime" => Ok(Datetime), "decimal" => Ok(Decimal), "duration" => Ok(Duration),
        "ip" => Ok(Ip), "is_ipv4" => Ok(IsIPv4), "is_ipv6" => Ok(IsIPV6),
        "is_loopback" => Ok(IsLoopback), "is_multicast" => Ok(IsMulticast),
        "to_date" => Ok(ToDate), "to_time" => Ok(ToTime),
        "to_milliseconds" => Ok(ToMilliseconds), "to_seconds" => Ok(ToSeconds),
        "to_minutes" => Ok(ToMinutes), "to_hours" => Ok(ToHours), "to_days" => Ok(ToDays),
        other => Err(pyo3::exceptions::PyValueError::new_err(format!(
            "cedarpy: unknown unary op {other:?}"
        ))),
    }
}

fn read_binary_op(name: &str) -> PyResult<pst::BinaryOp> {
    use pst::BinaryOp::*;
    match name {
        "eq" => Ok(Eq), "not_eq" => Ok(NotEq), "less" => Ok(Less), "less_eq" => Ok(LessEq),
        "greater" => Ok(Greater), "greater_eq" => Ok(GreaterEq),
        "and" => Ok(And), "or" => Ok(Or),
        "add" => Ok(Add), "sub" => Ok(Sub), "mul" => Ok(Mul),
        "in" => Ok(In), "contains" => Ok(Contains),
        "contains_all" => Ok(ContainsAll), "contains_any" => Ok(ContainsAny),
        "get_tag" => Ok(GetTag), "has_tag" => Ok(HasTag),
        "is_in_range" => Ok(IsInRange), "offset" => Ok(Offset),
        "duration_since" => Ok(DurationSince),
        "decimal_less_than" => Ok(DecimalLessThan), "decimal_less_eq" => Ok(DecimalLessEq),
        "decimal_greater" => Ok(DecimalGreater), "decimal_greater_eq" => Ok(DecimalGreaterEq),
        other => Err(pyo3::exceptions::PyValueError::new_err(format!(
            "cedarpy: unknown binary op {other:?}"
        ))),
    }
}

fn read_pattern(obj: &Bound<'_, PyAny>) -> PyResult<Vec<pst::PatternElem>> {
    let mut elems = Vec::new();
    for elem in obj.try_iter()? {
        let elem = elem?;
        match node_kind(&elem)?.as_str() {
            "Char" => {
                let s: String = elem.getattr("value")?.extract()?;
                let mut chars = s.chars();
                match (chars.next(), chars.next()) {
                    (Some(ch), None) => elems.push(pst::PatternElem::Char(ch)),
                    _ => {
                        return Err(pyo3::exceptions::PyValueError::new_err(format!(
                            "cedarpy: Char.value must be exactly one character, got {s:?}"
                        )))
                    }
                }
            }
            "Wildcard" => elems.push(pst::PatternElem::Wildcard),
            other => return Err(read_error("Char or Wildcard", other)),
        }
    }
    Ok(elems)
}

fn read_expr(obj: &Bound<'_, PyAny>) -> PyResult<pst::Expr> {
    use std::sync::Arc;
    let arc = |o: Bound<'_, PyAny>| -> PyResult<Arc<pst::Expr>> { Ok(Arc::new(read_expr(&o)?)) };
    match node_kind(obj)?.as_str() {
        "BoolLit" => Ok(pst::Expr::Literal(pst::Literal::Bool(
            obj.getattr("value")?.extract()?,
        ))),
        "LongLit" => Ok(pst::Expr::Literal(pst::Literal::Long(
            obj.getattr("value")?.extract()?,
        ))),
        "StringLit" => Ok(pst::Expr::Literal(pst::Literal::String(
            obj.getattr("value")?.extract::<String>()?.into(),
        ))),
        "EntityLit" => Ok(pst::Expr::Literal(pst::Literal::EntityUID(
            read_entity_uid(&obj.getattr("value")?)?,
        ))),
        "Var" => Ok(pst::Expr::Var(read_var(
            &obj.getattr("name")?.extract::<String>()?,
        )?)),
        "Slot" => Ok(pst::Expr::Slot(read_slot_id(
            &obj.getattr("name")?.extract::<String>()?,
        )?)),
        "UnaryOp" => Ok(pst::Expr::UnaryOp {
            op: read_unary_op(&obj.getattr("op")?.extract::<String>()?)?,
            expr: arc(obj.getattr("arg")?)?,
        }),
        "BinaryOp" => Ok(pst::Expr::BinaryOp {
            op: read_binary_op(&obj.getattr("op")?.extract::<String>()?)?,
            left: arc(obj.getattr("left")?)?,
            right: arc(obj.getattr("right")?)?,
        }),
        "GetAttr" => Ok(pst::Expr::GetAttr {
            expr: arc(obj.getattr("base")?)?,
            attr: obj.getattr("attr")?.extract::<String>()?.into(),
        }),
        "HasAttr" => {
            let attrs: Vec<String> = obj.getattr("attrs")?.extract()?;
            let attrs: Vec<pst::SmolStr> = attrs.into_iter().map(Into::into).collect();
            let attrs = pst::NonEmpty::from_vec(attrs).ok_or_else(|| {
                pyo3::exceptions::PyValueError::new_err(
                    "cedarpy: HasAttr.attrs must name at least one attribute",
                )
            })?;
            Ok(pst::Expr::HasAttr {
                expr: arc(obj.getattr("base")?)?,
                attrs,
            })
        }
        "Like" => Ok(pst::Expr::Like {
            expr: arc(obj.getattr("base")?)?,
            pattern: read_pattern(&obj.getattr("pattern")?)?,
        }),
        "Is" => {
            let in_expr = obj.getattr("in_expr")?;
            Ok(pst::Expr::Is {
                expr: arc(obj.getattr("base")?)?,
                entity_type: read_entity_type(&obj.getattr("entity_type")?)?,
                in_expr: if in_expr.is_none() { None } else { Some(arc(in_expr)?) },
            })
        }
        "IfThenElse" => Ok(pst::Expr::IfThenElse {
            cond: arc(obj.getattr("cond")?)?,
            then_expr: arc(obj.getattr("then_expr")?)?,
            else_expr: arc(obj.getattr("else_expr")?)?,
        }),
        "Set" => {
            let mut elements = Vec::new();
            for e in obj.getattr("elements")?.try_iter()? {
                elements.push(Arc::new(read_expr(&e?)?));
            }
            Ok(pst::Expr::Set(elements))
        }
        "Record" => {
            let mut fields = std::collections::BTreeMap::new();
            let items = obj.getattr("fields")?.call_method0("items")?;
            for item in items.try_iter()? {
                let (k, v): (String, Bound<'_, PyAny>) = item?.extract()?;
                fields.insert(k, Arc::new(read_expr(&v)?));
            }
            Ok(pst::Expr::Record(fields))
        }
        other => Err(read_error("expression node", other)),
    }
}

fn read_clause(obj: &Bound<'_, PyAny>) -> PyResult<pst::Clause> {
    use std::sync::Arc;
    let expr = Arc::new(read_expr(&obj.getattr("expr")?)?);
    match node_kind(obj)?.as_str() {
        "When" => Ok(pst::Clause::When(expr)),
        "Unless" => Ok(pst::Clause::Unless(expr)),
        other => Err(read_error("When or Unless", other)),
    }
}

fn read_principal_constraint(obj: &Bound<'_, PyAny>) -> PyResult<pst::PrincipalConstraint> {
    match node_kind(obj)?.as_str() {
        "ScopeAny" => Ok(pst::PrincipalConstraint::Any),
        "ScopeEq" => Ok(pst::PrincipalConstraint::Eq(read_entity_or_slot(
            &obj.getattr("entity")?,
        )?)),
        "ScopeIn" => Ok(pst::PrincipalConstraint::In(read_entity_or_slot(
            &obj.getattr("entity")?,
        )?)),
        "ScopeIs" => Ok(pst::PrincipalConstraint::Is(read_entity_type(
            &obj.getattr("entity_type")?,
        )?)),
        "ScopeIsIn" => Ok(pst::PrincipalConstraint::IsIn(
            read_entity_type(&obj.getattr("entity_type")?)?,
            read_entity_or_slot(&obj.getattr("entity")?)?,
        )),
        other => Err(read_error("scope constraint", other)),
    }
}

fn read_resource_constraint(obj: &Bound<'_, PyAny>) -> PyResult<pst::ResourceConstraint> {
    match node_kind(obj)?.as_str() {
        "ScopeAny" => Ok(pst::ResourceConstraint::Any),
        "ScopeEq" => Ok(pst::ResourceConstraint::Eq(read_entity_or_slot(
            &obj.getattr("entity")?,
        )?)),
        "ScopeIn" => Ok(pst::ResourceConstraint::In(read_entity_or_slot(
            &obj.getattr("entity")?,
        )?)),
        "ScopeIs" => Ok(pst::ResourceConstraint::Is(read_entity_type(
            &obj.getattr("entity_type")?,
        )?)),
        "ScopeIsIn" => Ok(pst::ResourceConstraint::IsIn(
            read_entity_type(&obj.getattr("entity_type")?)?,
            read_entity_or_slot(&obj.getattr("entity")?)?,
        )),
        other => Err(read_error("scope constraint", other)),
    }
}

fn read_action_constraint(obj: &Bound<'_, PyAny>) -> PyResult<pst::ActionConstraint> {
    match node_kind(obj)?.as_str() {
        "ScopeAny" => Ok(pst::ActionConstraint::Any),
        "ActionEq" => Ok(pst::ActionConstraint::Eq(read_entity_uid(
            &obj.getattr("entity")?,
        )?)),
        "ActionIn" => {
            let mut euids = Vec::new();
            for e in obj.getattr("entities")?.try_iter()? {
                euids.push(read_entity_uid(&e?)?);
            }
            Ok(pst::ActionConstraint::In(euids))
        }
        other => Err(read_error("action constraint", other)),
    }
}

fn read_template(obj: &Bound<'_, PyAny>) -> PyResult<pst::Template> {
    let kind = node_kind(obj)?;
    if kind != "Template" {
        return Err(read_error("Template", &kind));
    }
    let effect = match obj.getattr("effect")?.extract::<String>()?.as_str() {
        "permit" => pst::Effect::Permit,
        "forbid" => pst::Effect::Forbid,
        other => {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "cedarpy: unknown effect {other:?}"
            )))
        }
    };
    let template = pst::Template::new(
        obj.getattr("id")?.extract::<String>()?.as_str(),
        effect,
        read_principal_constraint(&obj.getattr("principal")?)?,
        read_action_constraint(&obj.getattr("action")?)?,
        read_resource_constraint(&obj.getattr("resource")?)?,
    );
    let mut clauses = Vec::new();
    for clause in obj.getattr("clauses")?.try_iter()? {
        clauses.push(read_clause(&clause?)?);
    }
    let template = template.try_with_clauses(clauses).map_err(pst_construction_error)?;
    let mut annotations = std::collections::BTreeMap::new();
    let items = obj.getattr("annotations")?.call_method0("items")?;
    for item in items.try_iter()? {
        let (k, v): (String, String) = item?.extract()?;
        annotations.insert(k, pst::SmolStr::from(v));
    }
    Ok(template.with_annotations(annotations))
}

fn read_policy_set(obj: &Bound<'_, PyAny>) -> PyResult<pst::PolicySet> {
    let kind = node_kind(obj)?;
    if kind != "PolicySet" {
        return Err(read_error("PolicySet", &kind));
    }
    let mut templates = pst::LinkedHashMap::new();
    for item in obj.getattr("templates")?.call_method0("items")?.try_iter()? {
        let (id, node): (String, Bound<'_, PyAny>) = item?.extract()?;
        templates.insert(pst::PolicyID::from(id.as_str()), read_template(&node)?);
    }
    let mut policies = pst::LinkedHashMap::new();
    for item in obj.getattr("static_policies")?.call_method0("items")?.try_iter()? {
        let (id, node): (String, Bound<'_, PyAny>) = item?.extract()?;
        let template = read_template(&node)?;
        let static_policy =
            pst::StaticPolicy::try_from(template).map_err(pst_construction_error)?;
        policies.insert(pst::PolicyID::from(id.as_str()), static_policy);
    }
    let mut template_links = Vec::new();
    for link in obj.getattr("template_links")?.try_iter()? {
        let link = link?;
        let kind = node_kind(&link)?;
        if kind != "TemplateLink" {
            return Err(read_error("TemplateLink", &kind));
        }
        let mut values = std::collections::HashMap::new();
        for item in link.getattr("values")?.call_method0("items")?.try_iter()? {
            let (slot, euid): (String, Bound<'_, PyAny>) = item?.extract()?;
            values.insert(read_slot_id(&slot)?, read_entity_uid(&euid)?);
        }
        template_links.push(pst::TemplateLink {
            template_id: pst::PolicyID::from(
                link.getattr("template_id")?.extract::<String>()?.as_str(),
            ),
            new_id: pst::PolicyID::from(link.getattr("new_id")?.extract::<String>()?.as_str()),
            values,
        });
    }
    Ok(pst::PolicySet {
        templates,
        policies,
        template_links,
    })
}
