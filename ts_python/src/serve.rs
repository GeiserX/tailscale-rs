//! Python marshaling for the TLS/Serve lane (`get_certificate`, `listen_tls`).
//!
//! Builds a native [`tailscale::ServeConfig`] from a Python mapping and propagates the
//! fail-closed [`tailscale::CertError`] faithfully. TLS issuance is **unimplemented** in this fork
//! (no client-side ACME engine / no `set-dns` RPC), so `get_certificate` and `listen_tls` ALWAYS
//! raise a Python exception carrying the `CertError` display — they never self-sign and never
//! downgrade to plaintext. When ACME lands upstream, these start succeeding with no API change.

use pyo3::{Borrowed, FromPyObject, PyAny, PyErr, PyResult, types::PyAnyMethods};

use crate::py_value_err;

/// A Python-supplied serve config: `{"name": str, "port": int, "target": <target>}`.
///
/// `target` is either the string `"accept"` or a mapping `{"proxy": "host:port"}`.
pub struct ServeConfigArg(pub tailscale::ServeConfig);

impl<'py> FromPyObject<'_, 'py> for ServeConfigArg {
    type Error = PyErr;

    fn extract(ob: Borrowed<'_, 'py, PyAny>) -> PyResult<Self> {
        let name: String = ob.get_item("name")?.extract()?;
        let port: u16 = ob.get_item("port")?.extract()?;
        let target_item = ob.get_item("target")?;
        let target = extract_target(target_item.as_borrowed())?;

        Ok(ServeConfigArg(tailscale::ServeConfig {
            name,
            port,
            target,
        }))
    }
}

/// Extract a [`tailscale::ServeTarget`] from `"accept"` or `{"proxy": "host:port"}`.
fn extract_target(ob: Borrowed<'_, '_, PyAny>) -> PyResult<tailscale::ServeTarget> {
    if let Ok(s) = ob.extract::<String>() {
        return match s.as_str() {
            "accept" => Ok(tailscale::ServeTarget::Accept),
            other => Err(py_value_err(format!(
                "unknown serve target {other:?}; expected \"accept\" or {{\"proxy\": \"host:port\"}}"
            ))),
        };
    }

    // Mapping form: {"proxy": "host:port"}.
    if let Ok(to_item) = ob.get_item("proxy") {
        let to: String = to_item.extract()?;
        return Ok(tailscale::ServeTarget::Proxy { to });
    }

    Err(py_value_err(
        "serve target must be \"accept\" or {\"proxy\": \"host:port\"}",
    ))
}
