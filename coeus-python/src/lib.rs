
use pyo3::prelude::*;

pub mod analysis;
pub mod parse; 
pub mod vm;

/// Coeur wrapper for python
#[pymodule]
fn coeus_python(py: Python, m: &PyModule) -> PyResult<()> {
    analysis::register(py, m)?;
    parse::register(py, m)?;
    vm::register(py, m)?;
    Ok(())
}