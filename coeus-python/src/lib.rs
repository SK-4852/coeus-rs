// Copyright (c) 2022 Ubique Innovation AG <https://www.ubique.ch>
// 
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.


use pyo3::prelude::*;

pub mod analysis;
pub mod parse; 
pub mod vm;
pub mod debugging;

/// Coeur wrapper for python
#[pymodule]
fn coeus_python(py: Python, m: &PyModule) -> PyResult<()> {
    analysis::register(py, m)?;
    parse::register(py, m)?;
    vm::register(py, m)?;
    debugging::register(py, m)?;
    m.add_function(wrap_pyfunction!(init_logging,m)?)?;
    Ok(())
}

#[pyfunction]
fn init_logging() {
    env_logger::init()
}