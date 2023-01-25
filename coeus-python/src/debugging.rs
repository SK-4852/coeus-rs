use std::convert::{TryFrom, TryInto};

// Copyright (c) 2023 Ubique Innovation AG <https://www.ubique.ch>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
use coeus::coeus_debug::{
    jdwp::JdwpClient,
    models::{Composite, Event, JdwpCommandPacket, JdwpPacket, Location, SlotValue, StackFrame},
    Runtime,
};
use pyo3::{
    exceptions::PyRuntimeError, pyclass, pymethods, types::PyModule, Py, PyAny, PyResult, Python,
    ToPyObject,
};
use serde_json::de;

use crate::analysis::Method;

#[pyclass]
/// A debugger struct, holding the jdwp_client for communication with the Debugger
/// and the runtime
pub struct Debugger {
    pub(crate) jdwp_client: JdwpClient,
    pub(crate) rt: Runtime,
}

#[pyclass]
pub struct DebuggerStackFrame {
    stack_frame: StackFrame,
}
#[pyclass]
pub struct StackValue {
    slot: SlotValue,
}
#[pymethods]
impl StackValue {
    pub fn get_value(&self, debugger: &mut Debugger, py: Python) -> PyResult<Py<PyAny>> {
        match self.slot.value {
            coeus::coeus_debug::models::Value::Object(o) => {
                let s = match debugger.jdwp_client.get_object_signature(&debugger.rt, o) {
                    Ok(s) => s,
                    Err(e) => {
                        return Err(PyRuntimeError::new_err(format!(
                            "Could not get object_reference: {}",
                            e
                        )))
                    }
                };
                Ok(s.to_object(py))
            }
            coeus::coeus_debug::models::Value::Byte(b) => Ok(b.to_object(py)),
            coeus::coeus_debug::models::Value::Short(s) => Ok(s.to_object(py)),
            coeus::coeus_debug::models::Value::Int(i) => Ok(i.to_object(py)),
            coeus::coeus_debug::models::Value::Long(l) => Ok(l.to_object(py)),
            coeus::coeus_debug::models::Value::String(s) => {
                let Ok(s) = debugger.jdwp_client.get_string(&debugger.rt, s) else {
                    return Err(PyRuntimeError::new_err("Could not get string"));
                };
                Ok(s.to_object(py))
            }
            coeus::coeus_debug::models::Value::Array(a) => Ok(a.to_object(py)),
            coeus::coeus_debug::models::Value::Float(f) => Ok(f.to_object(py)),
            coeus::coeus_debug::models::Value::Double(d) => Ok(d.to_object(py)),
            coeus::coeus_debug::models::Value::Boolean(b) => Ok((b == 1).to_object(py)),
            coeus::coeus_debug::models::Value::Char(c) => Ok(c.to_object(py)),
            coeus::coeus_debug::models::Value::Void => todo!(),
        }
    }
}

#[pymethods]
impl DebuggerStackFrame {
    pub fn get_values_for(&self, debugger: &mut Debugger, m: &Method) -> PyResult<Vec<StackValue>> {
        let Some(code_item) = m.method_data.as_ref().and_then(|md|md.code.as_ref()) else {
            return Err(PyRuntimeError::new_err("We need code data"));
        };
        let Ok(values) = self.stack_frame.get_values(code_item, &mut debugger.jdwp_client, &debugger.rt) else {
            return Err(PyRuntimeError::new_err("Failed to get values"));
        };
        Ok(values.into_iter().map(|slot| StackValue { slot }).collect())
    }
}

#[pymethods]
impl Debugger {
    #[new]
    pub fn new(host: &str, port: u16) -> PyResult<Debugger> {
        match coeus::coeus_debug::create_debugger(host, port) {
            Ok((jdwp_client, rt)) => Ok(Debugger { jdwp_client, rt }),
            Err(e) => Err(PyRuntimeError::new_err(format!("{}", e))),
        }
    }

    pub fn set_breakpoint(&mut self, method: &Method, code_index: u64) -> PyResult<()> {
        let class = method.get_class();
        let class_name = class.name();
        let class = match self.jdwp_client.get_class(&self.rt, class_name) {
            Ok(c) => c,
            Err(e) => {
                return Err(PyRuntimeError::new_err(format!(
                    "Class command failed: {}",
                    e
                )))
            }
        };
        let first = &class[0];
        let name_and_sig = method.signature().replace(&format!("{}->", class_name), "");
        let cmd = match first.set_breakpoint(&name_and_sig, code_index) {
            Ok(cmd) => cmd,
            Err(e) => {
                return Err(PyRuntimeError::new_err(format!(
                    "Could not get breakpoint command {}",
                    e
                )))
            }
        };
        if self.jdwp_client.set_breakpoint(&self.rt, cmd).is_err() {
            return Err(PyRuntimeError::new_err("Could not set breakpoint"));
        }
        Ok(())
    }
    pub fn resume(&mut self) -> PyResult<()> {
        self.jdwp_client
            .resume(&self.rt, 1)
            .map_err(|e| PyRuntimeError::new_err(format!("{}", e)))
    }
    pub fn wait_for_package(&mut self) -> PyResult<DebuggerStackFrame> {
        let Some(reply) = self.jdwp_client.wait_for_package_blocking(&self.rt) else {
            return Err(PyRuntimeError::new_err("Nothing"));
        };
        let JdwpPacket::CommandPacket(cmd) = reply else  {
           return Err(PyRuntimeError::new_err("Nothing"));
        };
        let Ok(composite) = Composite::try_from(cmd) else {
             return Err(PyRuntimeError::new_err("Not composite event")); 
        };
        let Event::Breakpoint(bp) = &composite.events[0];
        let thread = bp.get_thread();
        let Ok(stack_frame) = thread.get_top_frame(&mut self.jdwp_client, &self.rt) else {
            return Err(PyRuntimeError::new_err("Could not get Stackframe"));
        };
        // let values = sf.get_values(a, &mut self.jdwp_client, &self.rt);

        Ok(DebuggerStackFrame { stack_frame })
    }
}
pub(crate) fn register(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<Debugger>()?;
    m.add_class::<DebuggerStackFrame>()?;
    m.add_class::<StackValue>()?;
    Ok(())
}
