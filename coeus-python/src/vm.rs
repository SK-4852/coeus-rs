// Copyright (c) 2022 Patrick Amrein <amrein@ubique.ch>
//
// This software is released under the MIT License.
// https://opensource.org/licenses/MIT

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use coeus::coeus_emulation::vm::{ClassInstance, Register, Value, VM};
use pyo3::{exceptions::PyRuntimeError, prelude::*};

use crate::parse::AnalyzeObject;

#[pyclass]
#[derive(Clone)]
pub struct DexVm {
    pub(crate) vm: Arc<Mutex<VM>>,
}

#[pyclass]
#[derive(Clone)]
pub struct VmResult {
    pub(crate) data: Value,
    pub(crate) vm: DexVm,
}

#[pymethods]
impl VmResult {
    pub fn get_value(&self, py: Python) -> Py<PyAny> {
        match &self.data {
            coeus::coeus_emulation::vm::Value::Array(l) => l.to_object(py),
            coeus::coeus_emulation::vm::Value::Object(l) => DexClassObject {
                class: l.clone(),
                vm: self.vm.to_owned(),
            }
            .into_py(py),
            coeus::coeus_emulation::vm::Value::Int(i) => i.to_object(py),
            coeus::coeus_emulation::vm::Value::Short(s) => s.to_object(py),
            coeus::coeus_emulation::vm::Value::Byte(b) => b.to_object(py),
        }
    }
}

#[pyclass]
#[derive(Clone)]
pub struct DexClassObject {
    pub(crate) class: ClassInstance,
    pub(crate) vm: DexVm,
}

#[pymethods]
impl DexClassObject {
    pub fn get_instances(&self) -> PyResult<Vec<String>> {
        let vm = if let Ok(vm) = self.vm.vm.lock() {
            vm
        } else {
            return Err(PyRuntimeError::new_err("Could not acquire lock"));
        };
        let mut instances = vec![];
        for (field, ptr) in &self.class.instances {
            let instance = vm.get_instance(Register::Reference("".to_string(), *ptr));
            instances.push(format!("{} = {:?}", field, instance));
        }
        Ok(instances)
    }
    pub fn __str__(&self) -> PyResult<String> {
        Ok(format!("Instance of {}", self.class.class.class_name))
    }
    pub fn __getitem__(&self, name: &str) -> PyResult<String> {
        if let Some(field_value) = self
            .class
            .instances
            .iter()
            .find(|(field_name, _)| field_name.ends_with(name))
            .map(|(_, a)| a)
        {
            let vm = if let Ok(vm) = self.vm.vm.lock() {
                vm
            } else {
                return Err(PyRuntimeError::new_err("Could not acquire lock"));
            };
            let instance = vm.get_instance(Register::Reference("".to_string(), *field_value));

            if let Value::Object(cl) = &instance {
                return Ok(format!("{}", cl));
            } else {
                return Ok(format!("{:?}", instance));
            }
        } else {
            Err(PyRuntimeError::new_err(format!(
                "{} not found on {}",
                name, self.class.class.class_name
            )))
        }
    }
}

#[pymethods]
impl DexVm {
    #[new]
    pub fn new(ao: &AnalyzeObject) -> Self {
        let vm = VM::new(
            ao.files.multi_dex[0].primary.clone(),
            ao.files.multi_dex[0].secondary.clone(),
            Arc::new(HashMap::new()),
        );
        Self {
            vm: Arc::new(Mutex::new(vm)),
        }
    }

    pub fn get_current_state(&self) -> String {
        format!("{:?}", self.vm.lock().unwrap().get_current_state())
    }
    pub fn get_heap(&self) -> String {
        format!("Heap: {:?}", self.vm.lock().unwrap().get_heap())
    }
    pub fn get_instances(&self) -> String {
        format!("Heap: {:?}", self.vm.lock().unwrap().get_instances())
    }
    pub fn get_static_field(&self, fqdn: &str) -> PyResult<VmResult> {
        let vm = if let Ok(vm) = self.vm.lock() {
            vm
        } else {
            return Err(PyRuntimeError::new_err("Could not acquire lock"));
        };
        let instances = vm.get_instances();
        let heap = vm.get_heap();
        if let Some((_, address)) = instances.get(fqdn) {
            if let Some(obj) = heap.get(address) {
                return Ok(VmResult {
                    data: obj.to_owned(),
                    vm: self.clone(),
                });
            }
        }
        Err(PyRuntimeError::new_err("Could not get static field"))
    }
}

pub(crate) fn register(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<DexVm>()?;
    Ok(())
}
