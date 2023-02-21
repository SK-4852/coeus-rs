// Copyright (c) 2023 Ubique Innovation AG <https://www.ubique.ch>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use super::{runtime::invoke_runtime_with_method, Register, VMException, VM};
use coeus_models::models::{DexFile, Method};
use lazy_static::lazy_static;

pub trait Invokable: Send + Sync {
    fn call(&self, fn_name: &str, vm: &mut VM, args: &[Register]) -> Result<(), VMException>;
}
pub struct DynamicClass {
    pub methods: HashMap<String, fn(&mut VM, &[Register]) -> Result<Option<Register>, VMException>>,
}

impl DynamicClass {
    fn invoke_method(
        &self,
        fn_name: &str,
        vm: &mut VM,
        args: &[Register],
    ) -> Result<(), VMException> {
        let Some(m) = self.methods.get(fn_name) else {
            return Err(VMException::MethodNotFound(fn_name.to_string()));
        };
        let Some(result) = m(vm, args)? else {
            return Ok(());
        };
        vm.current_state.return_reg = result;
        Ok(())
    }
}

impl Invokable for DynamicClass {
    fn call(&self, fn_name: &str, vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
        self.invoke_method(fn_name, vm, args)
    }
}

lazy_static! {
    pub static ref VM_DYNAMIC_BUILTINS: Arc<Mutex<HashMap<String, Box<dyn Invokable>>>> =
        Arc::new(Mutex::new(HashMap::new()));
}

impl VM {
    pub fn register_class(class_name: &str, the_class: Box<dyn Invokable>) -> Result<(), String> {
        let Ok(mut class_lock) = VM_DYNAMIC_BUILTINS.lock() else {
            return Err("Could not get lock".to_string());
        };
        class_lock.insert(class_name.to_string(), the_class);
        Ok(())
    }
    pub fn invoke_dynamic_runtime(
        &mut self,
        dex_file: Arc<DexFile>,
        method_idx: u32,
        arguments: &[Register],
    ) -> Result<(), VMException> {
        let method = dex_file
            .methods
            .get(method_idx as usize)
            .ok_or_else(|| VMException::MethodNotFound(method_idx.to_string()))?;
        let type_str = *dex_file
            .types
            .get(method.class_idx as usize)
            .ok_or_else(|| VMException::StaticDataNotFound(method.class_idx as u32))?;
        let class_name = dex_file
            .get_string(type_str as usize)
            .ok_or_else(|| VMException::StaticDataNotFound(type_str))?;
        self.invoke_dynamic_runtime_with_method(class_name, method.clone(), arguments)
    }
    pub fn invoke_dynamic_runtime_with_method(
        &mut self,
        class_name: &str,
        method: Arc<Method>,
        arguments: &[Register],
    ) -> Result<(), VMException> {
        let fn_name = method.method_name.as_str();
        log::debug!("Invoke: {} {}", class_name, fn_name);
        let Ok(class_lock) = VM_DYNAMIC_BUILTINS.lock() else {
            return Err(VMException::LinkerError);
        };
        let Some(c) = class_lock.get(class_name) else {
            return Err(VMException::ClassNotFound(0));
        };
        c.call(fn_name, self, &arguments)
    }
}
