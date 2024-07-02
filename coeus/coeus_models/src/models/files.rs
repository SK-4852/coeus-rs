// Copyright (c) 2022 Ubique Innovation AG <https://www.ubique.ch>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use super::{BinaryObject, DexFile, MultiDexFile};
use abxml::visitor::{Executor, ModelVisitor, XmlVisitor};
use coeus_macros::iterator;
use rayon::prelude::*;
use std::{collections::HashMap, io::Cursor, sync::Arc};

#[derive(serde::Serialize, serde::Deserialize)]
pub struct Files {
    pub multi_dex: Vec<MultiDexFile>,
    pub binaries: HashMap<String, Arc<BinaryObject>>,
    pub binary_resource_file: Vec<u8>,
    #[serde(skip_deserializing, skip_serializing)]
    pub arsc: Option<arsc::Arsc>,
}

impl Clone for Files {
    fn clone(&self) -> Self {
        Self {
            multi_dex: self.multi_dex.clone(),
            binaries: self.binaries.clone(),
            binary_resource_file: self.binary_resource_file.clone(),
            arsc: None,
        }
    }
}

impl Files {
    pub fn new(multi_dex: Vec<MultiDexFile>, binaries: HashMap<String, Arc<BinaryObject>>) -> Self {
        Self {
            multi_dex,
            binaries,
            binary_resource_file: vec![],
            arsc: None,
        }
    }

    pub fn dex_file_from_identifier(&self, identifier: &str) -> Option<Arc<DexFile>> {
        iterator!(self.multi_dex)
            .filter_map(|md| md.dex_file_from_identifier(identifier))
            .collect::<Vec<_>>()
            .first()
            .cloned()
    }

    pub fn get_multi_dex_from_dex_identifier(
        &self,
        identifier: &str,
    ) -> Option<(&MultiDexFile, Arc<DexFile>)> {
        iterator!(self.multi_dex)
            .filter_map(|md| {
                if let Some(df) = md.dex_file_from_identifier(identifier) {
                    Some((md, df))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
            .first()
            .cloned()
    }
    pub fn decode_resource(&self, binary_xml: &[u8]) -> Option<String> {
        let android_resources_content = abxml::STR_ARSC.to_owned();

        let mut visitor = ModelVisitor::default();
        Executor::arsc(&self.binary_resource_file, &mut visitor).ok()?;
        Executor::arsc(&android_resources_content, &mut visitor).ok()?;
        let mut visitor = XmlVisitor::new(visitor.get_resources());
        let _ = Executor::xml(Cursor::new(&binary_xml), &mut visitor);
        visitor.into_string().ok()
    }
    pub fn load_arsc(&mut self) -> Result<(), String> {
        let Ok(arsc) = arsc::parse_from(Cursor::new(&self.binary_resource_file)) else {
            return Err("Could not load arsc".to_string());
        };
        self.arsc = Some(arsc);
        Ok(())
    }
    pub fn get_string_from_resource(&self, id: u32) -> Option<(String, HashMap<String, String>)> {
        let Some(arsc) = self.arsc.as_ref() else {
            return None;
        };
        let Some(pkg) = arsc.packages.iter().find(|p| p.id == ((id & 0xff_00_00_00) >> 24)) else {
            return None
        };
        let Some(ty) = pkg.types.iter().find(|ty| ty.id == ((id & 0x00_ff_00_00) >> 16) as usize) else {
            return None;
        };
        if pkg.type_names.strings[ty.id - 1] != "string" {
            return None;
        }
        let mut localized_strings = HashMap::new();
        let mut entry_name = String::default();

        for resource in &ty.configs {
            if let Some(entry) = resource
                .resources
                .resources
                .iter()
                .find(|r| r.spec_id == (id as usize) & 0xff_ff)
            {
                let locale = if &resource.id[8..10] == [0, 0] {
                    "default".to_string()
                } else if let Ok(locale) = std::str::from_utf8(&resource.id[8..10]) {
                    locale.to_string()
                } else {
                    continue;
                };
                if let Some(name) = pkg.key_names.strings.get(entry.name_index) {
                    entry_name = name.to_string();
                }

                match &entry.value {
                    arsc::ResourceValue::Plain(a) => {
                        if a.is_string() {
                            if let Some(val) = arsc.global_string_pool.strings.get(a.data_index) {
                                localized_strings.insert(locale.to_string(), val.to_string());
                            }
                        }
                    }
                    _ => continue,
                }
            }
        }
        Some((entry_name, localized_strings))
    }
}
