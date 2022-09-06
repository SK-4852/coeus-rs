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

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Files {
    pub multi_dex: Vec<MultiDexFile>,
    pub binaries: HashMap<String, Arc<BinaryObject>>,
    pub binary_resource_file: Vec<u8>,
}

impl Files {
    pub fn new(multi_dex: Vec<MultiDexFile>, binaries: HashMap<String, Arc<BinaryObject>>) -> Self {
        Self {
            multi_dex,
            binaries,
            binary_resource_file: vec![],
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
        let mut visitor = ModelVisitor::default();
        Executor::arsc(&self.binary_resource_file, &mut visitor).ok()?;
        let mut visitor = XmlVisitor::new(visitor.get_resources());
        let _ = Executor::xml(Cursor::new(&binary_xml), &mut visitor);
        visitor.into_string().ok()
    }
}
