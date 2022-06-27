// Copyright (c) 2022 Ubique Innovation AG <https://www.ubique.ch>
// 
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use coeus_macros::iterator;
use rayon::prelude::*;

use super::{AndroidManifest, Class, DexFile, Field, Method, Proto, StringEntry};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MultiDexFile {
    #[serde(skip_serializing, skip_deserializing)]
    loaded_classes: DexLock<HashMap<String, String>>,
    // class_array: DexLock<Vec<(&'a DexFile, &'a Class)>>,
    pub manifest_content: String,
    pub android_manifest: AndroidManifest,
    pub primary: Arc<DexFile>,
    pub secondary: Vec<Arc<DexFile>>,
}

impl<'a> MultiDexFile {
    pub fn new(
        android_manifest: AndroidManifest,
        manifest_content: String,
        primary: DexFile,
        secondary: Vec<DexFile>,
    ) -> Self {
        Self {
            loaded_classes: DexLock(RwLock::new(HashMap::new())),
            android_manifest,
            manifest_content,
            primary: Arc::new(primary),
            secondary: secondary.into_iter().map(Arc::new).collect(),
        }
    }

    pub fn dex_file_from_identifier(&self, identifier: &str) -> Option<Arc<DexFile>> {
        if self.primary.identifier == identifier {
            Some(self.primary.clone())
        } else {
            iterator!(self.secondary)
                .find_any(|d| d.identifier == identifier)
                .cloned()
        }
    }

    pub fn strings(&self) -> Vec<(Arc<DexFile>, &StringEntry, usize)> {
        let entries = iterator!(self.primary.strings).enumerate()
            .map(|(index,s)| (self.primary.clone(), s, index))
            .chain(
                iterator!(self.secondary)
                    .flat_map(|d| iterator!(d.strings).enumerate().map(move |(index, s)| (d.clone(), s, index))),
            );

        entries.collect()
    }

    pub fn methods(&self) -> Vec<(Arc<DexFile>, Arc<Method>)> {
        let entries = iterator!(self.primary.methods)
            .map(|s| (self.primary.clone(), s.clone()))
            .chain(
                iterator!(self.secondary)
                    .flat_map(|d| iterator!(d.methods).map(move |s| (d.clone(), s.clone()))),
            );

        entries.collect()
    }

    pub fn types(&self) -> Vec<(Arc<DexFile>, u32)> {
        let entries = iterator!(self.primary.types)
            .map(|s| (self.primary.clone(), *s))
            .chain(
                iterator!(self.secondary)
                    .flat_map(|d| iterator!(d.types).map(move |s| (d.clone(), *s))),
            );

        entries.collect()
    }
    pub fn types_enumerated(&self) -> Vec<(usize, Arc<DexFile>, &u32)> {
        let entries = iterator!(self.primary.types)
            .enumerate()
            .map(|(i, s)| (i, self.primary.clone(), s))
            .chain(iterator!(self.secondary).flat_map(|d| {
                iterator!(d.types)
                    .enumerate()
                    .map(move |(i, s)| (i, d.clone(), s))
            }));

        entries.collect()
    }

    pub fn protos(&'a self) -> Vec<(Arc<DexFile>, Arc<Proto>)> {
        let entries = iterator!(self.primary.protos)
            .map(|s| (self.primary.clone(), s.clone()))
            .chain(
                iterator!(self.secondary)
                    .flat_map(|d| iterator!(d.protos).map(move |s| (d.clone(), s.clone()))),
            );

        entries.collect()
    }

    pub fn fields(&self) -> Vec<(Arc<DexFile>, Arc<Field>)> {
        let entries = iterator!(self.primary.fields)
            .map(|s| (self.primary.clone(), s.clone()))
            .chain(
                iterator!(self.secondary)
                    .flat_map(|d| iterator!(d.fields).map(move |s| (d.clone(), s.clone()))),
            );

        entries.collect()
    }

    pub fn get_type_idx_for_string(&self, type_name: &str) -> Option<(Arc<DexFile>, u16)> {
        let the_iter = iterator!(self.primary.types)
            .enumerate()
            .map(|(i, s)| (i, self.primary.clone(), s))
            .chain(iterator!(self.secondary).flat_map(|d| {
                iterator!(d.types)
                    .enumerate()
                    .map(move |(i, s)| (i, d.clone(), s))
            }))
            .filter_map(
                |(idx, file, name_idx)| match file.get_string(*name_idx as usize) {
                    Some(tn) if tn == type_name => Some((file, idx as u16)),
                    _ => None,
                },
            );
        #[cfg(not(target_arch = "wasm32"))]
        {
            the_iter.find_any(|_| true)
        }
        #[cfg(target_arch = "wasm32")]
        {
            let mut the_iter = the_iter;
            the_iter.next()
        }
    }

    pub fn classes(&self) -> Vec<(Arc<DexFile>, Arc<Class>)> {
        iterator!(self.primary.classes)
            .map(|s| (self.primary.clone(), s.clone()))
            .chain(
                iterator!(self.secondary)
                    .flat_map(|d| iterator!(d.classes).map(move |s| (d.clone(), s.clone()))),
            )
            .collect()
    }

    pub fn load_classes(&'a self) {
        // let entries: Vec<(&'a DexFile, &'a Class)> = {
        //     iterator!(self.primary.classes)
        //         .map(|s| (&self.primary, s))
        //         .chain(
        //             iterator!(self.secondary)
        //                 .flat_map(|d| iterator!(d.classes).map(move |s| (d, s))),
        //         )
        //         .collect()
        // };

        // if let Ok(mut cache) = self.class_array.0.write() {
        //     cache.extend(entries);
        // }
    }

    pub fn get_class_for_method(
        &'a mut self,
        method: &Method,
        dex: Arc<DexFile>,
    ) -> Option<(Arc<Class>, Arc<DexFile>)> {
        let class_idx = method.class_idx;
        if let Some(class) = dex.get_class_by_type(class_idx) {
            if class.class_data.is_some() {
                return Some((class, dex));
            }
            return self.load_class(&class.class_name);
        }

        None
    }

    pub fn load_class(&'a self, class_name: &str) -> Option<(Arc<Class>, Arc<DexFile>)> {
        //check if we loaded the class before

        if let Some(class) = self.loaded_classes.0.read().unwrap().get(class_name) {
            if &self.primary.identifier == class {
                return self
                    .primary
                    .get_class_by_name(class_name)
                    .map(|c| (c, self.primary.clone()));
            } else {
                #[cfg(not(target_arch = "wasm32"))]
                if let Some(df) = self
                    .secondary
                    .par_iter()
                    .find_first(|a| &a.identifier == class)
                {
                    return df
                        .get_class_by_name(class_name)
                        .map(|c| (c, self.primary.clone()));
                }
                #[cfg(target_arch = "wasm32")]
                if let Some(df) = self.secondary.iter().find(|a| &a.identifier == class) {
                    return df
                        .get_class_by_name(class_name)
                        .map(|c| (c, self.primary.clone()));
                }
            }
        }

        let classes = self.classes();
        #[cfg(not(target_arch = "wasm32"))]
        let class = classes
            .par_iter()
            .find_first(|(_, class)| class.class_name == class_name && class.class_data.is_some());

        #[cfg(target_arch = "wasm32")]
        let class = classes
            .iter()
            .find(|(f, class)| class.class_name == class_name && class.class_data.is_some());
        if let Some(f) = class {
            self.loaded_classes
                .0
                .write()
                .unwrap()
                .insert(f.0.identifier.clone(), class_name.to_string());
            Some((f.1.clone(), f.0.clone()))
        } else {
            None
        }
    }
}

#[derive(Debug)]
struct DexLock<T>(RwLock<T>);

impl<T> Clone for DexLock<T>
where
    T: Clone,
{
    fn clone(&self) -> Self {
        DexLock(RwLock::new(self.0.read().unwrap().clone()))
    }
}

impl<U, V> Default for DexLock<HashMap<U, V>> {
    fn default() -> Self {
        DexLock(RwLock::new(HashMap::new()))
    }
}
