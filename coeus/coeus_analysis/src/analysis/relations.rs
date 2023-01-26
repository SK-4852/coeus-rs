// Copyright (c) 2023 Ubique Innovation AG <https://www.ubique.ch>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::sync::{Arc, Mutex};

use coeus_macros::iterator;
use coeus_models::models::{Class, DexFile, Files};
use rayon::prelude::ParallelIterator;

pub fn find_implementors_of(files: &Files, interface: &Class) -> Vec<(Arc<DexFile>, Arc<Class>)> {
    let mut matches = vec![];
    let vec_lock = Arc::new(Mutex::new(&mut matches));
    iterator!(files.multi_dex).for_each(|dex| {
        let classes = dex.classes();
        let matches: Vec<_> = iterator!(classes)
            .filter(|(_, class)| {
                class
                    .interfaces
                    .iter()
                    .filter(|inter| interface.class_idx == **inter as u32)
                    .count()
                    > 0
            })
            .cloned()
            .collect();
        if let Ok(mut lock) = vec_lock.lock() {
            lock.extend(matches);
        }
    });
    matches
}

pub fn find_subclasses_of(files: &Files, super_class: &Class) -> Vec<(Arc<DexFile>, Arc<Class>)> {
    let mut matches = vec![];
    let vec_lock = Arc::new(Mutex::new(&mut matches));
    iterator!(files.multi_dex).for_each(|dex| {
        let classes = dex.classes();
        let matches: Vec<_> = iterator!(classes)
            .filter(|(_, class)| class.super_class == super_class.class_idx)
            .cloned()
            .collect();
        if let Ok(mut lock) = vec_lock.lock() {
            lock.extend(matches);
        }
    });
    matches
}
