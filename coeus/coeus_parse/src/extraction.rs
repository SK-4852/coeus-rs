// Copyright (c) 2022 Ubique Innovation AG <https://www.ubique.ch>
// 
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! This module handles zip extraction and gathers all files into a `Files` struct, separating dex files and binary files. The dex files are parsed and inserted into `MultiDexFile` corresponding to all dex files at the same level. For binary files, we use `goblin` to allow parsing of potentially binary files. The binary parsing is a lazy operation though.
use abxml::{
    visitor::{Executor, ModelVisitor, XmlVisitor},
    STR_ARSC,
};

use std::{
    collections::HashMap,
    fs::File,
    io::{Cursor, ErrorKind, Read, Seek},
    sync::Arc,
};
use zip::ZipArchive;

use crate::dex::{parse_dex, parse_dex_buf, ArrayView};
use coeus_models::models::{AndroidManifest, BinaryObject, DexFile, Files, MultiDexFile};

pub fn extract_single_threaded(
    archive_name: &str,
    f: &ArrayView<u8>,
    should_build_graph: bool,
    found_dex: fn(&str, &ArrayView<u8>, bool) -> Option<DexFile>,
    depth: u32,
    max_depth: u32,
) -> Files {
    let mut archive = ZipArchive::new(f.get_cursor()).expect("Expected a zip file");
    let mut dex_files = vec![];
    let mut other_files = HashMap::new();
    let mut multi_dex = vec![];
    let mut bin_manifest = vec![];
    let mut bin_res_file = vec![];

    for i in 0..archive.len() {
        let mut file = archive.by_index(i).expect("Error Accessing file");
        let mut zip_bytes: Vec<u8> = vec![];

        std::io::copy(&mut file, &mut zip_bytes).expect("oops");
        let ptr = zip_bytes.as_slice();
        let file_name = format!("{}/{}", archive_name, file.name());
        if file.name().contains("AndroidManifest.xml") {
            bin_manifest = zip_bytes;
            other_files.insert(
                file.name().to_string(),
                Arc::new(BinaryObject::new(bin_manifest.to_vec())),
            );
            continue;
        } else if file.name().contains("resources.arsc") {
            bin_res_file = zip_bytes;
            continue;
        }

        if check_for_dex_signature(ptr) {
            let array_view = ArrayView::new(zip_bytes.as_slice());
            dex_files.extend(found_dex(&file_name, &array_view, should_build_graph));
            other_files.insert(
                file.name().to_string(),
                Arc::new(BinaryObject::new(zip_bytes)),
            );
        } else if (max_depth == 0 || depth <= max_depth) && check_for_zip_signature(ptr) {
            let zip_bytes = zip_bytes;
            let array_view = ArrayView::new(zip_bytes.as_slice());
            let inner = extract_single_threaded(
                &file_name,
                &array_view,
                should_build_graph,
                found_dex,
                depth + 1,
                max_depth,
            );
            multi_dex.extend(inner.multi_dex);
            other_files.extend(inner.binaries);
        } else {
            other_files.insert(
                file.name().to_string(),
                Arc::new(BinaryObject::new(zip_bytes)),
            );
        }
    }
    if !dex_files.is_empty() {
        let mut visitor = ModelVisitor::default();
        Executor::arsc(STR_ARSC, &mut visitor).unwrap();
        if !bin_res_file.is_empty() {
            Executor::arsc(&bin_res_file, &mut visitor).unwrap();
        }
        let mut visitor = XmlVisitor::new(visitor.get_resources());
        let _ = Executor::xml(Cursor::new(&bin_manifest), &mut visitor);
        let (manifest_content, android_manifest) = {
            let content = visitor.into_string().unwrap_or_else(|_| "".to_string());
            (
                content.clone(),
                serde_xml_rs::from_str(&content).unwrap_or_default(),
            )
        };

        let secondary = dex_files.split_off(1);
        multi_dex.push(MultiDexFile::new(
            android_manifest,
            manifest_content,
            dex_files.remove(0),
            secondary,
        ));
    }

    Files {
        multi_dex,
        binaries: other_files,
        binary_resource_file: bin_res_file,
        arsc: None
    }
}

pub fn extract_zip(
    archive_name: &str,
    f: &ArrayView<u8>,
    should_build_graph: bool,
    found_dex: fn(&str, &ArrayView<u8>, bool) -> Option<DexFile>,
    depth: u32,
    max_depth: u32,
) -> Files {
    let mut dex_files = vec![];
    let mut other_files = HashMap::new();
    let mut multi_dex = vec![];
    let mut dex_jobs = vec![];
    let mut bin_manifest = vec![];
    let mut bin_res_file = vec![];

    let mut archive = if let Ok(archive) = ZipArchive::new(f.get_cursor()) {
        archive
    } else {
        return Files {
            multi_dex,
            binaries: other_files,
            binary_resource_file: vec![],
            arsc: None
        };
    };

    for i in 0..archive.len() {
        let mut file = archive.by_index(i).expect("Error Accessing file");
        let mut zip_bytes: Vec<u8> = vec![];

        std::io::copy(&mut file, &mut zip_bytes).expect("oops");
        let ptr = zip_bytes.as_slice();
        let file_name = format!("{}/{}", archive_name, file.name());
        if file.name().contains("AndroidManifest.xml") {
            log::info!("Found AndroidManifest.xml in {}", archive_name);
            bin_manifest = zip_bytes;
            other_files.insert(
                file.name().to_string(),
                Arc::new(BinaryObject::new(bin_manifest.to_vec())),
            );
            continue;
        } else if file.name().contains("resources.arsc") {
            log::info!("Found resources.arsc in {}", archive_name);
            bin_res_file = zip_bytes;
            continue;
        }

        if check_for_dex_signature(ptr) {
            let dex_bytes = zip_bytes.clone();
            dex_jobs.push(std::thread::spawn(move || {
                let array_view = ArrayView::new(zip_bytes.as_slice());
                found_dex(&file_name, &array_view, should_build_graph)
            }));
            other_files.insert(
                file.name().to_string(),
                Arc::new(BinaryObject::new(dex_bytes)),
            );
        } else if (max_depth == 0 || depth <= max_depth) && check_for_zip_signature(ptr) {
            let zip_bytes = zip_bytes;
            let array_view = ArrayView::new(zip_bytes.as_slice());
            let inner = extract_zip(
                &file_name,
                &array_view,
                should_build_graph,
                found_dex,
                depth + 1,
                max_depth,
            );
            multi_dex.extend(inner.multi_dex);
            other_files.extend(inner.binaries);
        } else {
            other_files.insert(
                file.name().to_string(),
                Arc::new(BinaryObject::new(zip_bytes)),
            );
        }
    }
    for dex_file in dex_jobs {
        if let Ok(Some(dex_file)) = dex_file.join() {
            dex_files.push(dex_file);
        }
    }
    if !dex_files.is_empty() {
        let mut visitor = ModelVisitor::default();
        Executor::arsc(STR_ARSC, &mut visitor).unwrap();
        if !bin_res_file.is_empty() {
            Executor::arsc(&bin_res_file, &mut visitor).unwrap();
        }
        let mut visitor = XmlVisitor::new(visitor.get_resources());
        let _ = Executor::xml(Cursor::new(&bin_manifest), &mut visitor);
        let (manifest_content, android_manifest) = {
            let content = visitor.into_string().unwrap_or_else(|_| "".to_string());
            (
                content.clone(),
                serde_xml_rs::from_str(&content)
                    .or_else::<AndroidManifest, _>(|err| {
                        log::warn!("{:?}", err);
                        Ok(AndroidManifest::default())
                    })
                    .unwrap(),
            )
        };

        let secondary = dex_files.split_off(1);
        multi_dex.push(MultiDexFile::new(
            android_manifest,
            manifest_content,
            dex_files.remove(0),
            secondary,
        ));
    }

    Files {
        multi_dex,
        binaries: other_files,
        binary_resource_file: bin_res_file,
        arsc: None
    }
}

pub fn load_file(path: &str, build_graph: bool, max_depth: i64) -> Result<Files, std::io::Error> {
    let mut f = File::open(path)?;
    let mut zip_bytes: Vec<u8> = vec![];
    f.read_to_end(&mut zip_bytes)?;
    let ptr = zip_bytes.as_slice();
    let found_files: Files = if check_for_zip_signature(ptr) {
        extract_zip(
            path,
            &ArrayView::new(&zip_bytes),
            build_graph,
            parse_dex_buf,
            1,
            max_depth as u32,
        )
    } else if check_for_dex_signature(ptr) {
        log::debug!("found dex");
        f.seek(std::io::SeekFrom::Start(0))?;
        let coeus_file = parse_dex(path, f, build_graph)
            .ok_or_else(|| std::io::Error::new(ErrorKind::Other, "Could not parse dex"))?;
        let multi_dex = MultiDexFile::new(
            AndroidManifest::default(),
            String::new(),
            coeus_file,
            vec![],
        );
        Files::new(vec![multi_dex], HashMap::new())
    } else {
        log::debug!("nothing");
        Files::new(vec![], HashMap::new())
    };
    Ok(found_files)
}

#[inline(always)]
pub fn check_for_dex_signature<T: Read>(mut ptr: T) -> bool {
    let mut buf: [u8; 3] = [0, 0, 0];
    match ptr.read_exact(&mut buf) {
        Err(_) => false,
        _ => {
            let [a, b, c] = buf;
            a == b'd' && b == b'e' && c == b'x'
        }
    }
}
#[inline(always)]
pub fn check_for_zip_signature<T: Read>(mut ptr: T) -> bool {
    let mut buf: [u8; 2] = [0, 0];
    match ptr.read_exact(&mut buf) {
        Err(_) => false,
        _ => {
            let [a, b] = buf;
            a == b'P' && b == b'K'
        }
    }
}
