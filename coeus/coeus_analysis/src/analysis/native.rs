use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use goblin::{elf::Sym, Object};
#[cfg(not(target_arch = "wasm32"))]
use rayon::iter::{IndexedParallelIterator, ParallelIterator};
#[cfg(not(target_arch = "wasm32"))]
use rayon::prelude::ParallelSlice;
use regex::Regex;

use coeus_macros::{iterator, windows};
use coeus_models::models::BinaryObject;

use super::{ByteEvidence, ConfidenceLevel, Context, Evidence, Location, StringEvidence};

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum BinaryContent {
    Char(char),
    Byte(u8),
    Wildcard,
}

pub fn find_binary_pattern_in_elf<'a>(
    pattern: &'a [BinaryContent],
    files: &'a HashMap<String, Arc<BinaryObject>>,
) -> Vec<Evidence> {
    let mut matches = vec![];
    let vec_lock = Arc::new(Mutex::new(&mut matches));
    iterator!(files).for_each(|(file_name, object)| {
        let obj_data = object.data();
        let the_matches: Vec<Evidence> = windows!(obj_data, pattern.len())
            .enumerate()
            .filter(|(_, data)| {
                for i in 0..data.len() {
                    match pattern[i] {
                        BinaryContent::Char(c) => {
                            if c as u8 != data[i] {
                                return false;
                            }
                        }
                        BinaryContent::Byte(b) => {
                            if b != data[i] {
                                return false;
                            }
                        }
                        BinaryContent::Wildcard => continue,
                    }
                }
                true
            })
            .map(|(index, _)| {
                Evidence::BytePattern(ByteEvidence {
                    pattern: pattern.to_vec(),
                    place: Location::NativePattern(file_name.to_string(), index as usize),
                })
            })
            .collect();
        if let Ok(mut lock) = vec_lock.lock() {
            lock.extend(the_matches);
        }
    });
    matches
}

pub fn find_string_matches_in_elf(
    reg: &Regex,
    files: &HashMap<String, Arc<BinaryObject>>,
) -> Vec<Evidence> {
    let mut matches = vec![];
    let vec_lock = Arc::new(Mutex::new(&mut matches));
    iterator!(files).for_each(|(file_name, object)| {
        match object.object_no_cache() {
            Some(Object::Elf(elf)) => {
                let lib_matches: Vec<_> = iterator!(elf.libraries)
                    .filter(|&&lib| reg.is_match(lib))
                    .map(|&lib| {
                        Evidence::String(StringEvidence {
                            content: lib.to_string(),
                            context: Context::NativeLib(
                                object.clone(),
                                file_name.to_string(),
                                0,
                                false,
                                Sym::default(),
                            ),
                            confidence_level: ConfidenceLevel::Medium,
                            place: Location::NativeLibLoad,
                        })
                    })
                    .collect();

                let symbol_matches: Vec<_> = elf
                    .dynsyms
                    .iter()
                    .filter(|&sym| match elf.strtab.get_at(sym.st_name) {
                        Some(symbol_name) => reg.is_match(symbol_name),
                        _ => false,
                    })
                    .filter_map(|sym| {
                        Some(Evidence::String(StringEvidence {
                            content: elf.strtab.get_at(sym.st_name)?.to_string(),
                            context: Context::NativeSymbol(object.clone(), file_name.to_string()),
                            confidence_level: ConfidenceLevel::Medium,
                            place: Location::NativeSymbol,
                        }))
                    })
                    .collect();

                if let Ok(mut lock) = vec_lock.lock() {
                    lock.extend(lib_matches);
                    lock.extend(symbol_matches);
                }
            }
            Some(_) => {
                let mut tmp_matches: Vec<Evidence> = vec![];
                let str_lossy = object.get_utf8_lossy();
                for mat in reg.find_iter(&str_lossy) {
                    tmp_matches.push(Evidence::String(StringEvidence {
                        content: mat.as_str().to_string(),
                        confidence_level: ConfidenceLevel::Low,
                        context: Context::Binary(object.clone(), file_name.to_string()),
                        place: Location::Unknown,
                    }));
                }
                if let Ok(mut lock) = vec_lock.lock() {
                    lock.extend(tmp_matches);
                }
            }
            None => {}
        };
    });
    matches
}

pub fn find_exported_functions(reg: &Regex, bin_elf: Arc<BinaryObject>) -> Vec<Evidence> {
    let elf = if let Some(Object::Elf(elf)) = bin_elf.object_no_cache() {
        elf
    } else {
        return vec![];
    };
    let mut evidences = vec![];
    for sym in elf
        .dynsyms
        .into_iter()
        .filter(|a| a.is_function() && !a.is_import())
    {
        let sym_name = if let Some(sym_name) = elf.dynstrtab.get_at(sym.st_name) {
            sym_name
        } else {
            continue;
        };
        if reg.is_match(sym_name) {
            let evidence = StringEvidence {
                content: sym_name.to_string(),
                place: Location::NativeLibLoad,
                context: Context::NativeLib(
                    bin_elf.clone(),
                    sym_name.to_string(),
                    sym.st_value,
                    true,
                    sym,
                ),
                confidence_level: ConfidenceLevel::Medium,
            };
            evidences.push(Evidence::String(evidence));
        }
    }
    evidences
}

pub fn find_imported_functions(reg: &Regex, bin_elf: Arc<BinaryObject>) -> Vec<Evidence> {
    let elf = if let Some(Object::Elf(elf)) = bin_elf.object_no_cache() {
        elf
    } else {
        return vec![];
    };
    let mut evidences = vec![];
    let mask = match elf.header.e_machine {
        goblin::elf::header::EM_ARM => !1,
        _ => !0,
    };
    for sym in elf
        .dynsyms
        .into_iter()
        .filter(|a| a.is_function() && a.is_import())
    {
        let sym_name = if let Some(sym_name) = elf.dynstrtab.get_at(sym.st_name) {
            sym_name
        } else {
            continue;
        };
        if reg.is_match(sym_name) {
            let evidence = StringEvidence {
                content: sym_name.to_string(),
                place: Location::NativeLibLoad,
                context: Context::NativeLib(
                    bin_elf.clone(),
                    sym_name.to_string(),
                    sym.st_value & mask,
                    false,
                    sym,
                ),
                confidence_level: ConfidenceLevel::Medium,
            };
            evidences.push(Evidence::String(evidence));
        }
    }
    evidences
}

pub fn find_strings(reg: &Regex, bin_elf: Arc<BinaryObject>) -> Vec<Evidence> {
    let elf = if let Some(Object::Elf(elf)) = bin_elf.object_no_cache() {
        elf
    } else {
        return vec![];
    };
    let strings = if let Ok(strings) = elf.strtab.to_vec() {
        strings
    } else {
        return vec![];
    };
    let mut evidences = vec![];
    let regex = regex::bytes::Regex::new(r"(?-u)(?P<cstr>[^\x00]+)\x00").expect("REGEX IS WRONG");
    for h in &elf.section_headers {
        let name = if let Some(name) = elf.shdr_strtab.get_at(h.sh_name) {
            name
        } else {
            continue;
        };
        if name == ".rodata" {
            let cstrs: Vec<(usize, String)> = regex
                .captures_iter(
                    &bin_elf.data()[h.sh_offset as usize..(h.sh_offset + h.sh_size) as usize],
                )
                .filter_map(|c| {
                    if let Ok(cstr) = String::from_utf8(c.name("cstr")?.as_bytes().to_vec()) {
                        Some((c.name("cstr")?.start(), cstr))
                    } else {
                        None
                    }
                })
                .collect();
            for (offset, string) in cstrs {
                if reg.is_match(&string) {
                    let evidence = StringEvidence {
                        content: string.clone(),
                        place: Location::NativeLibLoad,
                        context: Context::NativeLib(
                            bin_elf.clone(),
                            string,
                            h.sh_offset + offset as u64,
                            false,
                            Sym::default(),
                        ),
                        confidence_level: ConfidenceLevel::Medium,
                    };
                    evidences.push(Evidence::String(evidence));
                }
            }
        }
    }
    // let relocs = elf.dynrelas.iter().find(|a| a.)

    for str in strings {
        if reg.is_match(str) {
            let evidence = StringEvidence {
                content: str.to_string(),
                place: Location::NativeLibLoad,
                context: Context::NativeSymbol(bin_elf.clone(), str.to_string()),
                confidence_level: ConfidenceLevel::Medium,
            };
            evidences.push(Evidence::String(evidence));
        }
    }
    evidences
}
